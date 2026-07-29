package qjs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var errSandboxUnsupported = errors.New("operation is not supported in sandbox filesystem mode")

type hostCodedError struct {
	code    string
	errno   int64
	message string
}

func (e *hostCodedError) Error() string { return e.message }

func newHostCodedError(code string, errno int64, message string) error {
	return &hostCodedError{code: code, errno: errno, message: message}
}

func errReadOnly(name string) error {
	return newHostCodedError("EROFS", -30, fmt.Sprintf("read-only filesystem: %s", name))
}

func errCrossDevice(source, dest string) error {
	return newHostCodedError("EXDEV", -18, fmt.Sprintf("cross-device link not permitted: %s -> %s", source, dest))
}

func errBusy(name string) error {
	return newHostCodedError("EBUSY", -16, fmt.Sprintf("resource busy or locked: %s", name))
}

func errIsDirectory(name string) error {
	return newHostCodedError("EISDIR", -21, fmt.Sprintf("illegal operation on a directory: %s", name))
}

func errBadFileDescriptor(fd int64) error {
	return newHostCodedError("EBADF", -9, fmt.Sprintf("bad file descriptor: %d", fd))
}

type hostFSMount struct {
	path     string
	name     string
	rootPath string
	root     *os.Root
	readOnly bool
}

type hostFSPath struct {
	mount         *hostFSMount
	relative      string
	virtual       string
	host          string
	syntheticRoot bool
}

type hostFileHandle struct {
	file     *os.File
	mount    *hostFSMount
	writable bool
}

type hostFileSystem struct {
	mode     FileSystemMode
	rootPath string
	root     *os.Root
	multi    bool
	mounts   []hostFSMount
	mountMap map[string]*hostFSMount

	cwdMu sync.RWMutex
	cwd   string

	handlesMu sync.Mutex
	nextFD    int64
	handles   map[int64]hostFileHandle
	closeOnce sync.Once
}

type hostFSOptions struct {
	Encoding      string `json:"encoding,omitempty"`
	Recursive     bool   `json:"recursive,omitempty"`
	Force         bool   `json:"force,omitempty"`
	WithFileTypes bool   `json:"withFileTypes,omitempty"`
	Flag          string `json:"flag,omitempty"`
	Mode          uint32 `json:"mode,omitempty"`
	Dest          string `json:"dest,omitempty"`
	FD            int64  `json:"fd,omitempty"`
	Offset        int64  `json:"offset,omitempty"`
	Position      int64  `json:"position,omitempty"`
	HasPosition   bool   `json:"hasPosition,omitempty"`
	AtimeMS       int64  `json:"atimeMs,omitempty"`
	MtimeMS       int64  `json:"mtimeMs,omitempty"`
}

func newHostFileSystem(options FileSystemOptions, cwd string) (*hostFileSystem, error) {
	if options.Mode != FileSystemSandbox && options.Mode != FileSystemHost {
		return nil, fmt.Errorf("invalid filesystem mode %d", options.Mode)
	}
	if len(options.Mounts) > 0 {
		return newMultiMountHostFileSystem(options)
	}

	rootPath, err := filepath.Abs(options.Root)
	if err != nil {
		return nil, err
	}
	cwd, err = filepath.Abs(cwd)
	if err != nil {
		return nil, err
	}

	h := &hostFileSystem{
		mode:     options.Mode,
		rootPath: rootPath,
		cwd:      cwd,
		nextFD:   2,
		handles:  make(map[int64]hostFileHandle),
	}
	if options.Mode == FileSystemSandbox {
		if _, err := pathWithinRoot(rootPath, cwd); err != nil {
			return nil, fmt.Errorf("runtime CWD must be inside filesystem root: %w", err)
		}
		h.root, err = os.OpenRoot(rootPath)
		if err != nil {
			return nil, fmt.Errorf("open filesystem root: %w", err)
		}
	}

	return h, nil
}

func newMultiMountHostFileSystem(options FileSystemOptions) (_ *hostFileSystem, err error) {
	if options.Mode != FileSystemSandbox {
		return nil, errors.New("filesystem mounts require sandbox mode")
	}
	if options.Root != "" {
		return nil, errors.New("filesystem Root and Mounts cannot be used together")
	}

	h := &hostFileSystem{
		mode:     FileSystemSandbox,
		multi:    true,
		mounts:   make([]hostFSMount, 0, len(options.Mounts)),
		mountMap: make(map[string]*hostFSMount, len(options.Mounts)),
		nextFD:   2,
		handles:  make(map[int64]hostFileHandle),
	}
	defer func() {
		if err != nil {
			h.close()
		}
	}()

	for index, option := range options.Mounts {
		if err := validateMountPath(option.Path); err != nil {
			return nil, fmt.Errorf("filesystem mount %d: %w", index, err)
		}
		if _, exists := h.mountMap[option.Path]; exists {
			return nil, fmt.Errorf("duplicate filesystem mount path %q", option.Path)
		}
		if option.Root == "" {
			return nil, fmt.Errorf("filesystem mount %q requires a physical Root", option.Path)
		}

		rootPath, err := filepath.Abs(option.Root)
		if err != nil {
			return nil, fmt.Errorf("resolve filesystem mount %q root: %w", option.Path, err)
		}
		rootPath, err = filepath.EvalSymlinks(rootPath)
		if err != nil {
			return nil, fmt.Errorf("resolve filesystem mount %q root symlinks: %w", option.Path, err)
		}
		info, err := os.Stat(rootPath)
		if err != nil {
			return nil, fmt.Errorf("stat filesystem mount %q root: %w", option.Path, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("filesystem mount %q root is not a directory: %s", option.Path, rootPath)
		}
		for _, existing := range h.mounts {
			if physicalPathsOverlap(existing.rootPath, rootPath) {
				return nil, fmt.Errorf("filesystem mount roots overlap: %q and %q", existing.path, option.Path)
			}
		}
		root, err := os.OpenRoot(rootPath)
		if err != nil {
			return nil, fmt.Errorf("open filesystem mount %q root: %w", option.Path, err)
		}
		h.mounts = append(h.mounts, hostFSMount{
			path:     option.Path,
			name:     strings.TrimPrefix(option.Path, "/"),
			rootPath: rootPath,
			root:     root,
			readOnly: option.ReadOnly,
		})
		h.mountMap[option.Path] = &h.mounts[len(h.mounts)-1]
	}

	sort.Slice(h.mounts, func(i, j int) bool { return h.mounts[i].path < h.mounts[j].path })
	for index := range h.mounts {
		h.mountMap[h.mounts[index].path] = &h.mounts[index]
	}

	h.cwd = options.VirtualCWD
	if h.cwd == "" {
		h.cwd = "/"
	}
	resolved, err := h.resolveVirtual(h.cwd)
	if err != nil {
		return nil, fmt.Errorf("invalid filesystem VirtualCWD %q: %w", h.cwd, err)
	}
	if !resolved.syntheticRoot {
		info, statErr := resolved.mount.root.Stat(resolved.relative)
		if statErr != nil {
			return nil, fmt.Errorf("stat filesystem VirtualCWD %q: %w", h.cwd, statErr)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("filesystem VirtualCWD is not a directory: %s", h.cwd)
		}
	}
	h.cwd = resolved.virtual
	return h, nil
}

func validateMountPath(name string) error {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.Contains(name, `\`) {
		return fmt.Errorf("invalid virtual mount path %q", name)
	}
	if name == "/" || !strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || pathpkg.Clean(name) != name {
		return fmt.Errorf("virtual mount path must be a normalized top-level absolute path: %q", name)
	}
	part := strings.TrimPrefix(name, "/")
	if part == "" || part == "." || part == ".." || strings.Contains(part, "/") {
		return fmt.Errorf("virtual mount path must be a normalized top-level absolute path: %q", name)
	}
	return nil
}

func physicalPathsOverlap(left, right string) bool {
	leftToRight, leftErr := filepath.Rel(left, right)
	rightToLeft, rightErr := filepath.Rel(right, left)
	isWithin := func(rel string, err error) bool {
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
	}
	return isWithin(leftToRight, leftErr) || isWithin(rightToLeft, rightErr)
}

func (h *hostFileSystem) close() {
	h.closeOnce.Do(func() {
		h.handlesMu.Lock()
		handles := h.handles
		h.handles = make(map[int64]hostFileHandle)
		h.handlesMu.Unlock()
		for _, handle := range handles {
			_ = handle.file.Close()
		}
		if h.root != nil {
			_ = h.root.Close()
		}
		for index := range h.mounts {
			if h.mounts[index].root != nil {
				_ = h.mounts[index].root.Close()
			}
		}
	})
}

func (h *hostFileSystem) currentCWD() string {
	h.cwdMu.RLock()
	defer h.cwdMu.RUnlock()
	return h.cwd
}

func (h *hostFileSystem) resolve(name string) (relative, full string, err error) {
	if h.multi {
		resolved, err := h.resolveVirtual(name)
		if err != nil {
			return "", "", err
		}
		if resolved.syntheticRoot {
			return ".", "", nil
		}
		return resolved.relative, resolved.host, nil
	}
	if strings.TrimSpace(name) == "" {
		return "", "", errors.New("path is required")
	}

	converted := filepath.FromSlash(name)
	if filepath.IsAbs(converted) {
		full = filepath.Clean(converted)
	} else {
		full = filepath.Join(h.currentCWD(), converted)
	}
	full, err = filepath.Abs(full)
	if err != nil {
		return "", "", err
	}
	if h.mode == FileSystemHost {
		return "", full, nil
	}

	relative, err = pathWithinRoot(h.rootPath, full)
	if err != nil {
		return "", "", err
	}
	return relative, full, nil
}

func (h *hostFileSystem) resolveVirtual(name string) (*hostFSPath, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("path is required")
	}
	if strings.ContainsRune(name, '\x00') {
		return nil, os.ErrInvalid
	}
	if runtime.GOOS == "windows" {
		name = strings.ReplaceAll(name, `\`, "/")
	}
	var virtual string
	if strings.HasPrefix(name, "/") {
		virtual = pathpkg.Clean(name)
	} else {
		virtual = pathpkg.Clean(pathpkg.Join(h.currentCWD(), name))
	}
	if virtual == "." {
		virtual = "/"
	}
	if !strings.HasPrefix(virtual, "/") {
		virtual = "/" + virtual
	}
	if virtual == "/" {
		return &hostFSPath{virtual: "/", syntheticRoot: true}, nil
	}

	first := strings.SplitN(strings.TrimPrefix(virtual, "/"), "/", 2)[0]
	mount := h.mountMap["/"+first]
	if mount == nil {
		return nil, fmt.Errorf("%w: %s", os.ErrNotExist, virtual)
	}
	relative := strings.TrimPrefix(virtual, mount.path)
	relative = strings.TrimPrefix(relative, "/")
	if relative == "" {
		relative = "."
	}
	return &hostFSPath{
		mount:    mount,
		relative: filepath.FromSlash(relative),
		virtual:  virtual,
		host:     filepath.Join(mount.rootPath, filepath.FromSlash(relative)),
	}, nil
}

func (h *hostFileSystem) resolveHostPath(name string, writable bool) (string, error) {
	if !h.multi {
		_, full, err := h.resolve(name)
		return full, err
	}
	resolved, err := h.resolveVirtual(name)
	if err != nil {
		return "", err
	}
	if resolved.syntheticRoot {
		return "", errors.New("synthetic filesystem root has no host path")
	}
	if writable && resolved.mount.readOnly {
		return "", errReadOnly(resolved.virtual)
	}
	return resolved.host, nil
}

func pathWithinRoot(root, name string) (string, error) {
	rel, err := filepath.Rel(root, name)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("path %q escapes filesystem root", name)
	}
	if rel == "" {
		rel = "."
	}
	return filepath.Clean(rel), nil
}

func (h *hostFileSystem) open(name string) (*os.File, error) {
	if h.multi {
		resolved, err := h.resolveVirtual(name)
		if err != nil {
			return nil, err
		}
		if resolved.syntheticRoot {
			return nil, errIsDirectory(resolved.virtual)
		}
		return resolved.mount.root.Open(resolved.relative)
	}
	rel, full, err := h.resolve(name)
	if err != nil {
		return nil, err
	}
	if h.mode == FileSystemSandbox {
		return h.root.Open(rel)
	}
	return os.Open(full)
}

func (h *hostFileSystem) openFile(name string, flag int, perm fs.FileMode) (*os.File, error) {
	file, _, err := h.openFileWithMount(name, flag, perm)
	return file, err
}

func (h *hostFileSystem) openFileWithMount(name string, flag int, perm fs.FileMode) (*os.File, *hostFSMount, error) {
	if h.multi {
		resolved, err := h.resolveVirtual(name)
		if err != nil {
			return nil, nil, err
		}
		if resolved.syntheticRoot || resolved.relative == "." && isWritableOpenFlag(flag) {
			return nil, nil, errIsDirectory(resolved.virtual)
		}
		if isWritableOpenFlag(flag) && resolved.mount.readOnly {
			return nil, nil, errReadOnly(resolved.virtual)
		}
		file, err := resolved.mount.root.OpenFile(resolved.relative, flag, perm)
		return file, resolved.mount, err
	}
	rel, full, err := h.resolve(name)
	if err != nil {
		return nil, nil, err
	}
	if h.mode == FileSystemSandbox {
		file, err := h.root.OpenFile(rel, flag, perm)
		return file, nil, err
	}
	file, err := os.OpenFile(full, flag, perm)
	return file, nil, err
}

func isWritableOpenFlag(flag int) bool {
	return flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0
}

func (h *hostFileSystem) readFile(name string) ([]byte, error) {
	if h.multi {
		resolved, err := h.resolveVirtual(name)
		if err != nil {
			return nil, err
		}
		if resolved.syntheticRoot {
			return nil, errIsDirectory(resolved.virtual)
		}
		info, err := resolved.mount.root.Stat(resolved.relative)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			return nil, errIsDirectory(resolved.virtual)
		}
		file, err := resolved.mount.root.Open(resolved.relative)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return io.ReadAll(file)
	}
	file, err := h.open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

func (h *hostFileSystem) writeFile(name string, data []byte, flag string, mode fs.FileMode) error {
	openFlag, err := parseNodeOpenFlag(flag)
	if err != nil {
		return err
	}
	file, err := h.openFile(name, openFlag, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(data)
	return err
}

func parseNodeOpenFlag(flag string) (int, error) {
	if flag == "" {
		flag = "w"
	}
	switch flag {
	case "r":
		return os.O_RDONLY, nil
	case "r+":
		return os.O_RDWR, nil
	case "w":
		return os.O_WRONLY | os.O_CREATE | os.O_TRUNC, nil
	case "wx", "xw":
		return os.O_WRONLY | os.O_CREATE | os.O_TRUNC | os.O_EXCL, nil
	case "w+":
		return os.O_RDWR | os.O_CREATE | os.O_TRUNC, nil
	case "wx+", "xw+":
		return os.O_RDWR | os.O_CREATE | os.O_TRUNC | os.O_EXCL, nil
	case "a":
		return os.O_WRONLY | os.O_CREATE | os.O_APPEND, nil
	case "ax", "xa":
		return os.O_WRONLY | os.O_CREATE | os.O_APPEND | os.O_EXCL, nil
	case "a+":
		return os.O_RDWR | os.O_CREATE | os.O_APPEND, nil
	case "ax+", "xa+":
		return os.O_RDWR | os.O_CREATE | os.O_APPEND | os.O_EXCL, nil
	default:
		return 0, fmt.Errorf("unsupported file open flag %q", flag)
	}
}

func (h *hostFileSystem) mkdir(name string, recursive bool, mode fs.FileMode) error {
	if h.multi {
		resolved, err := h.resolveVirtual(name)
		if err != nil {
			return err
		}
		if resolved.syntheticRoot {
			if recursive {
				return nil
			}
			return os.ErrExist
		}
		if resolved.mount.readOnly {
			return errReadOnly(resolved.virtual)
		}
		if recursive {
			return resolved.mount.root.MkdirAll(resolved.relative, mode)
		}
		return resolved.mount.root.Mkdir(resolved.relative, mode)
	}
	rel, full, err := h.resolve(name)
	if err != nil {
		return err
	}
	if h.mode == FileSystemHost {
		if recursive {
			return os.MkdirAll(full, mode)
		}
		return os.Mkdir(full, mode)
	}
	if !recursive {
		return h.root.Mkdir(rel, mode)
	}
	if rel == "." {
		return nil
	}

	current := ""
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		if err := h.root.Mkdir(current, mode); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return err
			}
			info, statErr := h.root.Stat(current)
			if statErr != nil || !info.IsDir() {
				return err
			}
		}
	}
	return nil
}

func (h *hostFileSystem) readDir(name string, withFileTypes bool) (any, error) {
	if h.multi {
		resolved, err := h.resolveVirtual(name)
		if err != nil {
			return nil, err
		}
		if resolved.syntheticRoot {
			if !withFileTypes {
				names := make([]string, 0, len(h.mounts))
				for index := range h.mounts {
					names = append(names, h.mounts[index].name)
				}
				return names, nil
			}
			entries := make([]map[string]any, 0, len(h.mounts))
			for index := range h.mounts {
				entries = append(entries, map[string]any{
					"name":           h.mounts[index].name,
					"isFile":         false,
					"isDirectory":    true,
					"isSymbolicLink": false,
				})
			}
			return entries, nil
		}
		file, err := resolved.mount.root.Open(resolved.relative)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return readDirEntries(file, withFileTypes)
	}
	file, err := h.open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readDirEntries(file, withFileTypes)
}

func readDirEntries(file *os.File, withFileTypes bool) (any, error) {
	entries, err := file.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	if !withFileTypes {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		return names, nil
	}
	result := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		typeBits := entry.Type()
		result = append(result, map[string]any{
			"name":           entry.Name(),
			"isFile":         typeBits.IsRegular(),
			"isDirectory":    typeBits.IsDir(),
			"isSymbolicLink": typeBits&os.ModeSymlink != 0,
		})
	}
	return result, nil
}

func (h *hostFileSystem) stat(name string, lstat bool) (map[string]any, error) {
	if h.multi {
		resolved, err := h.resolveVirtual(name)
		if err != nil {
			return nil, err
		}
		if resolved.syntheticRoot {
			return hostDirectoryInfoPayload("/"), nil
		}
		var info os.FileInfo
		if lstat {
			info, err = resolved.mount.root.Lstat(resolved.relative)
		} else {
			info, err = resolved.mount.root.Stat(resolved.relative)
		}
		if err != nil {
			return nil, err
		}
		payload := hostFileInfoPayload(info)
		if resolved.relative == "." {
			payload["name"] = resolved.mount.name
		}
		return payload, nil
	}
	rel, full, err := h.resolve(name)
	if err != nil {
		return nil, err
	}
	var info os.FileInfo
	if h.mode == FileSystemSandbox {
		if lstat {
			info, err = h.root.Lstat(rel)
		} else {
			info, err = h.root.Stat(rel)
		}
	} else if lstat {
		info, err = os.Lstat(full)
	} else {
		info, err = os.Stat(full)
	}
	if err != nil {
		return nil, err
	}
	return hostFileInfoPayload(info), nil
}

func hostDirectoryInfoPayload(name string) map[string]any {
	return map[string]any{
		"name":              name,
		"size":              int64(0),
		"mode":              uint32(fs.ModeDir | 0o555),
		"mtimeMs":           int64(0),
		"atimeMs":           int64(0),
		"ctimeMs":           int64(0),
		"birthtimeMs":       int64(0),
		"isFile":            false,
		"isDirectory":       true,
		"isSymbolicLink":    false,
		"isBlockDevice":     false,
		"isCharacterDevice": false,
		"isFIFO":            false,
		"isSocket":          false,
	}
}

func hostFileInfoPayload(info os.FileInfo) map[string]any {
	mode := info.Mode()
	modTime := info.ModTime()
	return map[string]any{
		"name":              info.Name(),
		"size":              info.Size(),
		"mode":              uint32(mode),
		"mtimeMs":           modTime.UnixMilli(),
		"atimeMs":           modTime.UnixMilli(),
		"ctimeMs":           modTime.UnixMilli(),
		"birthtimeMs":       modTime.UnixMilli(),
		"isFile":            mode.IsRegular(),
		"isDirectory":       mode.IsDir(),
		"isSymbolicLink":    mode&os.ModeSymlink != 0,
		"isBlockDevice":     mode&os.ModeDevice != 0 && mode&os.ModeCharDevice == 0,
		"isCharacterDevice": mode&os.ModeCharDevice != 0,
		"isFIFO":            mode&os.ModeNamedPipe != 0,
		"isSocket":          mode&os.ModeSocket != 0,
	}
}

func (h *hostFileSystem) remove(name string, recursive, force bool) error {
	if h.multi {
		resolved, err := h.resolveVirtual(name)
		if err != nil {
			if force && errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if resolved.syntheticRoot || resolved.relative == "." {
			return errBusy(resolved.virtual)
		}
		if resolved.mount.readOnly {
			return errReadOnly(resolved.virtual)
		}
		if recursive {
			err = removeSandboxTree(resolved.mount.root, resolved.relative)
		} else {
			err = resolved.mount.root.Remove(resolved.relative)
		}
		if force && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	rel, full, err := h.resolve(name)
	if err != nil {
		return err
	}
	if h.mode == FileSystemHost {
		if recursive {
			err = os.RemoveAll(full)
		} else {
			err = os.Remove(full)
		}
		if force && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if rel == "." {
		return errors.New("refusing to remove the filesystem root")
	}
	if recursive {
		err = h.removeSandboxTree(rel)
	} else {
		err = h.root.Remove(rel)
	}
	if force && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (h *hostFileSystem) removeSandboxTree(rel string) error {
	return removeSandboxTree(h.root, rel)
}

func removeSandboxTree(root *os.Root, rel string) error {
	info, err := root.Lstat(rel)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return root.Remove(rel)
	}
	file, err := root.Open(rel)
	if err != nil {
		return err
	}
	entries, readErr := file.ReadDir(-1)
	_ = file.Close()
	if readErr != nil {
		return readErr
	}
	for _, entry := range entries {
		if err := removeSandboxTree(root, filepath.Join(rel, entry.Name())); err != nil {
			return err
		}
	}
	return root.Remove(rel)
}

func (h *hostFileSystem) realPath(name string) (string, error) {
	if h.multi {
		resolved, err := h.resolveVirtual(name)
		if err != nil {
			return "", err
		}
		if resolved.syntheticRoot {
			return "/", nil
		}
		physical, err := filepath.EvalSymlinks(resolved.host)
		if err != nil {
			return "", err
		}
		relative, err := pathWithinRoot(resolved.mount.rootPath, physical)
		if err != nil {
			return "", err
		}
		if relative == "." {
			return resolved.mount.path, nil
		}
		return pathpkg.Join(resolved.mount.path, filepath.ToSlash(relative)), nil
	}
	_, full, err := h.resolve(name)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", err
	}
	if h.mode == FileSystemSandbox {
		if _, err := pathWithinRoot(h.rootPath, resolved); err != nil {
			return "", err
		}
	}
	return resolved, nil
}

func (h *hostFileSystem) copyFile(source, dest string, mode fs.FileMode) error {
	in, err := h.open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := h.openFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func (h *hostFileSystem) rename(source, dest string) error {
	if h.multi {
		sourcePath, err := h.resolveVirtual(source)
		if err != nil {
			return err
		}
		destPath, err := h.resolveVirtual(dest)
		if err != nil {
			return err
		}
		if sourcePath.syntheticRoot || sourcePath.relative == "." {
			return errBusy(sourcePath.virtual)
		}
		if destPath.syntheticRoot || destPath.relative == "." {
			return errBusy(destPath.virtual)
		}
		if sourcePath.mount != destPath.mount {
			return errCrossDevice(sourcePath.virtual, destPath.virtual)
		}
		if sourcePath.mount.readOnly {
			return errReadOnly(sourcePath.virtual)
		}
		if destPath.mount.readOnly {
			return errReadOnly(destPath.virtual)
		}
		return sourcePath.mount.root.Rename(sourcePath.relative, destPath.relative)
	}
	if h.mode == FileSystemSandbox {
		return errSandboxUnsupported
	}
	_, sourcePath, err := h.resolve(source)
	if err != nil {
		return err
	}
	_, destPath, err := h.resolve(dest)
	if err != nil {
		return err
	}
	return os.Rename(sourcePath, destPath)
}

func (h *hostFileSystem) chdir(name string) (string, error) {
	if h.multi {
		resolved, err := h.resolveVirtual(name)
		if err != nil {
			return "", err
		}
		if !resolved.syntheticRoot {
			info, err := resolved.mount.root.Stat(resolved.relative)
			if err != nil {
				return "", err
			}
			if !info.IsDir() {
				return "", fmt.Errorf("not a directory: %s", name)
			}
		}
		h.cwdMu.Lock()
		h.cwd = resolved.virtual
		h.cwdMu.Unlock()
		return resolved.virtual, nil
	}
	_, full, err := h.resolve(name)
	if err != nil {
		return "", err
	}
	info, err := h.stat(name, false)
	if err != nil {
		return "", err
	}
	if isDir, _ := info["isDirectory"].(bool); !isDir {
		return "", fmt.Errorf("not a directory: %s", name)
	}
	h.cwdMu.Lock()
	h.cwd = full
	h.cwdMu.Unlock()
	return full, nil
}

func (h *hostFileSystem) addHandle(file *os.File, mount *hostFSMount, writable bool) int64 {
	h.handlesMu.Lock()
	defer h.handlesMu.Unlock()
	h.nextFD++
	fd := h.nextFD
	h.handles[fd] = hostFileHandle{file: file, mount: mount, writable: writable}
	return fd
}

func (h *hostFileSystem) handle(fd int64) (hostFileHandle, error) {
	h.handlesMu.Lock()
	defer h.handlesMu.Unlock()
	handle, ok := h.handles[fd]
	if !ok {
		return hostFileHandle{}, errBadFileDescriptor(fd)
	}
	return handle, nil
}

func (h *hostFileSystem) closeHandle(fd int64) error {
	h.handlesMu.Lock()
	handle, ok := h.handles[fd]
	delete(h.handles, fd)
	h.handlesMu.Unlock()
	if !ok {
		return errBadFileDescriptor(fd)
	}
	return handle.file.Close()
}

func (s *hostRuntimeState) hostFSSync(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 3 {
		return nil, errors.New("filesystem operation, path, and options are required")
	}
	op, name := args[0].String(), args[1].String()
	options, err := parseHostFSOptions(args[2].String())
	if err != nil {
		return nil, err
	}
	var data []byte
	if len(args) > 3 && !args[3].IsNull() && !args[3].IsUndefined() {
		data, err = jsValueToBytes(args[3])
		if err != nil {
			return nil, err
		}
	}
	result, runErr := s.runHostFSOperation(op, name, options, data)
	payload := map[string]any{"result": result}
	if runErr != nil {
		payload = map[string]any{"error": makeHostError(runErr, op, name, options.Dest)}
	}
	return ToJsValue(this.Context(), payload)
}

func (s *hostRuntimeState) hostFSAsyncStart(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 3 {
		return nil, errors.New("filesystem operation, path, and options are required")
	}
	op, name := args[0].String(), args[1].String()
	options, err := parseHostFSOptions(args[2].String())
	if err != nil {
		return nil, err
	}
	var data []byte
	if len(args) > 3 && !args[3].IsNull() && !args[3].IsUndefined() {
		data, err = jsValueToBytes(args[3])
		if err != nil {
			return nil, err
		}
	}
	id, err := s.async.start(func(ctx context.Context) (any, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, err := s.runHostFSOperation(op, name, options, data)
		if err != nil {
			return nil, &hostOperationError{Err: err, Op: op, Path: name, Dest: options.Dest}
		}
		return result, ctx.Err()
	})
	if err != nil {
		return nil, err
	}
	return this.Context().NewInt64(id), nil
}

func parseHostFSOptions(raw string) (hostFSOptions, error) {
	options := hostFSOptions{Position: -1}
	if strings.TrimSpace(raw) == "" {
		return options, nil
	}
	if err := json.Unmarshal([]byte(raw), &options); err != nil {
		return hostFSOptions{}, fmt.Errorf("invalid filesystem options: %w", err)
	}
	return options, nil
}

func (s *hostRuntimeState) runHostFSOperation(op, name string, options hostFSOptions, data []byte) (any, error) {
	fileMode := fs.FileMode(options.Mode)
	if fileMode == 0 {
		fileMode = 0o666
	}
	switch op {
	case "readFile":
		return s.fsys.readFile(name)
	case "writeFile":
		flag := options.Flag
		if flag == "" {
			flag = "w"
		}
		return nil, s.fsys.writeFile(name, data, flag, fileMode)
	case "appendFile":
		return nil, s.fsys.writeFile(name, data, "a", fileMode)
	case "mkdir":
		dirMode := fs.FileMode(options.Mode)
		if dirMode == 0 {
			dirMode = 0o777
		}
		return nil, s.fsys.mkdir(name, options.Recursive, dirMode)
	case "readdir":
		return s.fsys.readDir(name, options.WithFileTypes)
	case "stat":
		return s.fsys.stat(name, false)
	case "lstat":
		return s.fsys.stat(name, true)
	case "exists":
		_, err := s.fsys.stat(name, false)
		if err == nil {
			return true, nil
		}
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return nil, err
	case "access":
		_, err := s.fsys.stat(name, false)
		return nil, err
	case "realpath":
		return s.fsys.realPath(name)
	case "copyFile":
		return nil, s.fsys.copyFile(name, options.Dest, fileMode)
	case "rename":
		return nil, s.fsys.rename(name, options.Dest)
	case "rm", "remove", "unlink":
		return nil, s.fsys.remove(name, options.Recursive, options.Force)
	case "open":
		flag := options.Flag
		if flag == "" {
			flag = "r"
		}
		openFlag, err := parseNodeOpenFlag(flag)
		if err != nil {
			return nil, err
		}
		file, mount, err := s.fsys.openFileWithMount(name, openFlag, fileMode)
		if err != nil {
			return nil, err
		}
		return s.fsys.addHandle(file, mount, isWritableOpenFlag(openFlag)), nil
	case "writeFD":
		handle, err := s.fsys.handle(options.FD)
		if err != nil {
			return nil, err
		}
		if !handle.writable {
			return nil, errBadFileDescriptor(options.FD)
		}
		if options.HasPosition {
			n, err := handle.file.WriteAt(data, options.Position)
			return n, err
		}
		n, err := handle.file.Write(data)
		return n, err
	case "closeFD":
		return nil, s.fsys.closeHandle(options.FD)
	case "syncFD":
		handle, err := s.fsys.handle(options.FD)
		if err != nil {
			return nil, err
		}
		return nil, handle.file.Sync()
	case "utimes":
		if s.fsys.multi {
			resolved, err := s.fsys.resolveVirtual(name)
			if err != nil {
				return nil, err
			}
			if resolved.syntheticRoot {
				return nil, errReadOnly(resolved.virtual)
			}
			if resolved.mount.readOnly {
				return nil, errReadOnly(resolved.virtual)
			}
			return nil, resolved.mount.root.Chtimes(resolved.relative, time.UnixMilli(options.AtimeMS), time.UnixMilli(options.MtimeMS))
		}
		if s.fsys.mode == FileSystemSandbox {
			return nil, errSandboxUnsupported
		}
		_, full, err := s.fsys.resolve(name)
		if err != nil {
			return nil, err
		}
		return nil, os.Chtimes(full, time.UnixMilli(options.AtimeMS), time.UnixMilli(options.MtimeMS))
	default:
		return nil, fmt.Errorf("unsupported filesystem operation %q", op)
	}
}
