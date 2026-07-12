package qjs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var errSandboxUnsupported = errors.New("operation is not supported in sandbox filesystem mode")

type hostFileSystem struct {
	mode     FileSystemMode
	rootPath string
	root     *os.Root

	cwdMu sync.RWMutex
	cwd   string

	handlesMu sync.Mutex
	nextFD    int64
	handles   map[int64]*os.File
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
		handles:  make(map[int64]*os.File),
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

func (h *hostFileSystem) close() {
	h.closeOnce.Do(func() {
		h.handlesMu.Lock()
		handles := h.handles
		h.handles = make(map[int64]*os.File)
		h.handlesMu.Unlock()
		for _, file := range handles {
			_ = file.Close()
		}
		if h.root != nil {
			_ = h.root.Close()
		}
	})
}

func (h *hostFileSystem) currentCWD() string {
	h.cwdMu.RLock()
	defer h.cwdMu.RUnlock()
	return h.cwd
}

func (h *hostFileSystem) resolve(name string) (relative, full string, err error) {
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
	rel, full, err := h.resolve(name)
	if err != nil {
		return nil, err
	}
	if h.mode == FileSystemSandbox {
		return h.root.OpenFile(rel, flag, perm)
	}
	return os.OpenFile(full, flag, perm)
}

func (h *hostFileSystem) readFile(name string) ([]byte, error) {
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
	file, err := h.open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
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
	info, err := h.root.Lstat(rel)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return h.root.Remove(rel)
	}
	file, err := h.root.Open(rel)
	if err != nil {
		return err
	}
	entries, readErr := file.ReadDir(-1)
	_ = file.Close()
	if readErr != nil {
		return readErr
	}
	for _, entry := range entries {
		if err := h.removeSandboxTree(filepath.Join(rel, entry.Name())); err != nil {
			return err
		}
	}
	return h.root.Remove(rel)
}

func (h *hostFileSystem) realPath(name string) (string, error) {
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

func (h *hostFileSystem) addHandle(file *os.File) int64 {
	h.handlesMu.Lock()
	defer h.handlesMu.Unlock()
	h.nextFD++
	fd := h.nextFD
	h.handles[fd] = file
	return fd
}

func (h *hostFileSystem) handle(fd int64) (*os.File, error) {
	h.handlesMu.Lock()
	defer h.handlesMu.Unlock()
	file := h.handles[fd]
	if file == nil {
		return nil, fmt.Errorf("bad file descriptor: %d", fd)
	}
	return file, nil
}

func (h *hostFileSystem) closeHandle(fd int64) error {
	h.handlesMu.Lock()
	file := h.handles[fd]
	delete(h.handles, fd)
	h.handlesMu.Unlock()
	if file == nil {
		return fmt.Errorf("bad file descriptor: %d", fd)
	}
	return file.Close()
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
			return nil, &os.PathError{Op: op, Path: name, Err: err}
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
		file, err := s.fsys.open(name)
		if err == nil {
			err = file.Close()
		}
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
		file, err := s.fsys.openFile(name, openFlag, fileMode)
		if err != nil {
			return nil, err
		}
		return s.fsys.addHandle(file), nil
	case "writeFD":
		file, err := s.fsys.handle(options.FD)
		if err != nil {
			return nil, err
		}
		if options.HasPosition {
			n, err := file.WriteAt(data, options.Position)
			return n, err
		}
		n, err := file.Write(data)
		return n, err
	case "closeFD":
		return nil, s.fsys.closeHandle(options.FD)
	case "syncFD":
		file, err := s.fsys.handle(options.FD)
		if err != nil {
			return nil, err
		}
		return nil, file.Sync()
	case "utimes":
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
