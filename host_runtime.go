package qjs

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxCryptoRandomValues = 65536

// HostRuntimeFeature selects optional host-backed runtime APIs.
type HostRuntimeFeature uint64

const (
	HostRuntimeFeatureCrypto HostRuntimeFeature = 1 << iota
	HostRuntimeFeatureFetch
	HostRuntimeFeatureFS
	HostRuntimeFeatureProcess
	HostRuntimeFeatureChildProcess
	HostRuntimeFeatureNet
	HostRuntimeFeatureHTTP
	HostRuntimeFeatureWebSocket
	HostRuntimeFeatureWorker
	HostRuntimeFeatureNodeCompat
)

const (
	HostRuntimeFeatureNodeTool = HostRuntimeFeatureCrypto |
		HostRuntimeFeatureFetch |
		HostRuntimeFeatureFS |
		HostRuntimeFeatureProcess |
		HostRuntimeFeatureNodeCompat
	HostRuntimeFeatureAll = HostRuntimeFeatureNodeTool |
		HostRuntimeFeatureChildProcess |
		HostRuntimeFeatureNet |
		HostRuntimeFeatureHTTP |
		HostRuntimeFeatureWebSocket |
		HostRuntimeFeatureWorker
)

// HostRuntimeProfile provides conservative feature presets.
type HostRuntimeProfile uint8

const (
	// HostRuntimeProfileNodeTool is the default and supports bundled Node-style tools.
	HostRuntimeProfileNodeTool HostRuntimeProfile = iota
	// HostRuntimeProfileBare enables only explicitly requested features.
	HostRuntimeProfileBare
	// HostRuntimeProfileAll enables experimental networking and worker features too.
	HostRuntimeProfileAll
)

// FileSystemMode controls whether filesystem paths are confined to a configured root.
type FileSystemMode uint8

const (
	FileSystemSandbox FileSystemMode = iota
	FileSystemHost
)

// FileSystemOptions configures the host filesystem exposed to JavaScript.
type FileSystemOptions struct {
	// Mode defaults to FileSystemSandbox.
	Mode FileSystemMode
	// Root is the sandbox boundary and defaults to the runtime CWD.
	// FileSystemHost does not restrict access to Root.
	Root string
	// Mounts configures a static virtual filesystem namespace. When non-empty,
	// each mount maps one top-level virtual path to an independent host root.
	Mounts []FileSystemMount
	// VirtualCWD is the initial virtual working directory in multi-mount mode.
	// It defaults to "/".
	VirtualCWD string
}

// FileSystemMount maps a top-level virtual path to a host directory.
type FileSystemMount struct {
	Path     string
	Root     string
	ReadOnly bool
}

// HostRuntimeOptions configures optional Web-like and Node-style host APIs.
type HostRuntimeOptions struct {
	CWD                  string
	Args                 []string
	Env                  map[string]string
	ExecPath             string
	Profile              HostRuntimeProfile
	EnableFeatures       HostRuntimeFeature
	DisableFeatures      HostRuntimeFeature
	FileSystem           FileSystemOptions
	Stdin                io.Reader
	Stdout               io.Writer
	Stderr               io.Writer
	FetchClient          *http.Client
	MaxBufferedBodyBytes int64
}

type hostRuntimeConfig struct {
	cwd         string
	args        []string
	env         map[string]string
	execPath    string
	features    HostRuntimeFeature
	fs          FileSystemOptions
	stdin       io.Reader
	stdout      io.Writer
	stderr      io.Writer
	fetchClient *http.Client
	maxBodySize int64
}

type hostRuntimeState struct {
	config     hostRuntimeConfig
	net        *hostNetState
	workers    *hostWorkerManager
	async      *hostAsyncManager
	fsys       *hostFileSystem
	fetchState *hostFetchState
	closeOnce  sync.Once

	cwdMu sync.RWMutex
	cwd   string

	nextSignalID int64
	signalsMu    sync.Mutex
	signals      map[int64]*hostSignal
	signalEvents []hostSignalEvent
}

type hostSignal struct {
	id     int64
	label  string
	cancel context.CancelFunc
	closed atomic.Bool
}

type hostSignalEvent struct {
	ID     int64  `json:"id"`
	Signal string `json:"signal"`
}

type execFileRequest struct {
	file      string
	args      []string
	cwd       string
	env       map[string]string
	input     []byte
	timeoutMs int64
	ctx       context.Context
}

// InstallHostRuntime installs optional Web-like and Node-style APIs on the runtime context.
func (r *Runtime) InstallHostRuntime(options ...HostRuntimeOptions) error {
	if r == nil || r.context == nil {
		return errors.New("runtime is closed")
	}

	return r.context.InstallHostRuntime(options...)
}

// InstallHostRuntime installs optional Web-like and Node-style APIs on the context.
func (c *Context) InstallHostRuntime(options ...HostRuntimeOptions) error {
	if c == nil || c.runtime == nil {
		return errors.New("context is closed")
	}
	if err := c.runtime.beginHostInstall(); err != nil {
		return err
	}

	config, err := c.newHostRuntimeConfig(options...)
	if err != nil {
		c.runtime.abortHostInstall()
		return err
	}
	fsys, err := newHostFileSystem(config.fs, config.cwd)
	if err != nil {
		c.runtime.abortHostInstall()
		return err
	}

	state := &hostRuntimeState{
		config:     config,
		cwd:        config.cwd,
		net:        newHostNetState(),
		workers:    newHostWorkerManager(),
		async:      newHostAsyncManager(c.Context),
		fsys:       fsys,
		fetchState: newHostFetchState(c.Context, config.fetchClient),
		signals:    make(map[int64]*hostSignal),
	}

	c.runtime.finishHostInstall()
	c.runtime.addCleanup(state.close)
	state.installHostFunctions(c)

	result, err := c.Eval("host-runtime.js", Code(hostRuntimeScript))
	if result != nil {
		result.Free()
	}
	if err != nil {
		return err
	}

	return c.installHostRuntimeModules(config)
}

func (c *Context) installHostRuntimeModules(config hostRuntimeConfig) error {
	modules := map[string]string{}
	if config.hasFeature(HostRuntimeFeatureFS) {
		modules["fs"] = hostFSModuleScript
		modules["node:fs"] = hostFSModuleScript
		modules["fs/promises"] = hostFSPromisesModuleScript
		modules["node:fs/promises"] = hostFSPromisesModuleScript
	}
	if config.hasFeature(HostRuntimeFeatureProcess) {
		modules["process"] = hostProcessModuleScript
		modules["node:process"] = hostProcessModuleScript
	}
	if config.hasFeature(HostRuntimeFeatureNodeCompat) {
		modules["buffer"] = hostBufferModuleScript
		modules["node:buffer"] = hostBufferModuleScript
		modules["path"] = hostPathModuleScript
		modules["node:path"] = hostPathModuleScript
		modules["os"] = hostOSModuleScript
		modules["node:os"] = hostOSModuleScript
		modules["crypto"] = hostCryptoModuleScript
		modules["node:crypto"] = hostCryptoModuleScript
		modules["perf_hooks"] = hostPerfHooksModuleScript
		modules["node:perf_hooks"] = hostPerfHooksModuleScript
	}

	for name, source := range modules {
		result, err := c.Load(name, Code(source))
		if result != nil {
			result.Free()
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Context) newHostRuntimeConfig(options ...HostRuntimeOptions) (hostRuntimeConfig, error) {
	if len(options) > 1 {
		return hostRuntimeConfig{}, errors.New("InstallHostRuntime accepts at most one options value")
	}

	var option HostRuntimeOptions
	if len(options) > 0 {
		option = options[0]
	}

	if option.CWD == "" {
		option.CWD = c.runtime.option.CWD
	}

	if option.Stdout == nil {
		option.Stdout = c.runtime.option.Stdout
	}

	if option.Stderr == nil {
		option.Stderr = c.runtime.option.Stderr
	}

	if option.Stdin == nil {
		option.Stdin = os.Stdin
	}
	if option.FetchClient == nil {
		option.FetchClient = &http.Client{}
	}
	if option.MaxBufferedBodyBytes == 0 {
		option.MaxBufferedBodyBytes = 64 << 20
	}

	features := HostRuntimeFeatureNodeTool
	switch option.Profile {
	case HostRuntimeProfileNodeTool:
	case HostRuntimeProfileBare:
		features = 0
	case HostRuntimeProfileAll:
		features = HostRuntimeFeatureAll
	default:
		return hostRuntimeConfig{}, fmt.Errorf("invalid host runtime profile %d", option.Profile)
	}
	features |= option.EnableFeatures
	features &^= option.DisableFeatures

	cwd, err := filepath.Abs(option.CWD)
	if err != nil {
		return hostRuntimeConfig{}, err
	}
	info, err := os.Stat(cwd)
	if err != nil {
		return hostRuntimeConfig{}, fmt.Errorf("stat runtime CWD: %w", err)
	}
	if !info.IsDir() {
		return hostRuntimeConfig{}, fmt.Errorf("runtime CWD is not a directory: %s", cwd)
	}

	if len(option.FileSystem.Mounts) == 0 {
		if option.FileSystem.VirtualCWD != "" {
			return hostRuntimeConfig{}, errors.New("filesystem VirtualCWD requires multi-mount mode")
		}
		if option.FileSystem.Root == "" {
			option.FileSystem.Root = cwd
		}
		option.FileSystem.Root, err = filepath.Abs(option.FileSystem.Root)
		if err != nil {
			return hostRuntimeConfig{}, fmt.Errorf("resolve filesystem root: %w", err)
		}
	} else {
		if option.FileSystem.Mode != FileSystemSandbox {
			return hostRuntimeConfig{}, errors.New("filesystem mounts require sandbox mode")
		}
		if option.FileSystem.Root != "" {
			return hostRuntimeConfig{}, errors.New("filesystem Root and Mounts cannot be used together")
		}
		option.FileSystem.Mounts = append([]FileSystemMount(nil), option.FileSystem.Mounts...)
	}

	env := cloneStringMap(option.Env)
	if env == nil {
		env = environMap()
	}

	args := append([]string(nil), option.Args...)
	if args == nil {
		args = append([]string(nil), os.Args...)
	}

	if option.ExecPath == "" {
		option.ExecPath, _ = os.Executable()
	}

	return hostRuntimeConfig{
		cwd:         cwd,
		args:        args,
		env:         env,
		execPath:    option.ExecPath,
		features:    features,
		fs:          option.FileSystem,
		stdin:       option.Stdin,
		stdout:      option.Stdout,
		stderr:      option.Stderr,
		fetchClient: option.FetchClient,
		maxBodySize: option.MaxBufferedBodyBytes,
	}, nil
}

func (c hostRuntimeConfig) hasFeature(feature HostRuntimeFeature) bool {
	return c.features&feature != 0
}

func cloneStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}

	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}

	return out
}

func environMap() map[string]string {
	env := map[string]string{}
	for _, item := range os.Environ() {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			env[key] = value
		}
	}

	return env
}

func envMapToList(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+env[key])
	}

	return result
}

func (s *hostRuntimeState) runtimeConfigJSON(this *This) (*Value, error) {
	config := map[string]any{
		"maxBufferedBodyBytes": s.config.maxBodySize,
		"platform":             nodePlatform(),
		"arch":                 nodeArch(),
		"features": map[string]bool{
			"crypto":       s.config.hasFeature(HostRuntimeFeatureCrypto),
			"fetch":        s.config.hasFeature(HostRuntimeFeatureFetch),
			"fs":           s.config.hasFeature(HostRuntimeFeatureFS),
			"process":      s.config.hasFeature(HostRuntimeFeatureProcess),
			"childProcess": s.config.hasFeature(HostRuntimeFeatureChildProcess),
			"net":          s.config.hasFeature(HostRuntimeFeatureNet),
			"http":         s.config.hasFeature(HostRuntimeFeatureHTTP),
			"websocket":    s.config.hasFeature(HostRuntimeFeatureWebSocket),
			"worker":       s.config.hasFeature(HostRuntimeFeatureWorker),
			"nodeCompat":   s.config.hasFeature(HostRuntimeFeatureNodeCompat),
		},
	}

	data, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	return this.Context().NewString(string(data)), nil
}

func (s *hostRuntimeState) installHostFunctions(c *Context) {
	c.SetFunc("__qjs_runtime_config_json", s.runtimeConfigJSON)
	c.SetFunc("__qjs_console_print", s.consolePrint)
	c.SetFunc("__qjs_async_poll", s.asyncPoll)
	c.SetFunc("__qjs_async_cancel", s.asyncCancel)
	c.SetFunc("__qjs_now_unix_ms", func(this *This) (*Value, error) {
		return this.Context().NewInt64(time.Now().UnixMilli()), nil
	})
	c.SetFunc("__qjs_sleep", s.sleep)

	if s.config.hasFeature(HostRuntimeFeatureCrypto) {
		c.SetFunc("__qjs_crypto_random", s.cryptoRandom)
		c.SetFunc("__qjs_crypto_uuid", s.cryptoUUID)
		c.SetFunc("__qjs_crypto_digest_async_start", s.cryptoDigestAsyncStart)
	}
	if s.config.hasFeature(HostRuntimeFeatureFetch) {
		c.SetFunc("__qjs_fetch_start", s.fetchStart)
		c.SetFunc("__qjs_fetch_body_read_start", s.fetchBodyReadStart)
		c.SetFunc("__qjs_fetch_body_close", s.fetchBodyClose)
	}
	if s.config.hasFeature(HostRuntimeFeatureFS) {
		c.SetFunc("__qjs_fs_sync", s.hostFSSync)
		c.SetFunc("__qjs_fs_host_async_start", s.hostFSAsyncStart)
	}
	if s.config.hasFeature(HostRuntimeFeatureProcess) {
		c.SetFunc("__qjs_process_info", s.processInfo)
		c.SetFunc("__qjs_process_cwd", s.processCWD)
		c.SetFunc("__qjs_process_chdir", s.processChdir)
		c.SetFunc("__qjs_process_env_json", s.processEnvJSON)
		c.SetFunc("__qjs_process_exit", s.processExit)
		c.SetFunc("__qjs_stream_write", s.stdioWrite)
	}
	if s.config.hasFeature(HostRuntimeFeatureNodeCompat) {
		c.SetFunc("__qjs_hash_digest", s.hashDigest)
	}
	if s.config.hasFeature(HostRuntimeFeatureChildProcess) {
		c.SetFunc("__qjs_process_kill", s.processKill)
		c.SetFunc("__qjs_exec_file", s.execFile)
		c.SetFunc("__qjs_exec_file_async_start", s.execFileAsyncStart)
		c.SetFunc("__qjs_signal_on", s.signalOn)
		c.SetFunc("__qjs_signal_off", s.signalOff)
		c.SetFunc("__qjs_signal_poll", s.signalPoll)
	}
	if s.config.hasFeature(HostRuntimeFeatureNet) {
		s.installNetHostFunctions(c)
	}
	if s.config.hasFeature(HostRuntimeFeatureHTTP) || s.config.hasFeature(HostRuntimeFeatureWebSocket) {
		s.installHTTPHostFunctions(c)
	}
	if s.config.hasFeature(HostRuntimeFeatureWorker) {
		s.installWorkerHostFunctions(c)
	}
}

func (s *hostRuntimeState) sleep(this *This) (*Value, error) {
	delay := int64(0)
	if args := this.Args(); len(args) > 0 {
		delay = args[0].Int64()
	}
	if delay < 0 {
		delay = 0
	}

	time.Sleep(time.Duration(delay) * time.Millisecond)

	return this.Context().NewUndefined(), nil
}

func (s *hostRuntimeState) consolePrint(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 2 {
		return this.Context().NewUndefined(), nil
	}

	level := args[0].String()
	message := args[1].String()
	out := s.config.stdout
	if level == "error" || level == "warn" || level == "trace" {
		out = s.config.stderr
	}

	if out != nil {
		fmt.Fprintln(out, message)
	}

	return this.Context().NewUndefined(), nil
}

func (s *hostRuntimeState) cryptoRandom(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("crypto random requires a byte length")
	}

	size := args[0].Int64()
	if size < 0 || size > maxCryptoRandomValues {
		return nil, fmt.Errorf("crypto random byte length must be between 0 and %d", maxCryptoRandomValues)
	}

	data := make([]byte, size)
	if _, err := cryptorand.Read(data); err != nil {
		return nil, err
	}

	return this.Context().NewArrayBuffer(data), nil
}

func (s *hostRuntimeState) cryptoUUID(this *This) (*Value, error) {
	data := make([]byte, 16)
	if _, err := cryptorand.Read(data); err != nil {
		return nil, err
	}

	data[6] = (data[6] & 0x0f) | 0x40
	data[8] = (data[8] & 0x3f) | 0x80

	uuid := fmt.Sprintf(
		"%s-%s-%s-%s-%s",
		hex.EncodeToString(data[0:4]),
		hex.EncodeToString(data[4:6]),
		hex.EncodeToString(data[6:8]),
		hex.EncodeToString(data[8:10]),
		hex.EncodeToString(data[10:16]),
	)

	return this.Context().NewString(uuid), nil
}

func (s *hostRuntimeState) cryptoDigestAsyncStart(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 2 {
		return nil, errors.New("crypto.subtle.digest requires algorithm and data")
	}

	algorithm := normalizeDigestAlgorithm(args[0].String())
	data, err := jsValueToBytes(args[1])
	if err != nil {
		return nil, err
	}

	id, err := s.async.start(func(ctx context.Context) (any, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return runCryptoDigest(algorithm, data)
	})
	if err != nil {
		return nil, err
	}

	return this.Context().NewInt64(id), nil
}

func runCryptoDigest(algorithm string, data []byte) ([]byte, error) {
	var digest []byte
	switch algorithm {
	case "SHA-1":
		sum := sha1.Sum(data)
		digest = sum[:]
	case "SHA-256":
		sum := sha256.Sum256(data)
		digest = sum[:]
	case "SHA-384":
		sum := sha512.Sum384(data)
		digest = sum[:]
	case "SHA-512":
		sum := sha512.Sum512(data)
		digest = sum[:]
	default:
		return nil, fmt.Errorf("unsupported digest algorithm %q", algorithm)
	}

	return digest, nil
}

func normalizeDigestAlgorithm(algorithm string) string {
	algorithm = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(algorithm), "_", "-"))
	switch algorithm {
	case "SHA1":
		return "SHA-1"
	case "SHA256":
		return "SHA-256"
	case "SHA384":
		return "SHA-384"
	case "SHA512":
		return "SHA-512"
	default:
		return algorithm
	}
}

func (s *hostRuntimeState) currentCWD() string {
	if s.fsys != nil {
		return s.fsys.currentCWD()
	}
	s.cwdMu.RLock()
	defer s.cwdMu.RUnlock()

	if s.cwd != "" {
		return s.cwd
	}

	return s.config.cwd
}

func (s *hostRuntimeState) resolveHostPath(name string, writable bool) (string, error) {
	if s.fsys != nil {
		return s.fsys.resolveHostPath(name, writable)
	}
	return s.resolvePathFrom(s.currentCWD(), name)
}

func (s *hostRuntimeState) resolvePathFrom(base, name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", errors.New("path is required")
	}

	root, err := filepath.Abs(s.config.cwd)
	if err != nil {
		return "", err
	}

	basePath := base
	cleanName := filepath.Clean(filepath.FromSlash(name))
	if filepath.IsAbs(cleanName) {
		volume := filepath.VolumeName(cleanName)
		cleanName = strings.TrimPrefix(cleanName, volume)
		cleanName = strings.TrimLeft(cleanName, `\/`)
		basePath = root
	}

	fullPath := filepath.Join(basePath, cleanName)
	fullPath, err = filepath.Abs(fullPath)
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(root, fullPath)
	if err != nil {
		return "", err
	}

	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes runtime CWD", name)
	}

	return fullPath, nil
}

func (s *hostRuntimeState) chdir(path string) (string, error) {
	if s.fsys != nil {
		return s.fsys.chdir(path)
	}
	next, err := s.resolveHostPath(path, false)
	if err != nil {
		return "", err
	}

	info, err := os.Stat(next)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("not a directory: %s", path)
	}

	s.cwdMu.Lock()
	s.cwd = next
	s.cwdMu.Unlock()

	return next, nil
}

func (s *hostRuntimeState) processInfo(this *This) (*Value, error) {
	info := map[string]any{
		"pid":      os.Getpid(),
		"ppid":     os.Getppid(),
		"platform": nodePlatform(),
		"arch":     nodeArch(),
		"cwd":      s.currentCWD(),
		"execPath": s.config.execPath,
		"argv":     append([]string(nil), s.config.args...),
		"args":     append([]string(nil), s.config.args...),
	}

	return ToJsValue(this.Context(), info)
}

func nodePlatform() string {
	if goruntime.GOOS == "windows" {
		return "win32"
	}
	return goruntime.GOOS
}

func nodeArch() string {
	switch goruntime.GOARCH {
	case "amd64":
		return "x64"
	case "386":
		return "ia32"
	default:
		return goruntime.GOARCH
	}
}

func (s *hostRuntimeState) processCWD(this *This) (*Value, error) {
	return this.Context().NewString(s.currentCWD()), nil
}

func (s *hostRuntimeState) processChdir(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("chdir requires a path")
	}

	cwd, err := s.chdir(args[0].String())
	if err != nil {
		return nil, err
	}

	return this.Context().NewString(cwd), nil
}

func (s *hostRuntimeState) processEnvJSON(this *This) (*Value, error) {
	data, err := json.Marshal(s.config.env)
	if err != nil {
		return nil, err
	}

	return this.Context().NewString(string(data)), nil
}

func (s *hostRuntimeState) processKill(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("kill requires a pid")
	}

	pid := int(args[0].Int64())
	signalName := "SIGTERM"
	if len(args) > 1 && !args[1].IsUndefined() && !args[1].IsNull() {
		signalName = args[1].String()
	}

	signal, err := parseProcessSignal(signalName)
	if err != nil {
		return nil, err
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil, err
	}
	if err := proc.Signal(signal); err != nil {
		return nil, err
	}

	return this.Context().NewBool(true), nil
}

func (s *hostRuntimeState) execFile(this *This) (*Value, error) {
	request, err := s.newExecFileRequest(this)
	if err != nil {
		return nil, err
	}

	result, err := s.doExecFile(request)
	if err != nil {
		return nil, err
	}

	return ToJsValue(this.Context(), result)
}

func (s *hostRuntimeState) execFileAsyncStart(this *This) (*Value, error) {
	request, err := s.newExecFileRequest(this)
	if err != nil {
		return nil, err
	}

	id, err := s.async.start(func(ctx context.Context) (any, error) {
		request.ctx = ctx
		return s.doExecFile(request)
	})
	if err != nil {
		return nil, err
	}

	return this.Context().NewInt64(id), nil
}

func (s *hostRuntimeState) newExecFileRequest(this *This) (execFileRequest, error) {
	args := this.Args()
	if len(args) < 6 {
		return execFileRequest{}, errors.New("execFile requires file, args, cwd, env, input, and timeout arguments")
	}

	file := args[0].String()
	cmdArgs, err := parseJSONStringSlice(args[1].String())
	if err != nil {
		return execFileRequest{}, fmt.Errorf("invalid execFile args: %w", err)
	}

	cwd := s.currentCWD()
	if argCWD := strings.TrimSpace(args[2].String()); argCWD != "" {
		cwd, err = s.resolveHostPath(argCWD, false)
		if err != nil {
			return execFileRequest{}, err
		}
	} else if s.fsys != nil && s.fsys.multi {
		cwd, err = s.resolveHostPath(cwd, false)
		if err != nil {
			return execFileRequest{}, err
		}
	}

	envMap := cloneStringMap(s.config.env)
	if envJSON := args[3].String(); envJSON != "" {
		envMap = map[string]string{}
		if err := json.Unmarshal([]byte(envJSON), &envMap); err != nil {
			return execFileRequest{}, fmt.Errorf("invalid execFile env: %w", err)
		}
	}

	var input []byte
	if !args[4].IsNull() && !args[4].IsUndefined() {
		input, err = jsValueToBytes(args[4])
		if err != nil {
			return execFileRequest{}, err
		}
	}

	return execFileRequest{
		file:      file,
		args:      cmdArgs,
		cwd:       cwd,
		env:       envMap,
		input:     input,
		timeoutMs: args[5].Int64(),
		ctx:       this.Context().Context,
	}, nil
}

func (s *hostRuntimeState) doExecFile(request execFileRequest) (map[string]any, error) {
	execCtx := request.ctx
	cancel := func() {}
	if request.timeoutMs > 0 {
		execCtx, cancel = context.WithTimeout(execCtx, time.Duration(request.timeoutMs)*time.Millisecond)
	}
	defer cancel()

	cmd := exec.CommandContext(execCtx, request.file, request.args...)
	cmd.Dir = request.cwd
	cmd.Env = envMapToList(request.env)
	if request.input != nil {
		cmd.Stdin = bytes.NewReader(request.input)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("execFile timed out after %dms", request.timeoutMs)
	}

	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return nil, runErr
		}
	}

	return map[string]any{
		"exitCode": exitCode,
		"success":  exitCode == 0,
		"stdout":   stdout.String(),
		"stderr":   stderr.String(),
	}, nil
}

func parseJSONStringSlice(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	var values []string
	err := json.Unmarshal([]byte(raw), &values)

	return values, err
}

func (s *hostRuntimeState) signalOn(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("onSignal requires a signal name")
	}

	sig, label, err := parsePortableSignal(args[0].String())
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	id := atomic.AddInt64(&s.nextSignalID, 1)
	watcher := &hostSignal{
		id:     id,
		label:  label,
		cancel: cancel,
	}

	s.signalsMu.Lock()
	s.signals[id] = watcher
	s.signalsMu.Unlock()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sig)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				s.enqueueSignal(watcher)
			}
		}
	}()

	return this.Context().NewInt64(id), nil
}

func (s *hostRuntimeState) enqueueSignal(watcher *hostSignal) {
	if watcher == nil || watcher.closed.Load() {
		return
	}

	s.signalsMu.Lock()
	if !watcher.closed.Load() {
		s.signalEvents = append(s.signalEvents, hostSignalEvent{ID: watcher.id, Signal: watcher.label})
	}
	s.signalsMu.Unlock()
}

func (s *hostRuntimeState) signalPoll(this *This) (*Value, error) {
	s.signalsMu.Lock()
	events := s.signalEvents
	s.signalEvents = nil
	s.signalsMu.Unlock()

	return ToJsValue(this.Context(), events)
}

func parsePortableSignal(name string) (os.Signal, string, error) {
	normalized := strings.ToUpper(strings.TrimSpace(name))
	normalized = strings.TrimPrefix(normalized, "SIG")
	switch normalized {
	case "INT", "INTERRUPT":
		return os.Interrupt, "SIGINT", nil
	default:
		return nil, "", fmt.Errorf("unsupported portable signal %q", name)
	}
}

func parseProcessSignal(name string) (os.Signal, error) {
	normalized := strings.ToUpper(strings.TrimSpace(name))
	normalized = strings.TrimPrefix(normalized, "SIG")
	switch normalized {
	case "", "TERM", "KILL":
		return os.Kill, nil
	case "INT", "INTERRUPT":
		return os.Interrupt, nil
	default:
		return nil, fmt.Errorf("unsupported signal %q", name)
	}
}

func (s *hostRuntimeState) signalOff(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return this.Context().NewUndefined(), nil
	}

	s.deleteSignal(args[0].Int64())

	return this.Context().NewUndefined(), nil
}

func (s *hostRuntimeState) deleteSignal(id int64) {
	s.signalsMu.Lock()
	watcher := s.signals[id]
	delete(s.signals, id)
	s.signalsMu.Unlock()

	if watcher != nil {
		watcher.close()
	}
}

func (s *hostSignal) close() {
	s.closed.Store(true)
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *hostRuntimeState) close() {
	s.closeOnce.Do(s.closeResources)
}

func (s *hostRuntimeState) closeResources() {
	if s.fetchState != nil {
		s.fetchState.close()
	}
	if s.async != nil {
		s.async.close()
	}
	if s.fsys != nil {
		s.fsys.close()
	}
	if s.net != nil {
		s.net.close()
	}
	if s.workers != nil {
		s.workers.close()
	}

	s.signalsMu.Lock()
	signals := make([]*hostSignal, 0, len(s.signals))
	for id, watcher := range s.signals {
		delete(s.signals, id)
		signals = append(signals, watcher)
	}
	s.signalsMu.Unlock()

	for _, watcher := range signals {
		watcher.close()
	}
}

func jsValueToBytes(value *Value) ([]byte, error) {
	switch {
	case value == nil || value.IsNull() || value.IsUndefined():
		return nil, nil
	case value.IsString():
		return []byte(value.String()), nil
	case value.IsByteArray():
		data := value.ToByteArray()
		return append([]byte(nil), data...), nil
	case IsTypedArray(value):
		data, err := JsTypedArrayToGo(value)
		if err != nil {
			return nil, err
		}

		return append([]byte(nil), data...), nil
	case value.String() == "[object ArrayBuffer]":
		data := value.ToByteArray()
		return append([]byte(nil), data...), nil
	default:
		return nil, fmt.Errorf("expected string, ArrayBuffer, or TypedArray, got %s", value.Type())
	}
}

const hostRuntimeScript = `
(function () {
  const define = (target, name, value, enumerable) => {
    Object.defineProperty(target, name, {
      configurable: true,
      writable: true,
      enumerable: !!enumerable,
      value
    });
  };

  const qjs = globalThis.qjs && typeof globalThis.qjs === "object" ? globalThis.qjs : {};
  define(globalThis, "qjs", qjs);
  const runtimeConfig = JSON.parse(__qjs_runtime_config_json());
  const feature = name => !!(runtimeConfig.features && runtimeConfig.features[name]);

  function createHostError(info, fallbackName = "Error") {
    if (!info || typeof info !== "object") return new Error(String(info || "Host operation failed"));
    const error = new Error(info.message || "Host operation failed");
    error.name = info.name || fallbackName;
    for (const key of ["code", "errno", "syscall", "path", "dest"]) {
      if (info[key] !== undefined && info[key] !== "") error[key] = info[key];
    }
    return error;
  }

  const pendingHostOperations = new Map();
  let hostOperationTimer = 0;

  function scheduleHostOperationPump() {
    if (hostOperationTimer || pendingHostOperations.size === 0) return;
    hostOperationTimer = setTimeout(pumpHostOperations, 1);
  }

  function pumpHostOperations() {
    hostOperationTimer = 0;
    for (const [id, operation] of Array.from(pendingHostOperations)) {
      let payload;
      try {
        payload = __qjs_async_poll(id);
      } catch (error) {
        pendingHostOperations.delete(id);
        operation.cleanup();
        operation.reject(error);
        continue;
      }
      if (!payload.done) continue;
      pendingHostOperations.delete(id);
      operation.cleanup();
      if (payload.error) {
        const hostError = payload.error.name === "AbortError" && operation.signal && operation.signal.aborted
          ? operation.signal.reason || new DOMException("This operation was aborted", "AbortError")
          : createHostError(payload.error);
        operation.reject(hostError);
      } else {
        try {
          operation.resolve(operation.transform ? operation.transform(payload.result) : payload.result);
        } catch (error) {
          operation.reject(error);
        }
      }
    }
    scheduleHostOperationPump();
  }

  function hostAsync(start, options = {}) {
    return new Promise((resolve, reject) => {
      let id;
      try {
        id = start();
      } catch (error) {
        reject(error);
        return;
      }
      const signal = options.signal;
      const onAbort = () => __qjs_async_cancel(id);
      const cleanup = () => {
        if (signal) signal.removeEventListener("abort", onAbort);
      };
      if (signal) {
        if (signal.aborted) {
          __qjs_async_cancel(id);
        } else {
          signal.addEventListener("abort", onAbort, { once: true });
        }
      }
      pendingHostOperations.set(id, { resolve, reject, cleanup, transform: options.transform, signal });
      scheduleHostOperationPump();
    });
  }
  if (typeof globalThis.self === "undefined") define(globalThis, "self", globalThis);
  const nativeSetTimeout = globalThis.setTimeout;
  const nativeClearTimeout = globalThis.clearTimeout;
  const nativeSetInterval = globalThis.setInterval;
  const nativeClearInterval = globalThis.clearInterval;

  if (typeof globalThis.DOMException !== "function") {
    class DOMException extends Error {
      constructor(message = "", name = "Error") {
        super(String(message));
        this.name = String(name);
      }
    }
    define(globalThis, "DOMException", DOMException);
  }

  if (typeof globalThis.Event !== "function") {
    class Event {
      constructor(type, options = {}) {
        this.type = String(type);
        this.bubbles = !!options.bubbles;
        this.cancelable = !!options.cancelable;
        this.composed = !!options.composed;
        this.defaultPrevented = false;
        this.target = null;
        this.currentTarget = null;
        this.timeStamp = Date.now();
      }
      preventDefault() {
        if (this.cancelable) this.defaultPrevented = true;
      }
      stopPropagation() {}
      stopImmediatePropagation() {}
    }
    define(globalThis, "Event", Event);
  }

  if (typeof globalThis.EventTarget !== "function") {
    class EventTarget {
      constructor() {
        this.__qjsListeners = new Map();
      }
      addEventListener(type, callback) {
        if (callback == null) return;
        type = String(type);
        if (!this.__qjsListeners.has(type)) this.__qjsListeners.set(type, new Set());
        this.__qjsListeners.get(type).add(callback);
      }
      removeEventListener(type, callback) {
        const callbacks = this.__qjsListeners.get(String(type));
        if (callbacks) callbacks.delete(callback);
      }
      dispatchEvent(event) {
        if (!event || typeof event.type !== "string") throw new TypeError("event type is required");
        if (!event.target) event.target = this;
        event.currentTarget = this;
        const callbacks = this.__qjsListeners.get(event.type);
        if (callbacks) {
          for (const callback of Array.from(callbacks)) {
            if (typeof callback === "function") callback.call(this, event);
            else if (callback && typeof callback.handleEvent === "function") callback.handleEvent(event);
          }
        }
        const handler = this["on" + event.type];
        if (typeof handler === "function") handler.call(this, event);
        return !event.defaultPrevented;
      }
    }
    define(globalThis, "EventTarget", EventTarget);
  }

  if (typeof globalThis.MessageEvent !== "function") {
    class MessageEvent extends Event {
      constructor(type, options = {}) {
        super(type, options);
        this.data = options.data;
        this.origin = options.origin || "";
        this.lastEventId = options.lastEventId || "";
        this.source = options.source || null;
        this.ports = options.ports || [];
      }
    }
    define(globalThis, "MessageEvent", MessageEvent);
  }

  if (typeof globalThis.ErrorEvent !== "function") {
    class ErrorEvent extends Event {
      constructor(type, options = {}) {
        super(type, options);
        this.message = options.message || "";
        this.filename = options.filename || "";
        this.lineno = options.lineno || 0;
        this.colno = options.colno || 0;
        this.error = options.error;
      }
    }
    define(globalThis, "ErrorEvent", ErrorEvent);
  }

  if (typeof globalThis.AbortController !== "function") {
    class AbortSignal extends EventTarget {
      constructor() {
        super();
        this.aborted = false;
        this.reason = undefined;
      }
      throwIfAborted() {
        if (this.aborted) throw this.reason;
      }
    }
    class AbortController {
      constructor() {
        this.signal = new AbortSignal();
      }
      abort(reason) {
        const signal = this.signal;
        if (signal.aborted) return;
        signal.aborted = true;
        signal.reason = reason === undefined ? new DOMException("This operation was aborted", "AbortError") : reason;
        signal.dispatchEvent(new Event("abort"));
      }
    }
    define(globalThis, "AbortSignal", AbortSignal);
    define(globalThis, "AbortController", AbortController);
  }

  if (typeof globalThis.queueMicrotask !== "function") {
    define(globalThis, "queueMicrotask", function queueMicrotask(callback) {
      if (typeof callback !== "function") throw new TypeError("callback must be a function");
      Promise.resolve().then(callback);
    });
  }

  if (typeof globalThis.performance !== "object") {
    define(globalThis, "performance", {
      timeOrigin: __qjs_now_unix_ms(),
      now() {
        return __qjs_now_unix_ms() - this.timeOrigin;
      }
    });
  } else if (typeof globalThis.performance.now !== "function") {
    globalThis.performance.now = function now() {
      return __qjs_now_unix_ms();
    };
  }

  if (typeof globalThis.atob !== "function" || typeof globalThis.btoa !== "function") {
    const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const base64Lookup = Object.create(null);
    for (let i = 0; i < base64Alphabet.length; i++) base64Lookup[base64Alphabet[i]] = i;
    define(globalThis, "btoa", function btoa(input) {
      const str = String(input);
      let out = "";
      for (let i = 0; i < str.length; i += 3) {
        const a = str.charCodeAt(i);
        const b = i + 1 < str.length ? str.charCodeAt(i + 1) : NaN;
        const c = i + 2 < str.length ? str.charCodeAt(i + 2) : NaN;
        if (a > 255 || b > 255 || c > 255) throw new DOMException("The string to be encoded contains characters outside of the Latin1 range.", "InvalidCharacterError");
        const triplet = (a << 16) | ((b || 0) << 8) | (c || 0);
        out += base64Alphabet[(triplet >> 18) & 63];
        out += base64Alphabet[(triplet >> 12) & 63];
        out += Number.isNaN(b) ? "=" : base64Alphabet[(triplet >> 6) & 63];
        out += Number.isNaN(c) ? "=" : base64Alphabet[triplet & 63];
      }
      return out;
    });
    define(globalThis, "atob", function atob(input) {
      const str = String(input).replace(/[\t\n\f\r ]+/g, "");
      if (str.length % 4 === 1) throw new DOMException("Invalid base64 input", "InvalidCharacterError");
      let out = "";
      for (let i = 0; i < str.length; i += 4) {
        const a = base64Lookup[str[i]];
        const b = base64Lookup[str[i + 1]];
        const c = str[i + 2] === "=" || i + 2 >= str.length ? 0 : base64Lookup[str[i + 2]];
        const d = str[i + 3] === "=" || i + 3 >= str.length ? 0 : base64Lookup[str[i + 3]];
        if (a === undefined || b === undefined || c === undefined || d === undefined) throw new DOMException("Invalid base64 input", "InvalidCharacterError");
        const triplet = (a << 18) | (b << 12) | (c << 6) | d;
        out += String.fromCharCode((triplet >> 16) & 255);
        if (str[i + 2] !== "=" && i + 2 < str.length) out += String.fromCharCode((triplet >> 8) & 255);
        if (str[i + 3] !== "=" && i + 3 < str.length) out += String.fromCharCode(triplet & 255);
      }
      return out;
    });
  }

  function utf8Encode(value) {
    value = String(value);
    const bytes = [];
    for (let i = 0; i < value.length; i++) {
      let code = value.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff && i + 1 < value.length) {
        const next = value.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          code = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
          i++;
        }
      }
      if (code <= 0x7f) {
        bytes.push(code);
      } else if (code <= 0x7ff) {
        bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
      } else if (code <= 0xffff) {
        bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
      } else {
        bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
      }
    }
    return new Uint8Array(bytes);
  }

  function utf8Decode(input) {
    const bytes = input instanceof Uint8Array ? input : new Uint8Array(input || 0);
    let out = "";
    for (let i = 0; i < bytes.length;) {
      const b0 = bytes[i++];
      if (b0 < 0x80) {
        out += String.fromCharCode(b0);
      } else if ((b0 & 0xe0) === 0xc0) {
        const b1 = bytes[i++] & 0x3f;
        out += String.fromCharCode(((b0 & 0x1f) << 6) | b1);
      } else if ((b0 & 0xf0) === 0xe0) {
        const b1 = bytes[i++] & 0x3f;
        const b2 = bytes[i++] & 0x3f;
        out += String.fromCharCode(((b0 & 0x0f) << 12) | (b1 << 6) | b2);
      } else {
        const b1 = bytes[i++] & 0x3f;
        const b2 = bytes[i++] & 0x3f;
        const b3 = bytes[i++] & 0x3f;
        let code = ((b0 & 0x07) << 18) | (b1 << 12) | (b2 << 6) | b3;
        code -= 0x10000;
        out += String.fromCharCode(0xd800 + (code >> 10), 0xdc00 + (code & 0x3ff));
      }
    }
    return out;
  }

  if (typeof globalThis.TextEncoder !== "function") {
    class TextEncoder {
      constructor() {
        this.encoding = "utf-8";
      }
      encode(input = "") {
        return utf8Encode(input);
      }
      encodeInto(source, destination) {
        const bytes = utf8Encode(source);
        const written = Math.min(bytes.length, destination.length);
        destination.set(bytes.subarray(0, written));
        return { read: String(source).length, written };
      }
    }
    define(globalThis, "TextEncoder", TextEncoder);
  }

  if (typeof globalThis.TextDecoder !== "function") {
    class TextDecoder {
      constructor(label = "utf-8") {
        this.encoding = String(label).toLowerCase();
        if (this.encoding !== "utf-8" && this.encoding !== "utf8") throw new RangeError("Only utf-8 TextDecoder is supported");
        this.encoding = "utf-8";
      }
      decode(input = new Uint8Array()) {
        return utf8Decode(input);
      }
    }
    define(globalThis, "TextDecoder", TextDecoder);
  }

  const encoder = typeof TextEncoder !== "undefined" ? new TextEncoder() : null;
  const decoder = typeof TextDecoder !== "undefined" ? new TextDecoder() : null;

  function encodeString(value) {
    value = String(value);
    if (encoder) return encoder.encode(value).buffer;
    const bytes = new Uint8Array(value.length);
    for (let i = 0; i < value.length; i++) bytes[i] = value.charCodeAt(i) & 0xff;
    return bytes.buffer;
  }

  function decodeBytes(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    if (decoder) return decoder.decode(bytes);
    let out = "";
    for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
    return out;
  }

  function toArrayBuffer(value) {
    if (value == null) return null;
    if (value instanceof ArrayBuffer) return value.slice(0);
    if (ArrayBuffer.isView(value)) {
      return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
    }
    if (typeof Blob !== "undefined" && value instanceof Blob) return value.arrayBufferSync();
    return encodeString(value);
  }

  if (typeof globalThis.structuredClone !== "function") {
    define(globalThis, "structuredClone", function structuredClone(value) {
      const seen = new Map();
      function clone(item) {
        if (item === null || typeof item !== "object") return item;
        if (seen.has(item)) return seen.get(item);
        if (item instanceof Date) return new Date(item.getTime());
        if (item instanceof RegExp) return new RegExp(item.source, item.flags);
        if (item instanceof ArrayBuffer) return item.slice(0);
        if (ArrayBuffer.isView(item)) return new item.constructor(item);
        if (item instanceof Map) {
          const out = new Map();
          seen.set(item, out);
          item.forEach((v, k) => out.set(clone(k), clone(v)));
          return out;
        }
        if (item instanceof Set) {
          const out = new Set();
          seen.set(item, out);
          item.forEach(v => out.add(clone(v)));
          return out;
        }
        if (Array.isArray(item)) {
          const out = [];
          seen.set(item, out);
          for (const entry of item) out.push(clone(entry));
          return out;
        }
        const out = {};
        seen.set(item, out);
        for (const key of Object.keys(item)) out[key] = clone(item[key]);
        return out;
      }
      return clone(value);
    });
  }

  function concatUint8Arrays(chunks) {
    let size = 0;
    for (const chunk of chunks) size += chunk.byteLength;
    const out = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      out.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return out;
  }

  if (typeof globalThis.ReadableStream !== "function") {
    class ReadableStreamDefaultController {
      constructor(stream) { this._stream = stream; }
      enqueue(chunk) { this._stream._enqueue(chunk); }
      close() { this._stream._close(); }
      error(error) { this._stream._error(error); }
      get desiredSize() { return this._stream._queue.length === 0 ? 1 : 0; }
    }

    class ReadableStreamDefaultReader {
      constructor(stream) {
        if (stream.locked) throw new TypeError("ReadableStream is locked");
        this._stream = stream;
        stream._reader = this;
        this.closed = stream._closedPromise;
      }
      read() {
        if (!this._stream) return Promise.reject(new TypeError("Reader has been released"));
        return this._stream._read();
      }
      cancel(reason) {
        if (!this._stream) return Promise.reject(new TypeError("Reader has been released"));
        return this._stream._cancel(reason);
      }
      releaseLock() {
        if (!this._stream) return;
        if (this._stream._reads.length) throw new TypeError("Cannot release a reader with pending reads");
        this._stream._reader = null;
        this._stream = null;
      }
    }

    class ReadableStream {
      constructor(source = {}) {
        this._source = source || {};
        this._queue = [];
        this._reads = [];
        this._state = "readable";
        this._storedError = undefined;
        this._reader = null;
        this._pulling = false;
        this._controller = new ReadableStreamDefaultController(this);
        let closeResolve, closeReject;
        this._closedPromise = new Promise((resolve, reject) => {
          closeResolve = resolve;
          closeReject = reject;
        });
        this._closeResolve = closeResolve;
        this._closeReject = closeReject;
        try {
          const started = typeof this._source.start === "function"
            ? this._source.start(this._controller)
            : undefined;
          Promise.resolve(started).catch(error => this._error(error));
        } catch (error) {
          this._error(error);
        }
      }
      get locked() { return this._reader !== null; }
      getReader() { return new ReadableStreamDefaultReader(this); }
      cancel(reason) {
        if (this.locked) return Promise.reject(new TypeError("ReadableStream is locked"));
        return this._cancel(reason);
      }
      _cancel(reason) {
        this._queue.length = 0;
        this._close();
        try {
          return Promise.resolve(typeof this._source.cancel === "function" ? this._source.cancel(reason) : undefined);
        } catch (error) {
          return Promise.reject(error);
        }
      }
      _read() {
        if (this._queue.length) return Promise.resolve({ value: this._queue.shift(), done: false });
        if (this._state === "closed") return Promise.resolve({ value: undefined, done: true });
        if (this._state === "errored") return Promise.reject(this._storedError);
        const pending = new Promise((resolve, reject) => this._reads.push({ resolve, reject }));
        this._pull();
        return pending;
      }
      _pull() {
        if (this._pulling || this._state !== "readable" || typeof this._source.pull !== "function") return;
        this._pulling = true;
        let pulled;
        try { pulled = this._source.pull(this._controller); }
        catch (error) { this._pulling = false; this._error(error); return; }
        Promise.resolve(pulled).then(() => {
          this._pulling = false;
          if (this._reads.length && this._queue.length === 0) this._pull();
        }, error => {
          this._pulling = false;
          this._error(error);
        });
      }
      _enqueue(chunk) {
        if (this._state !== "readable") throw new TypeError("ReadableStream is not readable");
        if (this._reads.length) this._reads.shift().resolve({ value: chunk, done: false });
        else this._queue.push(chunk);
      }
      _close() {
        if (this._state !== "readable") return;
        this._state = "closed";
        while (this._reads.length) this._reads.shift().resolve({ value: undefined, done: true });
        this._closeResolve();
      }
      _error(error) {
        if (this._state !== "readable") return;
        this._state = "errored";
        this._storedError = error;
        while (this._reads.length) this._reads.shift().reject(error);
        this._closeReject(error);
      }
      tee() {
        const reader = this.getReader();
        let leftController, rightController, pulling = false, finished = false;
        const pump = () => {
          if (pulling || finished || !leftController || !rightController) return;
          pulling = true;
          reader.read().then(({ value, done }) => {
            pulling = false;
            if (done) {
              finished = true;
              leftController.close();
              rightController.close();
            } else {
              leftController.enqueue(value instanceof Uint8Array ? value.slice() : value);
              rightController.enqueue(value instanceof Uint8Array ? value.slice() : value);
            }
          }, error => {
            pulling = false;
            finished = true;
            leftController.error(error);
            rightController.error(error);
          });
        };
        const left = new ReadableStream({ start(c) { leftController = c; }, pull: pump });
        const right = new ReadableStream({ start(c) { rightController = c; }, pull: pump });
        return [left, right];
      }
      [Symbol.asyncIterator]() {
        const reader = this.getReader();
        return {
          next: () => reader.read(),
          return: () => reader.cancel().then(() => ({ done: true })),
          [Symbol.asyncIterator]() { return this; }
        };
      }
    }
    define(globalThis, "ReadableStream", ReadableStream);
    define(globalThis, "ReadableStreamDefaultReader", ReadableStreamDefaultReader);
  }

  if (typeof globalThis.Blob !== "function") {
    class Blob {
      constructor(parts = [], options = {}) {
        const chunks = [];
        for (const part of parts) {
          if (part instanceof Blob) chunks.push(new Uint8Array(part.arrayBufferSync()));
          else chunks.push(new Uint8Array(toArrayBuffer(part) || new ArrayBuffer(0)));
        }
        this._bytes = concatUint8Arrays(chunks);
        this.size = this._bytes.byteLength;
        this.type = String(options.type || "").toLowerCase();
      }
      arrayBufferSync() {
        return this._bytes.buffer.slice(this._bytes.byteOffset, this._bytes.byteOffset + this._bytes.byteLength);
      }
      arrayBuffer() {
        return Promise.resolve(this.arrayBufferSync());
      }
      text() {
        return Promise.resolve(decodeBytes(this._bytes));
      }
      stream() {
        const bytes = this._bytes.slice();
        return new ReadableStream({
          start(controller) {
            if (bytes.byteLength) controller.enqueue(bytes);
            controller.close();
          }
        });
      }
      slice(start = 0, end = this.size, type = "") {
        const size = this.size;
        let relativeStart = start < 0 ? Math.max(size + start, 0) : Math.min(start, size);
        let relativeEnd = end < 0 ? Math.max(size + end, 0) : Math.min(end, size);
        const span = Math.max(relativeEnd - relativeStart, 0);
        return new Blob([this._bytes.slice(relativeStart, relativeStart + span)], { type });
      }
    }
    define(globalThis, "Blob", Blob);
  }

  if (typeof globalThis.File !== "function") {
    class File extends Blob {
      constructor(parts, name, options = {}) {
        super(parts, options);
        this.name = String(name);
        this.lastModified = options.lastModified === undefined ? Date.now() : Number(options.lastModified);
      }
    }
    define(globalThis, "File", File);
  }

  function bytesForEncoding(value, encoding = "utf8") {
    encoding = String(encoding || "utf8").toLowerCase().replace("utf-8", "utf8");
    if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
    const text = String(value);
    if (encoding === "hex") {
      if (text.length % 2) throw new TypeError("Invalid hex string");
      const out = new Uint8Array(text.length / 2);
      for (let i = 0; i < out.length; i++) {
        const byte = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
        if (!Number.isFinite(byte)) throw new TypeError("Invalid hex string");
        out[i] = byte;
      }
      return out;
    }
    if (encoding === "base64" || encoding === "base64url") {
      let source = text;
      if (encoding === "base64url") source = source.replace(/-/g, "+").replace(/_/g, "/");
      while (source.length % 4) source += "=";
      const binary = atob(source);
      const out = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
      return out;
    }
    if (encoding === "latin1" || encoding === "binary" || encoding === "ascii") {
      const out = new Uint8Array(text.length);
      for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & (encoding === "ascii" ? 0x7f : 0xff);
      return out;
    }
    return new Uint8Array(encodeString(text));
  }

  function encodedString(bytes, encoding = "utf8") {
    encoding = String(encoding || "utf8").toLowerCase().replace("utf-8", "utf8");
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (encoding === "hex") return Array.from(view, byte => byte.toString(16).padStart(2, "0")).join("");
    if (encoding === "base64" || encoding === "base64url") {
      let binary = "";
      for (const byte of view) binary += String.fromCharCode(byte);
      const encoded = btoa(binary);
      return encoding === "base64url" ? encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") : encoded;
    }
    if (encoding === "latin1" || encoding === "binary" || encoding === "ascii") {
      return Array.from(view, byte => String.fromCharCode(encoding === "ascii" ? byte & 0x7f : byte)).join("");
    }
    return decodeBytes(view);
  }

  function asBinary(value) {
    if (typeof Buffer === "function") return Buffer.from(value || new ArrayBuffer(0));
    return new Uint8Array(value || new ArrayBuffer(0));
  }

  if (feature("nodeCompat") && typeof globalThis.Buffer !== "function") {
    class Buffer extends Uint8Array {
      static from(value, encodingOrOffset, length) {
        let bytes;
        if (typeof value === "string") bytes = bytesForEncoding(value, encodingOrOffset);
        else if (value instanceof ArrayBuffer) {
          const offset = Number(encodingOrOffset || 0);
          const size = length === undefined ? value.byteLength - offset : Number(length);
          bytes = new Uint8Array(value, offset, size).slice();
        } else if (ArrayBuffer.isView(value) || Array.isArray(value)) bytes = Uint8Array.from(value);
        else if (value && typeof value[Symbol.iterator] === "function") bytes = Uint8Array.from(value);
        else throw new TypeError("Unsupported Buffer input");
        Object.setPrototypeOf(bytes, Buffer.prototype);
        return bytes;
      }
      static alloc(size, fill = 0, encoding) {
        const out = new Uint8Array(Number(size));
        Object.setPrototypeOf(out, Buffer.prototype);
        if (typeof fill === "string") {
          const pattern = Buffer.from(fill, encoding);
          for (let i = 0; i < out.length; i++) out[i] = pattern[i % pattern.length];
        } else out.fill(Number(fill) || 0);
        return out;
      }
      static allocUnsafe(size) { return Buffer.alloc(size); }
      static isBuffer(value) { return value instanceof Buffer; }
      static byteLength(value, encoding) { return Buffer.from(value, encoding).byteLength; }
      static concat(list, totalLength) {
        if (!Array.isArray(list)) throw new TypeError("list must be an Array");
        const length = totalLength === undefined
          ? list.reduce((sum, item) => sum + item.byteLength, 0)
          : Number(totalLength);
        const out = Buffer.alloc(length);
        let offset = 0;
        for (const item of list) {
          const bytes = Buffer.from(item);
          out.set(bytes.subarray(0, Math.max(0, length - offset)), offset);
          offset += bytes.byteLength;
          if (offset >= length) break;
        }
        return out;
      }
      toString(encoding = "utf8", start = 0, end = this.length) {
        return encodedString(Uint8Array.prototype.subarray.call(this, start, end), encoding);
      }
      slice(start, end) {
        const out = Uint8Array.prototype.subarray.call(this, start, end);
        Object.setPrototypeOf(out, Buffer.prototype);
        return out;
      }
      subarray(start, end) {
        const out = Uint8Array.prototype.subarray.call(this, start, end);
        Object.setPrototypeOf(out, Buffer.prototype);
        return out;
      }
      write(value, offset = 0, length, encoding = "utf8") {
        const bytes = Buffer.from(value, encoding);
        const count = Math.min(length === undefined ? bytes.length : Number(length), this.length - Number(offset));
        this.set(bytes.subarray(0, count), Number(offset));
        return count;
      }
      equals(other) {
        const bytes = Buffer.from(other);
        return this.length === bytes.length && this.every((value, index) => value === bytes[index]);
      }
      get [Symbol.toStringTag]() { return "Uint8Array"; }
    }
    define(globalThis, "Buffer", Buffer);
  }

  class HostStats {
    constructor(info = {}) {
      Object.assign(this, info);
      this.atime = new Date(info.atimeMs || 0);
      this.mtime = new Date(info.mtimeMs || 0);
      this.ctime = new Date(info.ctimeMs || 0);
      this.birthtime = new Date(info.birthtimeMs || 0);
    }
    isFile() { return !!this.__isFile; }
    isDirectory() { return !!this.__isDirectory; }
    isSymbolicLink() { return !!this.__isSymbolicLink; }
    isBlockDevice() { return !!this.__isBlockDevice; }
    isCharacterDevice() { return !!this.__isCharacterDevice; }
    isFIFO() { return !!this.__isFIFO; }
    isSocket() { return !!this.__isSocket; }
  }

  function makeStats(info) {
    return new HostStats({
      name: info.name,
      size: info.size,
      mode: info.mode,
      atimeMs: info.atimeMs,
      mtimeMs: info.mtimeMs,
      ctimeMs: info.ctimeMs,
      birthtimeMs: info.birthtimeMs,
      __isFile: info.isFile,
      __isDirectory: info.isDirectory,
      __isSymbolicLink: info.isSymbolicLink,
      __isBlockDevice: info.isBlockDevice,
      __isCharacterDevice: info.isCharacterDevice,
      __isFIFO: info.isFIFO,
      __isSocket: info.isSocket
    });
  }

  class HostDirent {
    constructor(info) { Object.assign(this, info); }
    isFile() { return !!this.__isFile; }
    isDirectory() { return !!this.__isDirectory; }
    isSymbolicLink() { return !!this.__isSymbolicLink; }
    isBlockDevice() { return false; }
    isCharacterDevice() { return false; }
    isFIFO() { return false; }
    isSocket() { return false; }
  }

  function makeDirent(info) {
    return new HostDirent({
      name: info.name,
      __isFile: info.isFile,
      __isDirectory: info.isDirectory,
      __isSymbolicLink: info.isSymbolicLink
    });
  }

  if (typeof globalThis.FormData !== "function") {
    class FormData {
      constructor() {
        this._entries = [];
      }
      append(name, value, filename) {
        let stored = value instanceof Blob ? value : String(value);
        if (filename !== undefined && stored instanceof Blob && !(stored instanceof File)) stored = new File([stored], filename, { type: stored.type });
        this._entries.push([String(name), stored]);
      }
      set(name, value, filename) {
        name = String(name);
        this.delete(name);
        this.append(name, value, filename);
      }
      get(name) {
        name = String(name);
        const entry = this._entries.find(([key]) => key === name);
        return entry ? entry[1] : null;
      }
      getAll(name) {
        name = String(name);
        return this._entries.filter(([key]) => key === name).map(([, value]) => value);
      }
      has(name) {
        name = String(name);
        return this._entries.some(([key]) => key === name);
      }
      delete(name) {
        name = String(name);
        this._entries = this._entries.filter(([key]) => key !== name);
      }
      entries() {
        return this._entries[Symbol.iterator]();
      }
      keys() {
        return this._entries.map(([key]) => key)[Symbol.iterator]();
      }
      values() {
        return this._entries.map(([, value]) => value)[Symbol.iterator]();
      }
      forEach(callback, thisArg) {
        for (const [key, value] of this._entries) callback.call(thisArg, value, key, this);
      }
      [Symbol.iterator]() {
        return this.entries();
      }
    }
    define(globalThis, "FormData", FormData);
  }

  if (typeof globalThis.URLSearchParams !== "function") {
    class URLSearchParams {
      constructor(init = "") {
        this._entries = [];
        if (typeof init === "string") {
          const query = init.startsWith("?") ? init.slice(1) : init;
          if (query) {
            for (const pair of query.split("&")) {
              if (pair === "") continue;
              const index = pair.indexOf("=");
              const key = index < 0 ? pair : pair.slice(0, index);
              const value = index < 0 ? "" : pair.slice(index + 1);
              this.append(decodeURIComponent(key.replace(/\+/g, " ")), decodeURIComponent(value.replace(/\+/g, " ")));
            }
          }
        } else if (Array.isArray(init)) {
          for (const pair of init) this.append(pair[0], pair[1]);
        } else if (init && typeof init === "object") {
          if (typeof init[Symbol.iterator] === "function") {
            for (const pair of init) this.append(pair[0], pair[1]);
          } else {
            for (const key of Object.keys(init)) this.append(key, init[key]);
          }
        }
      }
      append(name, value) {
        this._entries.push([String(name), String(value)]);
      }
      set(name, value) {
        name = String(name);
        this.delete(name);
        this.append(name, value);
      }
      get(name) {
        name = String(name);
        const entry = this._entries.find(([key]) => key === name);
        return entry ? entry[1] : null;
      }
      getAll(name) {
        name = String(name);
        return this._entries.filter(([key]) => key === name).map(([, value]) => value);
      }
      has(name) {
        name = String(name);
        return this._entries.some(([key]) => key === name);
      }
      delete(name) {
        name = String(name);
        this._entries = this._entries.filter(([key]) => key !== name);
      }
      sort() {
        this._entries.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
      }
      entries() {
        return this._entries[Symbol.iterator]();
      }
      keys() {
        return this._entries.map(([key]) => key)[Symbol.iterator]();
      }
      values() {
        return this._entries.map(([, value]) => value)[Symbol.iterator]();
      }
      forEach(callback, thisArg) {
        for (const [key, value] of this._entries) callback.call(thisArg, value, key, this);
      }
      toString() {
        return this._entries.map(([key, value]) => encodeURIComponent(key).replace(/%20/g, "+") + "=" + encodeURIComponent(value).replace(/%20/g, "+")).join("&");
      }
      [Symbol.iterator]() {
        return this.entries();
      }
    }
    define(globalThis, "URLSearchParams", URLSearchParams);
  }

  function inspect(value, seen) {
    if (typeof value === "string") return value;
    if (typeof value === "undefined") return "undefined";
    if (value === null) return "null";
    if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") return String(value);
    if (typeof value === "function") return "[Function" + (value.name ? ": " + value.name : "") + "]";
    if (value instanceof Error) return value.stack || value.message || String(value);
    seen = seen || new Set();
    if (seen.has(value)) return "[Circular]";
    seen.add(value);
    try {
      const json = JSON.stringify(value);
      if (json !== undefined) return json;
    } catch (_) {}
    try {
      return String(value);
    } catch (_) {
      return Object.prototype.toString.call(value);
    }
  }

  const countMap = new Map();
  const timeMap = new Map();
  const consoleObj = {
    log: (...args) => __qjs_console_print("log", args.map(arg => inspect(arg)).join(" ")),
    info: (...args) => __qjs_console_print("info", args.map(arg => inspect(arg)).join(" ")),
    debug: (...args) => __qjs_console_print("debug", args.map(arg => inspect(arg)).join(" ")),
    warn: (...args) => __qjs_console_print("warn", args.map(arg => inspect(arg)).join(" ")),
    error: (...args) => __qjs_console_print("error", args.map(arg => inspect(arg)).join(" ")),
    trace: (...args) => {
      const err = new Error(args.map(arg => inspect(arg)).join(" "));
      __qjs_console_print("trace", err.stack || err.message);
    },
    assert: (condition, ...args) => {
      if (!condition) consoleObj.error("Assertion failed", ...args);
    },
    count: (label = "default") => {
      label = String(label);
      const count = (countMap.get(label) || 0) + 1;
      countMap.set(label, count);
      consoleObj.log(label + ": " + count);
    },
    countReset: (label = "default") => {
      countMap.delete(String(label));
    },
    time: (label = "default") => {
      timeMap.set(String(label), __qjs_now_unix_ms());
    },
    timeLog: (label = "default", ...args) => {
      label = String(label);
      if (!timeMap.has(label)) return consoleObj.warn("No such label", label);
      consoleObj.log(label + ": " + (__qjs_now_unix_ms() - timeMap.get(label)) + "ms", ...args);
    },
    timeEnd: (label = "default") => {
      label = String(label);
      if (!timeMap.has(label)) return consoleObj.warn("No such label", label);
      consoleObj.log(label + ": " + (__qjs_now_unix_ms() - timeMap.get(label)) + "ms");
      timeMap.delete(label);
    },
    dir: value => consoleObj.log(value),
    table: value => consoleObj.log(value),
    clear: () => {}
  };
  define(globalThis, "console", consoleObj);

  let nextTimerID = 1;
  const activeTimers = new Map();

  if (typeof nativeSetTimeout !== "function") {
    define(globalThis, "setTimeout", function setTimeout(callback, delay = 0, ...args) {
      if (typeof callback !== "function") callback = Function(String(callback));
      const id = nextTimerID++;
      const token = { active: true };
      activeTimers.set(id, token);
      __qjs_sleep(Number(delay) || 0);
      if (!token.active) return;
      activeTimers.delete(id);
      callback(...args);
      return id;
    });

    define(globalThis, "clearTimeout", function clearTimeout(id) {
      const token = activeTimers.get(Number(id) || 0);
      if (token) token.active = false;
      activeTimers.delete(Number(id) || 0);
    });

    define(globalThis, "setInterval", function setInterval(callback, delay = 0, ...args) {
      if (typeof callback !== "function") callback = Function(String(callback));
      const id = nextTimerID++;
      const token = { active: true };
      activeTimers.set(id, token);
      while (token.active) {
        __qjs_sleep(Number(delay) || 0);
        if (token.active) callback(...args);
      }
      return id;
    });

    define(globalThis, "clearInterval", function clearInterval(id) {
      return clearTimeout(id);
    });
  } else {
    if (typeof nativeClearTimeout === "function") define(globalThis, "clearTimeout", nativeClearTimeout);
    if (typeof nativeSetInterval === "function") define(globalThis, "setInterval", nativeSetInterval);
    if (typeof nativeClearInterval === "function") define(globalThis, "clearInterval", nativeClearInterval);
  }

  if (feature("crypto")) {
    const cryptoObj = globalThis.crypto && typeof globalThis.crypto === "object" ? globalThis.crypto : {};
    cryptoObj.getRandomValues = function getRandomValues(target) {
      if (!ArrayBuffer.isView(target)) throw new TypeError("Expected an integer TypedArray");
      if (target.byteLength > 65536) throw new Error("QuotaExceededError");
      const random = new Uint8Array(__qjs_crypto_random(target.byteLength));
      new Uint8Array(target.buffer, target.byteOffset, target.byteLength).set(random);
      return target;
    };
    cryptoObj.randomUUID = function randomUUID() {
      return __qjs_crypto_uuid();
    };
    cryptoObj.subtle = cryptoObj.subtle || {};
    cryptoObj.subtle.digest = function digest(algorithm, data) {
      const name = typeof algorithm === "string" ? algorithm : algorithm && algorithm.name;
      return hostAsync(() => __qjs_crypto_digest_async_start(name, toArrayBuffer(data)));
    };
    define(globalThis, "crypto", cryptoObj);
  }

  class Headers {
    constructor(init) {
      this._values = Object.create(null);
      if (!init) return;
      if (init instanceof Headers) {
        init.forEach((value, key) => this.append(key, value));
      } else if (Array.isArray(init)) {
        for (const pair of init) this.append(pair[0], pair[1]);
      } else {
        for (const key of Object.keys(init)) {
          const value = init[key];
          if (Array.isArray(value)) for (const item of value) this.append(key, item);
          else this.set(key, value);
        }
      }
    }
    _key(name) {
      const key = String(name).toLowerCase();
      if (!key || /[^a-z0-9\-#$%&'*+.^_|~!]/i.test(key)) throw new TypeError("Invalid HTTP header name");
      return key;
    }
    _value(value) {
      const text = String(value);
      if (/\r|\n/.test(text)) throw new TypeError("Invalid HTTP header value");
      return text.trim();
    }
    append(name, value) {
      const key = this._key(name);
      if (!this._values[key]) this._values[key] = [];
      this._values[key].push(this._value(value));
    }
    set(name, value) { this._values[this._key(name)] = [this._value(value)]; }
    get(name) {
      const value = this._values[this._key(name)];
      return value ? value.join(", ") : null;
    }
    has(name) { return !!this._values[this._key(name)]; }
    delete(name) { delete this._values[this._key(name)]; }
    forEach(callback, thisArg) {
      for (const [key, values] of Object.entries(this._values)) callback.call(thisArg, values.join(", "), key, this);
    }
    entries() {
      return Object.entries(this._values).map(([key, values]) => [key, values.join(", ")])[Symbol.iterator]();
    }
    keys() { return Object.keys(this._values)[Symbol.iterator](); }
    values() { return Object.values(this._values).map(values => values.join(", "))[Symbol.iterator](); }
    toObject() {
      const out = {};
      for (const [key, values] of Object.entries(this._values)) out[key] = values.slice();
      return out;
    }
    [Symbol.iterator]() { return this.entries(); }
  }
  define(globalThis, "Headers", Headers);

  function headersToObject(headers) {
    return new Headers(headers).toObject();
  }

  function streamFromBytes(bytes) {
    const value = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || new ArrayBuffer(0));
    return new ReadableStream({
      start(controller) {
        if (value.byteLength) controller.enqueue(value);
        controller.close();
      }
    });
  }

  function requestBodyBytes(body, headers) {
    if (body == null) return null;
    if (body instanceof ReadableStream) {
      const error = new TypeError("Streaming request bodies are not supported");
      error.code = "ERR_NOT_SUPPORTED";
      throw error;
    }
    if (body instanceof FormData) {
      const boundary = "----qjs-" + (globalThis.crypto && crypto.randomUUID ? crypto.randomUUID() : String(Date.now()));
      const chunks = [];
      for (const [name, value] of body.entries()) {
        let header = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + String(name).replace(/\"/g, "%22") + "\"";
        let bytes;
        if (value instanceof Blob) {
          const filename = value instanceof File ? value.name : "blob";
          header += "; filename=\"" + String(filename).replace(/\"/g, "%22") + "\"\r\nContent-Type: " + (value.type || "application/octet-stream");
          bytes = new Uint8Array(value.arrayBufferSync());
        } else bytes = bytesForEncoding(String(value));
        chunks.push(bytesForEncoding(header + "\r\n\r\n"), bytes, bytesForEncoding("\r\n"));
      }
      chunks.push(bytesForEncoding("--" + boundary + "--\r\n"));
      if (!headers.has("content-type")) headers.set("content-type", "multipart/form-data; boundary=" + boundary);
      return concatUint8Arrays(chunks).buffer;
    }
    if (body instanceof URLSearchParams) {
      if (!headers.has("content-type")) headers.set("content-type", "application/x-www-form-urlencoded;charset=UTF-8");
      return bytesForEncoding(body.toString()).buffer;
    }
    if (body instanceof Blob) {
      if (body.type && !headers.has("content-type")) headers.set("content-type", body.type);
      return body.arrayBufferSync();
    }
    if (typeof body === "string") {
      if (!headers.has("content-type")) headers.set("content-type", "text/plain;charset=UTF-8");
      return bytesForEncoding(body).buffer;
    }
    const converted = toArrayBuffer(body);
    return converted || bytesForEncoding(String(body)).buffer;
  }

  function installBody(target, stream) {
    target.body = stream;
    target.bodyUsed = false;
  }

  async function consumeBody(target) {
    if (target.bodyUsed) throw new TypeError("Body is unusable: Body has already been read");
    target.bodyUsed = true;
    if (target.body == null) return new ArrayBuffer(0);
    const reader = target.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
      total += chunk.byteLength;
      if (runtimeConfig.maxBufferedBodyBytes > 0 && total > runtimeConfig.maxBufferedBodyBytes) {
        await reader.cancel("buffer limit exceeded");
        const error = new RangeError("Response body exceeds the configured buffer limit");
        error.code = "ERR_BODY_TOO_LARGE";
        throw error;
      }
      chunks.push(chunk);
    }
    const result = concatUint8Arrays(chunks);
    return result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength);
  }

  const BodyMethods = {
    arrayBuffer() { return consumeBody(this); },
    text() { return consumeBody(this).then(decodeBytes); },
    json() { return this.text().then(JSON.parse); },
    blob() { return consumeBody(this).then(bytes => new Blob([bytes], { type: this.headers.get("content-type") || "" })); },
    formData() {
      const type = this.headers.get("content-type") || "";
      if (!type.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
        const error = new TypeError("Only URL-encoded form bodies are supported");
        error.code = "ERR_NOT_SUPPORTED";
        return Promise.reject(error);
      }
      return this.text().then(text => new FormData(new URLSearchParams(text)));
    }
  };

  class Request {
    constructor(input, init = {}) {
      const source = input instanceof Request ? input : null;
      if (source && source.bodyUsed) throw new TypeError("Cannot construct a Request from a used body");
      this.url = String(source ? source.url : input && input.url ? input.url : input);
      if (!this.url || this.url === "undefined") throw new TypeError("Request requires a URL");
      this.method = String(init.method || (source && source.method) || "GET").toUpperCase();
      this.headers = new Headers(init.headers || (source && source.headers) || {});
      this.signal = init.signal || (source && source.signal) || null;
      this.redirect = init.redirect || (source && source.redirect) || "follow";
      this.credentials = init.credentials || (source && source.credentials) || "same-origin";
      const hasInitBody = Object.prototype.hasOwnProperty.call(init, "body");
      const body = hasInitBody ? init.body : source && source._bodyBytes ? source._bodyBytes.slice(0) : null;
      if ((this.method === "GET" || this.method === "HEAD") && body != null) throw new TypeError("Body not allowed for GET or HEAD requests");
      this._bodyBytes = requestBodyBytes(body, this.headers);
      installBody(this, this._bodyBytes == null ? null : streamFromBytes(new Uint8Array(this._bodyBytes)));
    }
    clone() {
      if (this.bodyUsed) throw new TypeError("Cannot clone a used Request");
      return new Request(this);
    }
  }
  Object.assign(Request.prototype, BodyMethods);
  define(globalThis, "Request", Request);

  class Response {
    constructor(body = null, init = {}) {
      this.url = init.url || "";
      this.status = init.status === undefined ? 200 : Number(init.status);
      if (this.status < 200 || this.status > 599) throw new RangeError("Response status must be between 200 and 599");
      this.statusText = init.statusText === undefined ? "" : String(init.statusText);
      this.ok = this.status >= 200 && this.status <= 299;
      this.redirected = !!init.redirected;
      this.type = "default";
      this.headers = new Headers(init.headers || {});
      if (body instanceof ReadableStream) installBody(this, body);
      else {
        const bytes = requestBodyBytes(body, this.headers);
        installBody(this, bytes == null ? null : streamFromBytes(new Uint8Array(bytes)));
      }
    }
    clone() {
      if (this.bodyUsed) throw new TypeError("Cannot clone a used Response");
      let cloneBody = null;
      if (this.body) {
        const branches = this.body.tee();
        this.body = branches[0];
        cloneBody = branches[1];
      }
      return new Response(cloneBody, {
        status: this.status,
        statusText: this.statusText,
        headers: this.headers.toObject(),
        url: this.url,
        redirected: this.redirected
      });
    }
    static error() {
      const response = Object.create(Response.prototype);
      response.url = "";
      response.status = 0;
      response.statusText = "";
      response.ok = false;
      response.redirected = false;
      response.type = "error";
      response.headers = new Headers();
      installBody(response, null);
      return response;
    }
    static json(value, init = {}) {
      const headers = new Headers(init.headers || {});
      if (!headers.has("content-type")) headers.set("content-type", "application/json");
      return new Response(JSON.stringify(value), { ...init, headers });
    }
    static redirect(url, status = 302) {
      if (![301, 302, 303, 307, 308].includes(Number(status))) throw new RangeError("Invalid redirect status");
      return new Response(null, { status: Number(status), headers: { location: String(url) } });
    }
    static _fromHost(payload, signal) {
      const bodyId = Number(payload.bodyId);
      if (signal && signal.aborted) {
        __qjs_fetch_body_close(bodyId);
        throw signal.reason || new DOMException("This operation was aborted", "AbortError");
      }
      let finished = false;
      let onAbort;
      let streamController;
      const close = () => {
        if (finished) return;
        finished = true;
        __qjs_fetch_body_close(bodyId);
        if (signal && onAbort) signal.removeEventListener("abort", onAbort);
      };
      const stream = new ReadableStream({
        start(controller) { streamController = controller; },
        pull(controller) {
          return hostAsync(() => __qjs_fetch_body_read_start(bodyId, 64 * 1024), { signal }).then(chunk => {
            if (chunk.done) {
              finished = true;
              if (signal && onAbort) signal.removeEventListener("abort", onAbort);
              controller.close();
            } else {
              controller.enqueue(new Uint8Array(chunk.data));
              if (chunk.final) {
                finished = true;
                if (signal && onAbort) signal.removeEventListener("abort", onAbort);
                controller.close();
              }
            }
          }, error => {
            close();
            controller.error(error);
          });
        },
        cancel() { close(); }
      });
      if (signal) {
        onAbort = () => {
          const reason = signal.reason || new DOMException("This operation was aborted", "AbortError");
          close();
          if (streamController) streamController.error(reason);
        };
        signal.addEventListener("abort", onAbort, { once: true });
      }
      return new Response(stream, payload);
    }
  }
  Object.assign(Response.prototype, BodyMethods);
  define(globalThis, "Response", Response);

  if (feature("fetch")) {
    define(globalThis, "fetch", function fetch(input, init = {}) {
      let request;
      try {
        request = input instanceof Request && Object.keys(init || {}).length === 0 ? input : new Request(input, init);
      } catch (error) {
        return Promise.reject(error);
      }
      if (request.signal && request.signal.aborted) return Promise.reject(request.signal.reason || new DOMException("This operation was aborted", "AbortError"));
      return hostAsync(() => __qjs_fetch_start(
        request.url,
        request.method,
        JSON.stringify(headersToObject(request.headers)),
        request._bodyBytes,
        request.redirect
      ), {
        signal: request.signal,
        transform: payload => Response._fromHost(payload, request.signal)
      }).catch(error => {
        if (error && error.name === "AbortError") throw error;
        const networkError = new TypeError(error && error.message ? error.message : "fetch failed");
        networkError.cause = error;
        throw networkError;
      });
    });
  }

  if (feature("fs")) {
    function normalizedFSOptions(options, defaults = {}) {
      const value = typeof options === "string" ? { encoding: options } : { ...(options || {}) };
      return { ...defaults, ...value };
    }
    function unwrapFS(payload) {
      if (payload && payload.error) throw createHostError(payload.error);
      return payload ? payload.result : undefined;
    }
    function fsSync(op, path, options = {}, data) {
      return unwrapFS(__qjs_fs_sync(String(op), String(path), JSON.stringify(options || {}), data === undefined ? null : data));
    }
    function fsAsync(op, path, options = {}, data) {
      return hostAsync(() => __qjs_fs_host_async_start(
        String(op),
        String(path),
        JSON.stringify(options || {}),
        data === undefined ? null : data
      ));
    }
    function decodeFSResult(value, options) {
      const encoding = typeof options === "string" ? options : options && options.encoding;
      const binary = asBinary(value);
      return encoding && encoding !== "buffer" ? encodedString(binary, encoding) : binary;
    }
    function nodeCallback(promise, callback) {
      if (typeof callback !== "function") return promise;
      promise.then(value => callback(null, value), error => callback(error));
      return undefined;
    }
    function callbackFromArgs(args) {
      const last = args[args.length - 1];
      return typeof last === "function" ? last : undefined;
    }
    function unsupportedFS(name) {
      const error = new Error(name + " is not supported by this runtime");
      error.code = "ERR_NOT_SUPPORTED";
      throw error;
    }

    const fsPromises = {};
    fsPromises.readFile = (path, options) => fsAsync("readFile", path, normalizedFSOptions(options)).then(value => decodeFSResult(value, options));
    fsPromises.writeFile = (path, data, options) => fsAsync("writeFile", path, normalizedFSOptions(options, { flag: "w", mode: 0o666 }), toArrayBuffer(data));
    fsPromises.appendFile = (path, data, options) => fsAsync("appendFile", path, normalizedFSOptions(options, { flag: "a", mode: 0o666 }), toArrayBuffer(data));
    fsPromises.mkdir = (path, options) => fsAsync("mkdir", path, normalizedFSOptions(options, { mode: 0o777 }));
    fsPromises.readdir = (path = ".", options) => fsAsync("readdir", path, normalizedFSOptions(options)).then(value =>
      options && typeof options === "object" && options.withFileTypes ? value.map(makeDirent) : value
    );
    fsPromises.stat = path => fsAsync("stat", path).then(makeStats);
    fsPromises.lstat = path => fsAsync("lstat", path).then(makeStats);
    fsPromises.access = (path, mode = 0) => fsAsync("access", path, { mode });
    fsPromises.realpath = path => fsAsync("realpath", path);
    fsPromises.copyFile = (source, dest, mode = 0) => fsAsync("copyFile", source, { dest: String(dest), mode: mode || 0o666 });
    fsPromises.rename = (source, dest) => fsAsync("rename", source, { dest: String(dest) });
    fsPromises.rm = (path, options) => fsAsync("rm", path, normalizedFSOptions(options));
    fsPromises.unlink = path => fsAsync("unlink", path);
    fsPromises.exists = path => fsAsync("exists", path);
    fsPromises.readFileText = path => fsPromises.readFile(path, "utf8");
    fsPromises.remove = fsPromises.rm;
    fsPromises.readDir = fsPromises.readdir;

    const fs = qjs.fs || {};
    fs.readFileSync = (path, options) => decodeFSResult(fsSync("readFile", path), options);
    fs.readFileTextSync = path => fs.readFileSync(path, "utf8");
    fs.writeFileSync = (path, data, options) => fsSync("writeFile", path, normalizedFSOptions(options, { flag: "w", mode: 0o666 }), toArrayBuffer(data));
    fs.appendFileSync = (path, data, options) => fsSync("appendFile", path, normalizedFSOptions(options, { flag: "a", mode: 0o666 }), toArrayBuffer(data));
    fs.mkdirSync = (path, options) => fsSync("mkdir", path, normalizedFSOptions(options, { mode: 0o777 }));
    fs.readdirSync = (path = ".", options) => {
      const value = fsSync("readdir", path, normalizedFSOptions(options));
      return options && typeof options === "object" && options.withFileTypes ? value.map(makeDirent) : value;
    };
    fs.statSync = path => makeStats(fsSync("stat", path));
    fs.lstatSync = path => makeStats(fsSync("lstat", path));
    fs.accessSync = (path, mode = 0) => fsSync("access", path, { mode });
    fs.existsSync = path => { try { return !!fsSync("exists", path); } catch (_) { return false; } };
    fs.realpathSync = path => fsSync("realpath", path);
    fs.copyFileSync = (source, dest, mode = 0) => fsSync("copyFile", source, { dest: String(dest), mode: mode || 0o666 });
    fs.renameSync = (source, dest) => fsSync("rename", source, { dest: String(dest) });
    fs.rmSync = (path, options) => fsSync("rm", path, normalizedFSOptions(options));
    fs.removeSync = fs.rmSync;
    fs.unlinkSync = path => fsSync("unlink", path);
    fs.openSync = (path, flags = "r", mode = 0o666) => fsSync("open", path, { flag: String(flags), mode: Number(mode) });
    fs.closeSync = fd => fsSync("closeFD", "<fd>", { fd: Number(fd) });
    fs.fsyncSync = fd => fsSync("syncFD", "<fd>", { fd: Number(fd) });
    fs.writeSync = function writeSync(fd, value, offset, length, position) {
      let bytes;
      if (typeof value === "string") {
        const stringPosition = typeof offset === "number" ? offset : null;
        const encoding = typeof length === "string" ? length : "utf8";
        bytes = bytesForEncoding(value, encoding);
        position = stringPosition;
      } else {
        const source = asBinary(value);
        const start = Number(offset || 0);
        const count = length === undefined ? source.byteLength - start : Number(length);
        bytes = source.subarray(start, start + count);
      }
      return fsSync("writeFD", "<fd>", {
        fd: Number(fd),
        position: position == null ? -1 : Number(position),
        hasPosition: position != null
      }, toArrayBuffer(bytes));
    };
    fs.utimesSync = (path, atime, mtime) => fsSync("utimes", path, {
      atimeMs: new Date(atime).getTime(),
      mtimeMs: new Date(mtime).getTime()
    });

    fs.readFile = function(path, options, callback) {
      if (typeof options === "function") { callback = options; options = undefined; }
      return nodeCallback(fsPromises.readFile(path, options), callback);
    };
    fs.writeFile = function(path, data, options, callback) {
      if (typeof options === "function") { callback = options; options = undefined; }
      return nodeCallback(fsPromises.writeFile(path, data, options), callback);
    };
    fs.appendFile = function(path, data, options, callback) {
      if (typeof options === "function") { callback = options; options = undefined; }
      return nodeCallback(fsPromises.appendFile(path, data, options), callback);
    };
    for (const name of ["mkdir", "readdir", "stat", "lstat", "access", "realpath", "rm", "unlink"]) {
      fs[name] = (...args) => {
        const callback = callbackFromArgs(args);
        if (callback) args.pop();
        return nodeCallback(fsPromises[name](...args), callback);
      };
    }
    fs.copyFile = (source, dest, mode, callback) => {
      if (typeof mode === "function") { callback = mode; mode = 0; }
      return nodeCallback(fsPromises.copyFile(source, dest, mode), callback);
    };
    fs.rename = (source, dest, callback) => nodeCallback(fsPromises.rename(source, dest), callback);
    fs.exists = (path, callback) => {
      const promise = fsPromises.exists(path);
      if (typeof callback !== "function") return promise;
      promise.then(value => callback(value), () => callback(false));
    };
    fs.readFileText = fsPromises.readFileText;
    fs.remove = fs.rm;
    fs.readDir = fs.readdir;
    fs.makeDir = fs.mkdir;
    fs.watch = () => unsupportedFS("fs.watch");
    fs.watchFile = () => unsupportedFS("fs.watchFile");
    fs.unwatchFile = () => unsupportedFS("fs.unwatchFile");
    fs.constants = Object.freeze({ F_OK: 0, R_OK: 4, W_OK: 2, X_OK: 1, COPYFILE_EXCL: 1 });
    fs.Stats = HostStats;
    fs.Dirent = HostDirent;
    define(fs, "promises", fsPromises, true);
    define(qjs, "fs", fs, true);
  }

  if (feature("net")) {
  class TCPSocket {
    constructor(remoteAddress, remotePort, options = {}, acceptedInfo) {
      this._init(acceptedInfo || __qjs_tcp_connect(String(remoteAddress), Number(remotePort), Number(options.timeout || 0)));
    }
    static fromInfo(info) {
      const socket = Object.create(TCPSocket.prototype);
      socket._init(info);
      return socket;
    }
    _init(info) {
      this._id = info.id;
      this.localAddress = info.localAddress || "";
      this.localPort = info.localPort || 0;
      this.remoteAddress = info.remoteAddress || "";
      this.remotePort = info.remotePort || 0;
      this.opened = Promise.resolve({
        localAddress: this.localAddress,
        localPort: this.localPort,
        remoteAddress: this.remoteAddress,
        remotePort: this.remotePort,
        socket: this
      });
    }
    read(maxBytes = 65536) {
      return Promise.resolve(__qjs_tcp_read(this._id, Number(maxBytes) || 65536));
    }
    readText(maxBytes = 65536) {
      return this.read(maxBytes).then(decodeBytes);
    }
    write(data) {
      return Promise.resolve(__qjs_tcp_write(this._id, toArrayBuffer(data)));
    }
    close() {
      if (this._id) __qjs_tcp_close(this._id);
      this._id = 0;
    }
  }

  class TCPServerSocket {
    constructor(localAddress = "127.0.0.1", options = {}) {
      const info = __qjs_tcp_listen(String(localAddress || "127.0.0.1"), Number(options.localPort || options.port || 0));
      this._id = info.id;
      this.localAddress = info.localAddress || "";
      this.localPort = info.localPort || 0;
      this.opened = Promise.resolve({
        localAddress: this.localAddress,
        localPort: this.localPort,
        socket: this
      });
    }
    accept() {
      return Promise.resolve(TCPSocket.fromInfo(__qjs_tcp_accept(this._id)));
    }
    close() {
      if (this._id) __qjs_tcp_close(this._id);
      this._id = 0;
    }
  }

  class UDPSocket {
    constructor(options = {}) {
      const info = __qjs_udp_bind(String(options.localAddress || "127.0.0.1"), Number(options.localPort || options.port || 0));
      this._id = info.id;
      this.localAddress = info.localAddress || "";
      this.localPort = info.localPort || 0;
      this.opened = Promise.resolve({
        localAddress: this.localAddress,
        localPort: this.localPort,
        socket: this
      });
    }
    send(data, remoteAddress, remotePort) {
      if (data && typeof data === "object" && "data" in data) {
        remoteAddress = data.remoteAddress;
        remotePort = data.remotePort;
        data = data.data;
      }
      return Promise.resolve(__qjs_udp_send(this._id, toArrayBuffer(data), String(remoteAddress), Number(remotePort)));
    }
    receive(maxBytes = 65536) {
      return Promise.resolve(__qjs_udp_receive(this._id, Number(maxBytes) || 65536));
    }
    close() {
      if (this._id) __qjs_udp_close(this._id);
      this._id = 0;
    }
  }

  class PipeSocket extends TCPSocket {
    constructor(path) {
      super("127.0.0.1", 0, {}, __qjs_unix_connect(String(path)));
    }
    static fromInfo(info) {
      const socket = Object.create(PipeSocket.prototype);
      socket._init(info);
      socket.path = info.path || "";
      return socket;
    }
  }

  class PipeServerSocket {
    constructor(path) {
      const info = __qjs_unix_listen(String(path));
      this._id = info.id;
      this.path = info.path || String(path);
      this.opened = Promise.resolve({ path: this.path, socket: this });
    }
    accept() {
      return Promise.resolve(PipeSocket.fromInfo(__qjs_unix_accept(this._id)));
    }
    close() {
      if (this._id) __qjs_tcp_close(this._id);
      this._id = 0;
    }
  }

  const net = qjs.net || {};
  net.TCPSocket = TCPSocket;
  net.TCPServerSocket = TCPServerSocket;
  net.UDPSocket = UDPSocket;
  net.PipeSocket = PipeSocket;
  net.PipeServerSocket = PipeServerSocket;
  net.connect = function connect(transport, host, port, options = {}) {
    transport = String(transport);
    if (transport === "tcp") return Promise.resolve(new TCPSocket(host, port, options));
    if (transport === "udp") return Promise.resolve(new UDPSocket({ ...options, remoteAddress: host, remotePort: port }));
    if (transport === "unix" || transport === "pipe") return Promise.resolve(new PipeSocket(host));
    return Promise.reject(new TypeError("unsupported transport: " + transport));
  };
  net.listen = function listen(transport, host, port, options = {}) {
    transport = String(transport);
    if (transport === "tcp") return Promise.resolve(new TCPServerSocket(host, { ...options, localPort: port }));
    if (transport === "udp") return Promise.resolve(new UDPSocket({ ...options, localAddress: host, localPort: port }));
    if (transport === "unix" || transport === "pipe") return Promise.resolve(new PipeServerSocket(host));
    return Promise.reject(new TypeError("unsupported transport: " + transport));
  };
  define(qjs, "net", net, true);
  define(globalThis, "TCPSocket", TCPSocket);
  define(globalThis, "TCPServerSocket", TCPServerSocket);
  define(globalThis, "UDPSocket", UDPSocket);
  define(globalThis, "PipeSocket", PipeSocket);
  define(globalThis, "PipeServerSocket", PipeServerSocket);
  }

  if (feature("http")) {
  class HostWebSocket extends EventTarget {
    constructor() {
      super();
      this.onopen = null;
      this.onmessage = null;
      this.onerror = null;
      this.onclose = null;
    }
    _init(info) {
      if (!this.__qjsListeners) this.__qjsListeners = new Map();
      this._id = info.id;
      this.url = info.url || "";
      this.path = info.path || "";
      this.readyState = WebSocket.OPEN;
      this.opened = Promise.resolve(this);
      this.dispatchEvent(new Event("open"));
    }
    send(data) {
      if (this.readyState !== WebSocket.OPEN) throw new Error("WebSocket is not open");
      return __qjs_ws_send(this._id, toArrayBuffer(data), data instanceof ArrayBuffer || ArrayBuffer.isView(data));
    }
    read() {
      return Promise.resolve(__qjs_ws_read(this._id)).then(message => {
        const data = message.opcode === 1 ? message.text : message.data;
        this.dispatchEvent(new MessageEvent("message", { data }));
        return message;
      }).catch(error => {
        this.dispatchEvent(new ErrorEvent("error", { error, message: String(error && error.message || error) }));
        throw error;
      });
    }
    readText() {
      return this.read().then(message => message.text);
    }
    close() {
      if (this.readyState === WebSocket.CLOSED) return;
      this.readyState = WebSocket.CLOSED;
      if (this._id) __qjs_ws_close(this._id);
      this._id = 0;
      this.dispatchEvent(new Event("close"));
    }
  }

  class WebSocket extends HostWebSocket {
    constructor(url, protocolsOrOptions) {
      super();
      this.readyState = WebSocket.CONNECTING;
      this._init(__qjs_ws_connect(String(url), JSON.stringify({})));
    }
  }
  WebSocket.CONNECTING = 0;
  WebSocket.OPEN = 1;
  WebSocket.CLOSING = 2;
  WebSocket.CLOSED = 3;

  class ServerWebSocket extends HostWebSocket {
    static fromInfo(info) {
      const ws = Object.create(ServerWebSocket.prototype);
      ws._init(info);
      return ws;
    }
  }

  class HTTPRequest {
    constructor(info) {
      this.id = info.id;
      this.serverId = info.serverId;
      this.method = info.method;
      this.url = info.url;
      this.path = info.path;
      this.headers = new Headers(info.headers || {});
      this.websocket = !!info.websocket;
      this._body = toArrayBuffer(info.body || new ArrayBuffer(0));
    }
    arrayBuffer() {
      return Promise.resolve(this._body.slice(0));
    }
    text() {
      return Promise.resolve(decodeBytes(this._body));
    }
    json() {
      return this.text().then(JSON.parse);
    }
    respond(body = "", options = {}) {
      const status = Number(options.status || 200);
      const headers = headersToObject(options.headers || {});
      __qjs_http_respond(this.id, status, JSON.stringify(headers), toArrayBuffer(body));
    }
    upgrade() {
      return Promise.resolve(ServerWebSocket.fromInfo(__qjs_http_upgrade(this.id)));
    }
  }

  class HTTPServer {
    constructor(options = {}) {
      const hostname = String(options.hostname || options.host || "127.0.0.1");
      const port = Number(options.port || 0);
      const info = __qjs_http_listen(hostname, port);
      this._id = info.id;
      this.hostname = info.localAddress || hostname;
      this.port = info.localPort || 0;
    }
    accept() {
      return Promise.resolve(new HTTPRequest(__qjs_http_accept(this._id)));
    }
    close() {
      if (this._id) __qjs_http_close(this._id);
      this._id = 0;
    }
  }

  const httpRuntime = qjs.http || {};
  httpRuntime.serve = function serve(options = {}) {
    return new HTTPServer(options);
  };
  httpRuntime.HTTPServer = HTTPServer;
  httpRuntime.HTTPRequest = HTTPRequest;
  httpRuntime.ServerWebSocket = ServerWebSocket;
  define(qjs, "http", httpRuntime, true);
  define(qjs, "serve", httpRuntime.serve, true);
  define(globalThis, "WebSocket", WebSocket);
  }

  if (feature("worker")) {
    function serializeWorkerMessage(value) {
      const raw = JSON.stringify(value);
      return raw === undefined ? "null" : raw;
    }

    function parseWorkerMessage(raw) {
      try {
        return JSON.parse(raw);
      } catch (_) {
        return raw;
      }
    }

    class Worker extends EventTarget {
      constructor(source, options = {}) {
        super();
        this._id = __qjs_worker_create(String(source), JSON.stringify(options || {}));
        this.onmessage = null;
        this.onerror = null;
      }
      postMessage(value) {
        return __qjs_worker_post(this._id, serializeWorkerMessage(value));
      }
      pollMessages() {
        const messages = __qjs_worker_poll(this._id);
        for (const raw of messages) {
          this.dispatchEvent(new MessageEvent("message", {
            data: parseWorkerMessage(raw),
            target: this,
            currentTarget: this
          }));
        }

        const err = __qjs_worker_error(this._id);
        if (err) {
          this.dispatchEvent(new ErrorEvent("error", {
            message: err,
            error: new Error(err),
            target: this,
            currentTarget: this
          }));
        }

        return messages.length;
      }
      terminate() {
        if (this._id) __qjs_worker_terminate(this._id);
        this._id = 0;
      }
    }

    define(globalThis, "Worker", Worker);
  }

  if (feature("process")) {
    const processObj = qjs.process || {};
    const processInfo = __qjs_process_info();
    processObj.pid = processInfo.pid;
    processObj.ppid = processInfo.ppid;
    processObj.platform = processInfo.platform;
    processObj.arch = processInfo.arch;
    processObj.execPath = processInfo.execPath || "";
    processObj.argv = Object.freeze((processInfo.argv || []).slice());
    processObj.args = Object.freeze((processInfo.args || []).slice());
    processObj.execArgv = Object.freeze([]);
    processObj.cwd = () => __qjs_process_cwd();
    processObj.chdir = path => __qjs_process_chdir(String(path));
    processObj.exitCode = 0;
    processObj.version = "v24.0.0-qjs";
    processObj.versions = Object.freeze({ node: "24.0.0-qjs", qjs: "1" });
    processObj.browser = false;
    processObj.nextTick = (callback, ...args) => queueMicrotask(() => callback(...args));
    processObj.exit = (code = processObj.exitCode || 0) => __qjs_process_exit(Number(code) || 0);
    processObj.memoryUsage = () => ({ rss: 0, heapTotal: 0, heapUsed: 0, external: 0, arrayBuffers: 0 });
    const makeOutputStream = (fd, writer) => Object.freeze({
      fd,
      isTTY: false,
      columns: undefined,
      rows: undefined,
      write(value, encoding, callback) {
        if (typeof encoding === "function") { callback = encoding; encoding = undefined; }
        try {
          const result = __qjs_stream_write(fd, typeof value === "string" ? bytesForEncoding(value, encoding) : toArrayBuffer(value));
          if (typeof callback === "function") queueMicrotask(() => callback(null));
          return result;
        } catch (error) {
          if (typeof callback === "function") { queueMicrotask(() => callback(error)); return false; }
          throw error;
        }
      }
    });
    processObj.stdout = makeOutputStream(1);
    processObj.stderr = makeOutputStream(2);
    processObj.stdin = Object.freeze({ fd: 0, isTTY: false, readable: false });

    const envTarget = JSON.parse(__qjs_process_env_json());
    processObj.env = new Proxy(envTarget, {
      get(target, prop) {
        if (prop === Symbol.toStringTag) return "process.env";
        if (prop === "toJSON") return () => ({ ...target });
        if (typeof prop === "string") return target[prop];
        return undefined;
      },
      set(target, prop, value) {
        if (typeof prop !== "string") return false;
        target[prop] = String(value);
        return true;
      },
      deleteProperty(target, prop) {
        if (typeof prop === "string") delete target[prop];
        return true;
      },
      ownKeys(target) {
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor(target, prop) {
        if (Object.prototype.hasOwnProperty.call(target, prop)) {
          return { configurable: true, enumerable: true, writable: true, value: target[prop] };
        }
        return undefined;
      }
    });

    if (feature("childProcess")) {
    processObj.kill = (pid, signal = "SIGTERM") => __qjs_process_kill(Number(pid), String(signal));
    function execFileArgs(file, args = [], options = {}) {
      const input = options.input == null ? null : toArrayBuffer(options.input);
      const env = Object.prototype.hasOwnProperty.call(options, "env") ? options.env : processObj.env;
      return [
        String(file),
        JSON.stringify(args.map(String)),
        options.cwd ? String(options.cwd) : "",
        JSON.stringify(env || {}),
        input,
        Number(options.timeout || 0)
      ];
    }
    processObj.execFileSync = function execFileSync(file, args = [], options = {}) {
      return __qjs_exec_file(...execFileArgs(file, args, options));
    };
    processObj.execFile = function execFile(file, args = [], options = {}) {
      return hostAsync(() => __qjs_exec_file_async_start(...execFileArgs(file, args, options)));
    };
    const signalCallbacks = new Map();
    processObj.onSignal = function onSignal(signalName, callback) {
      if (typeof callback !== "function") throw new TypeError("signal callback must be a function");
      const id = __qjs_signal_on(String(signalName));
      signalCallbacks.set(id, callback);
      return () => {
        signalCallbacks.delete(id);
        __qjs_signal_off(id);
      };
    };
    processObj.pollSignals = function pollSignals() {
      const events = __qjs_signal_poll();
      for (const event of events) {
        const callback = signalCallbacks.get(event.id);
        if (callback) callback(event.signal);
      }
      return events.length;
    };
    }
    define(qjs, "process", processObj, true);
    define(globalThis, "process", processObj);
  }

  if (feature("nodeCompat")) {
    if (typeof globalThis.global === "undefined") define(globalThis, "global", globalThis);
    if (typeof globalThis.setImmediate !== "function") define(globalThis, "setImmediate", (callback, ...args) => setTimeout(callback, 0, ...args));
    if (typeof globalThis.clearImmediate !== "function") define(globalThis, "clearImmediate", id => clearTimeout(id));

    const isWindowsPath = runtimeConfig.platform === "win32";
    const pathSeparator = isWindowsPath ? "\\" : "/";
    const pathDelimiter = isWindowsPath ? ";" : ":";
    const pathIsAbsolute = value => {
      value = String(value);
      return isWindowsPath ? /^[A-Za-z]:[\\/]/.test(value) || /^[\\/]/.test(value) : value.startsWith("/");
    };
    function pathNormalize(value) {
      value = String(value);
      if (!value) return ".";
      if (isWindowsPath) value = value.replace(/\//g, "\\");
      const driveMatch = isWindowsPath ? /^[A-Za-z]:/.exec(value) : null;
      const drive = driveMatch ? driveMatch[0] : "";
      const absolute = pathIsAbsolute(value);
      const source = drive ? value.slice(drive.length) : value;
      const parts = source.split(isWindowsPath ? /[\\/]+/ : /\/+/);
      const output = [];
      for (const part of parts) {
        if (!part || part === ".") continue;
        if (part === "..") {
          if (output.length && output[output.length - 1] !== "..") output.pop();
          else if (!absolute) output.push("..");
        } else output.push(part);
      }
      let result = output.join(pathSeparator);
      if (absolute) result = pathSeparator + result;
      if (drive) result = drive + (absolute ? result : pathSeparator + result);
      if (!result) return drive ? drive + pathSeparator : absolute ? pathSeparator : ".";
      return result;
    }
    function pathJoin(...parts) {
      const filtered = parts.map(String).filter(Boolean);
      return pathNormalize(filtered.length ? filtered.join(pathSeparator) : ".");
    }
    function pathResolve(...parts) {
      let result = "";
      for (const part of [qjs.process ? qjs.process.cwd() : ".", ...parts]) {
        const value = String(part);
        if (!value) continue;
        result = pathIsAbsolute(value) ? value : (result ? result + pathSeparator + value : value);
      }
      return pathNormalize(result);
    }
    function pathDirname(value) {
      const normalized = pathNormalize(value);
      const rootLength = isWindowsPath && /^[A-Za-z]:\\/.test(normalized) ? 3 : normalized.startsWith(pathSeparator) ? 1 : 0;
      const index = normalized.lastIndexOf(pathSeparator);
      if (index < rootLength) return rootLength ? normalized.slice(0, rootLength) : ".";
      return normalized.slice(0, index) || pathSeparator;
    }
    function pathBasename(value, suffix = "") {
      const normalized = pathNormalize(value);
      let base = normalized.slice(normalized.lastIndexOf(pathSeparator) + 1);
      suffix = String(suffix || "");
      if (suffix && base.endsWith(suffix)) base = base.slice(0, -suffix.length);
      return base;
    }
    function pathExtname(value) {
      const base = pathBasename(value);
      const index = base.lastIndexOf(".");
      return index <= 0 ? "" : base.slice(index);
    }
    function pathRelative(from, to) {
      const left = pathResolve(from).split(pathSeparator).filter(Boolean);
      const right = pathResolve(to).split(pathSeparator).filter(Boolean);
      let common = 0;
      while (common < left.length && common < right.length &&
        (isWindowsPath ? left[common].toLowerCase() === right[common].toLowerCase() : left[common] === right[common])) common++;
      return [...left.slice(common).map(() => ".."), ...right.slice(common)].join(pathSeparator) || "";
    }
    const nodePath = {
      sep: pathSeparator,
      delimiter: pathDelimiter,
      normalize: pathNormalize,
      isAbsolute: pathIsAbsolute,
      join: pathJoin,
      resolve: pathResolve,
      dirname: pathDirname,
      basename: pathBasename,
      extname: pathExtname,
      relative: pathRelative,
      parse(value) {
        const dir = pathDirname(value), base = pathBasename(value), ext = pathExtname(base);
        return { root: pathIsAbsolute(value) ? pathResolve(value).slice(0, isWindowsPath ? 3 : 1) : "", dir, base, ext, name: ext ? base.slice(0, -ext.length) : base };
      },
      format(value) { return pathJoin(value.dir || value.root || "", value.base || String(value.name || "") + String(value.ext || "")); },
      toNamespacedPath(value) { return String(value); }
    };
    nodePath.posix = nodePath;
    nodePath.win32 = nodePath;

    const nodeOS = {
      EOL: runtimeConfig.platform === "win32" ? "\r\n" : "\n",
      devNull: runtimeConfig.platform === "win32" ? "\\\\.\\nul" : "/dev/null",
      platform: () => runtimeConfig.platform,
      arch: () => runtimeConfig.arch,
      type: () => runtimeConfig.platform === "win32" ? "Windows_NT" : runtimeConfig.platform === "darwin" ? "Darwin" : "Linux",
      release: () => "",
      hostname: () => "localhost",
      homedir: () => (qjs.process && (qjs.process.env.USERPROFILE || qjs.process.env.HOME)) || "",
      tmpdir: () => (qjs.process && (qjs.process.env.TEMP || qjs.process.env.TMP || qjs.process.env.TMPDIR)) || (runtimeConfig.platform === "win32" ? "C:\\Windows\\Temp" : "/tmp"),
      endianness: () => "LE",
      cpus: () => [],
      totalmem: () => 0,
      freemem: () => 0
    };

    class NodeHash {
      constructor(algorithm) { this.algorithm = String(algorithm); this.chunks = []; this.finished = false; }
      update(data, encoding) {
        if (this.finished) throw new Error("Digest already called");
        this.chunks.push(typeof data === "string" ? bytesForEncoding(data, encoding) : asBinary(data));
        return this;
      }
      digest(encoding) {
        if (this.finished) throw new Error("Digest already called");
        this.finished = true;
        const result = asBinary(__qjs_hash_digest(this.algorithm, toArrayBuffer(concatUint8Arrays(this.chunks))));
        return encoding ? encodedString(result, encoding) : result;
      }
      copy() {
        const clone = new NodeHash(this.algorithm);
        clone.chunks = this.chunks.map(chunk => chunk.slice());
        return clone;
      }
    }
    const nodeCrypto = {
      createHash: algorithm => new NodeHash(algorithm),
      randomUUID: () => crypto.randomUUID(),
      randomBytes(size) {
        const bytes = typeof Buffer === "function" ? Buffer.alloc(Number(size)) : new Uint8Array(Number(size));
        crypto.getRandomValues(bytes);
        return bytes;
      },
      webcrypto: globalThis.crypto
    };
    const nodeBuffer = { Buffer: globalThis.Buffer };
    const nodePerfHooks = { performance: globalThis.performance };
    define(qjs, "nodePath", nodePath, true);
    define(qjs, "nodeOS", nodeOS, true);
    define(qjs, "nodeCrypto", nodeCrypto, true);
    define(qjs, "nodeBuffer", nodeBuffer, true);
    define(qjs, "nodePerfHooks", nodePerfHooks, true);

    if (qjs.process) {
      const startNs = BigInt(Math.floor(performance.now() * 1000000));
      const hrtime = previous => {
        const now = BigInt(Math.floor(performance.now() * 1000000));
        const elapsed = previous ? now - (BigInt(previous[0]) * 1000000000n + BigInt(previous[1])) : now - startNs;
        return [Number(elapsed / 1000000000n), Number(elapsed % 1000000000n)];
      };
      hrtime.bigint = () => BigInt(Math.floor(performance.now() * 1000000));
      qjs.process.hrtime = hrtime;
      qjs.process.uptime = () => Number(hrtime.bigint() - startNs) / 1e9;
    }

    const builtins = Object.freeze({
      fs: qjs.fs,
      "node:fs": qjs.fs,
      "fs/promises": qjs.fs && qjs.fs.promises,
      "node:fs/promises": qjs.fs && qjs.fs.promises,
      process: qjs.process,
      "node:process": qjs.process,
      path: nodePath,
      "node:path": nodePath,
      os: nodeOS,
      "node:os": nodeOS,
      crypto: nodeCrypto,
      "node:crypto": nodeCrypto,
      buffer: nodeBuffer,
      "node:buffer": nodeBuffer,
      perf_hooks: nodePerfHooks,
      "node:perf_hooks": nodePerfHooks
    });
    define(globalThis, "require", function require(name) {
      name = String(name);
      if (Object.prototype.hasOwnProperty.call(builtins, name) && builtins[name]) return builtins[name];
      const error = new Error("Cannot find module '" + name + "'");
      error.code = "MODULE_NOT_FOUND";
      throw error;
    });
  }
})();
`

const hostFSModuleScript = `
const fs = globalThis.qjs && globalThis.qjs.fs;
if (!fs) throw new Error("qjs fs runtime is not installed");
const promises = fs.promises;
const readFile = fs.readFile;
const readFileText = fs.readFileText;
const writeFile = fs.writeFile;
const appendFile = fs.appendFile;
const mkdir = fs.mkdir;
const makeDir = fs.makeDir;
const readdir = fs.readdir;
const readDir = fs.readDir;
const stat = fs.stat;
const lstat = fs.lstat;
const access = fs.access;
const realpath = fs.realpath;
const copyFile = fs.copyFile;
const rename = fs.rename;
const unlink = fs.unlink;
const exists = fs.exists;
const remove = fs.remove;
const rm = fs.rm;
const readFileSync = fs.readFileSync;
const readFileTextSync = fs.readFileTextSync;
const writeFileSync = fs.writeFileSync;
const appendFileSync = fs.appendFileSync;
const mkdirSync = fs.mkdirSync;
const readdirSync = fs.readdirSync;
const statSync = fs.statSync;
const lstatSync = fs.lstatSync;
const accessSync = fs.accessSync;
const realpathSync = fs.realpathSync;
const copyFileSync = fs.copyFileSync;
const renameSync = fs.renameSync;
const unlinkSync = fs.unlinkSync;
const openSync = fs.openSync;
const closeSync = fs.closeSync;
const writeSync = fs.writeSync;
const fsyncSync = fs.fsyncSync;
const utimesSync = fs.utimesSync;
const existsSync = fs.existsSync;
const removeSync = fs.removeSync;
const rmSync = fs.rmSync;
const constants = fs.constants;
const Stats = fs.Stats;
const Dirent = fs.Dirent;
export {
  promises,
  readFile,
  readFileText,
  writeFile,
  appendFile,
  mkdir,
  makeDir,
  readdir,
  readDir,
  stat,
  lstat,
  access,
  realpath,
  copyFile,
  rename,
  unlink,
  exists,
  remove,
  rm,
  readFileSync,
  readFileTextSync,
  writeFileSync,
  appendFileSync,
  mkdirSync,
  readdirSync,
  statSync,
  lstatSync,
  accessSync,
  realpathSync,
  copyFileSync,
  renameSync,
  unlinkSync,
  openSync,
  closeSync,
  writeSync,
  fsyncSync,
  utimesSync,
  existsSync,
  removeSync,
  rmSync,
  constants,
  Stats,
  Dirent
};
export default fs;
`

const hostFSPromisesModuleScript = `
const fs = globalThis.qjs && globalThis.qjs.fs;
if (!fs) throw new Error("qjs fs runtime is not installed");
const promises = fs.promises;
const readFile = promises.readFile;
const readFileText = promises.readFileText;
const writeFile = promises.writeFile;
const appendFile = promises.appendFile;
const mkdir = promises.mkdir;
const makeDir = promises.mkdir;
const readdir = promises.readdir;
const readDir = promises.readDir;
const stat = promises.stat;
const lstat = promises.lstat;
const access = promises.access;
const realpath = promises.realpath;
const copyFile = promises.copyFile;
const rename = promises.rename;
const unlink = promises.unlink;
const exists = promises.exists;
const remove = promises.remove;
const rm = promises.rm;
export {
  readFile,
  readFileText,
  writeFile,
  appendFile,
  mkdir,
  makeDir,
  readdir,
  readDir,
  stat,
  lstat,
  access,
  realpath,
  copyFile,
  rename,
  unlink,
  exists,
  remove,
  rm
};
export default promises;
`

const hostProcessModuleScript = `
const process = globalThis.qjs && globalThis.qjs.process;
if (!process) throw new Error("qjs process runtime is not installed");
const pid = process.pid;
const ppid = process.ppid;
const platform = process.platform;
const arch = process.arch;
const execPath = process.execPath;
const argv = process.argv;
const args = process.args;
const env = process.env;
const cwd = process.cwd;
const chdir = process.chdir;
const exit = process.exit;
const nextTick = process.nextTick;
const stdout = process.stdout;
const stderr = process.stderr;
const stdin = process.stdin;
const exitCode = process.exitCode;
const kill = process.kill;
const execFile = process.execFile;
const execFileSync = process.execFileSync;
const onSignal = process.onSignal;
const pollSignals = process.pollSignals;
export {
  pid,
  ppid,
  platform,
  arch,
  execPath,
  argv,
  args,
  env,
  cwd,
  chdir,
  exit,
  nextTick,
  stdout,
  stderr,
  stdin,
  exitCode,
  kill,
  execFile,
  execFileSync,
  onSignal,
  pollSignals
};
export default process;
`

const hostBufferModuleScript = `
const mod = globalThis.qjs && globalThis.qjs.nodeBuffer;
if (!mod) throw new Error("Node buffer compatibility is not installed");
const Buffer = mod.Buffer;
export { Buffer };
export default mod;
`

const hostPathModuleScript = `
const path = globalThis.qjs && globalThis.qjs.nodePath;
if (!path) throw new Error("Node path compatibility is not installed");
const sep = path.sep;
const delimiter = path.delimiter;
const normalize = path.normalize;
const isAbsolute = path.isAbsolute;
const join = path.join;
const resolve = path.resolve;
const dirname = path.dirname;
const basename = path.basename;
const extname = path.extname;
const relative = path.relative;
const parse = path.parse;
const format = path.format;
const toNamespacedPath = path.toNamespacedPath;
const posix = path.posix;
const win32 = path.win32;
export { sep, delimiter, normalize, isAbsolute, join, resolve, dirname, basename, extname, relative, parse, format, toNamespacedPath, posix, win32 };
export default path;
`

const hostOSModuleScript = `
const os = globalThis.qjs && globalThis.qjs.nodeOS;
if (!os) throw new Error("Node os compatibility is not installed");
const EOL = os.EOL;
const devNull = os.devNull;
const platform = os.platform;
const arch = os.arch;
const type = os.type;
const release = os.release;
const hostname = os.hostname;
const homedir = os.homedir;
const tmpdir = os.tmpdir;
const endianness = os.endianness;
const cpus = os.cpus;
const totalmem = os.totalmem;
const freemem = os.freemem;
export { EOL, devNull, platform, arch, type, release, hostname, homedir, tmpdir, endianness, cpus, totalmem, freemem };
export default os;
`

const hostCryptoModuleScript = `
const crypto = globalThis.qjs && globalThis.qjs.nodeCrypto;
if (!crypto) throw new Error("Node crypto compatibility is not installed");
const createHash = crypto.createHash;
const randomUUID = crypto.randomUUID;
const randomBytes = crypto.randomBytes;
const webcrypto = crypto.webcrypto;
export { createHash, randomUUID, randomBytes, webcrypto };
export default crypto;
`

const hostPerfHooksModuleScript = `
const mod = globalThis.qjs && globalThis.qjs.nodePerfHooks;
if (!mod) throw new Error("Node perf_hooks compatibility is not installed");
const performance = mod.performance;
export { performance };
export default mod;
`
