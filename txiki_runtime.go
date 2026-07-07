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
	"net/url"
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

	"github.com/valyala/fasthttp"
)

const maxCryptoRandomValues = 65536

// TxikiRuntimeFeature selects optional host-backed runtime APIs.
// A zero value in TxikiRuntimeOptions.Features keeps the default: all features enabled.
type TxikiRuntimeFeature uint64

const (
	TxikiRuntimeFeatureCrypto TxikiRuntimeFeature = 1 << iota
	TxikiRuntimeFeatureFetch
	TxikiRuntimeFeatureFS
	TxikiRuntimeFeatureProcess
	TxikiRuntimeFeatureNet
	TxikiRuntimeFeatureHTTP
	TxikiRuntimeFeatureWorker
)

const TxikiRuntimeFeatureAll = TxikiRuntimeFeatureCrypto |
	TxikiRuntimeFeatureFetch |
	TxikiRuntimeFeatureFS |
	TxikiRuntimeFeatureProcess |
	TxikiRuntimeFeatureNet |
	TxikiRuntimeFeatureHTTP |
	TxikiRuntimeFeatureWorker

// TxikiRuntimeOptions configures the optional host-backed runtime APIs inspired by txiki.js.
type TxikiRuntimeOptions struct {
	CWD             string
	Args            []string
	Env             map[string]string
	ExecPath        string
	Features        TxikiRuntimeFeature
	DisableFeatures TxikiRuntimeFeature
	Stdout          io.Writer
	Stderr          io.Writer
	FetchClient     *fasthttp.Client
}

type txikiRuntimeConfig struct {
	cwd         string
	args        []string
	env         map[string]string
	execPath    string
	features    TxikiRuntimeFeature
	stdout      io.Writer
	stderr      io.Writer
	fetchClient *fasthttp.Client
}

type txikiRuntimeState struct {
	config  txikiRuntimeConfig
	net     *txikiNetState
	workers *txikiWorkerManager

	cwdMu sync.RWMutex
	cwd   string

	asyncMu       sync.Mutex
	nextAsyncID   int64
	asyncFSJobs   map[int64]*txikiAsyncJob
	asyncProcJobs map[int64]*txikiAsyncJob
	nextSignalID  int64
	signalsMu     sync.Mutex
	signals       map[int64]*txikiSignal
	signalEvents  []txikiSignalEvent
}

type txikiAsyncJob struct {
	done   bool
	result any
	err    error
}

type txikiSignal struct {
	id     int64
	label  string
	cancel context.CancelFunc
	closed atomic.Bool
}

type txikiSignalEvent struct {
	ID     int64  `json:"id"`
	Signal string `json:"signal"`
}

type fetchPayload struct {
	URL        string              `json:"url"`
	Status     int                 `json:"status"`
	StatusText string              `json:"statusText"`
	Headers    map[string][]string `json:"headers"`
	Body       []byte              `json:"body"`
}

type fetchRequest struct {
	url     string
	method  string
	headers map[string][]string
	body    []byte
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

// InstallTxikiRuntime installs optional Web-like and host runtime APIs on the runtime context.
func (r *Runtime) InstallTxikiRuntime(options ...TxikiRuntimeOptions) error {
	if r == nil || r.context == nil {
		return errors.New("runtime is closed")
	}

	return r.context.InstallTxikiRuntime(options...)
}

// InstallTxikiRuntime installs optional Web-like and host runtime APIs on the context.
func (c *Context) InstallTxikiRuntime(options ...TxikiRuntimeOptions) error {
	if c == nil || c.runtime == nil {
		return errors.New("context is closed")
	}

	config, err := c.newTxikiRuntimeConfig(options...)
	if err != nil {
		return err
	}

	state := &txikiRuntimeState{
		config:        config,
		cwd:           config.cwd,
		net:           newTxikiNetState(),
		workers:       newTxikiWorkerManager(),
		signals:       make(map[int64]*txikiSignal),
		asyncFSJobs:   make(map[int64]*txikiAsyncJob),
		asyncProcJobs: make(map[int64]*txikiAsyncJob),
	}

	c.runtime.addCleanup(state.close)
	state.installHostFunctions(c)

	result, err := c.Eval("txiki-runtime.js", Code(txikiRuntimeScript))
	if result != nil {
		result.Free()
	}
	if err != nil {
		return err
	}

	return c.installTxikiRuntimeModules(config)
}

func (c *Context) installTxikiRuntimeModules(config txikiRuntimeConfig) error {
	modules := map[string]string{}
	if config.hasFeature(TxikiRuntimeFeatureFS) {
		modules["fs"] = txikiFSModuleScript
		modules["node:fs"] = txikiFSModuleScript
		modules["fs/promises"] = txikiFSPromisesModuleScript
		modules["node:fs/promises"] = txikiFSPromisesModuleScript
	}
	if config.hasFeature(TxikiRuntimeFeatureProcess) {
		modules["process"] = txikiProcessModuleScript
		modules["node:process"] = txikiProcessModuleScript
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

func (c *Context) newTxikiRuntimeConfig(options ...TxikiRuntimeOptions) (txikiRuntimeConfig, error) {
	var option TxikiRuntimeOptions
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

	if option.FetchClient == nil {
		option.FetchClient = &fasthttp.Client{}
	}

	if option.Features == 0 {
		option.Features = TxikiRuntimeFeatureAll
	}
	option.Features &^= option.DisableFeatures

	cwd, err := filepath.Abs(option.CWD)
	if err != nil {
		return txikiRuntimeConfig{}, err
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

	return txikiRuntimeConfig{
		cwd:         cwd,
		args:        args,
		env:         env,
		execPath:    option.ExecPath,
		features:    option.Features,
		stdout:      option.Stdout,
		stderr:      option.Stderr,
		fetchClient: option.FetchClient,
	}, nil
}

func (c txikiRuntimeConfig) hasFeature(feature TxikiRuntimeFeature) bool {
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

func (s *txikiRuntimeState) runtimeConfigJSON(this *This) (*Value, error) {
	config := map[string]any{
		"features": map[string]bool{
			"crypto":  s.config.hasFeature(TxikiRuntimeFeatureCrypto),
			"fetch":   s.config.hasFeature(TxikiRuntimeFeatureFetch),
			"fs":      s.config.hasFeature(TxikiRuntimeFeatureFS),
			"process": s.config.hasFeature(TxikiRuntimeFeatureProcess),
			"net":     s.config.hasFeature(TxikiRuntimeFeatureNet),
			"http":    s.config.hasFeature(TxikiRuntimeFeatureHTTP),
			"worker":  s.config.hasFeature(TxikiRuntimeFeatureWorker),
		},
	}

	data, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	return this.Context().NewString(string(data)), nil
}

func (s *txikiRuntimeState) installHostFunctions(c *Context) {
	c.SetFunc("__qjs_runtime_config_json", s.runtimeConfigJSON)
	c.SetFunc("__qjs_console_print", s.consolePrint)
	c.SetFunc("__qjs_now_unix_ms", func(this *This) (*Value, error) {
		return this.Context().NewInt64(time.Now().UnixMilli()), nil
	})
	c.SetFunc("__qjs_sleep", s.sleep)

	if s.config.hasFeature(TxikiRuntimeFeatureCrypto) {
		c.SetFunc("__qjs_crypto_random", s.cryptoRandom)
		c.SetFunc("__qjs_crypto_uuid", s.cryptoUUID)
		c.SetFunc("__qjs_crypto_digest", s.cryptoDigest)
	}
	if s.config.hasFeature(TxikiRuntimeFeatureFetch) {
		c.SetFunc("__qjs_fetch", s.fetch)
	}
	if s.config.hasFeature(TxikiRuntimeFeatureFS) {
		c.SetFunc("__qjs_fs_read_file", s.fsReadFile)
		c.SetFunc("__qjs_fs_read_text", s.fsReadText)
		c.SetFunc("__qjs_fs_write_file", s.fsWriteFile)
		c.SetFunc("__qjs_fs_mkdir", s.fsMkdir)
		c.SetFunc("__qjs_fs_readdir", s.fsReaddir)
		c.SetFunc("__qjs_fs_stat", s.fsStat)
		c.SetFunc("__qjs_fs_exists", s.fsExists)
		c.SetFunc("__qjs_fs_remove", s.fsRemove)
		c.SetFunc("__qjs_fs_async_start", s.fsAsyncStart)
		c.SetFunc("__qjs_fs_async_poll", s.fsAsyncPoll)
	}
	if s.config.hasFeature(TxikiRuntimeFeatureProcess) {
		c.SetFunc("__qjs_process_info", s.processInfo)
		c.SetFunc("__qjs_process_cwd", s.processCWD)
		c.SetFunc("__qjs_process_chdir", s.processChdir)
		c.SetFunc("__qjs_process_env_json", s.processEnvJSON)
		c.SetFunc("__qjs_process_kill", s.processKill)
		c.SetFunc("__qjs_exec_file", s.execFile)
		c.SetFunc("__qjs_exec_file_async_start", s.execFileAsyncStart)
		c.SetFunc("__qjs_exec_file_async_poll", s.execFileAsyncPoll)
		c.SetFunc("__qjs_signal_on", s.signalOn)
		c.SetFunc("__qjs_signal_off", s.signalOff)
		c.SetFunc("__qjs_signal_poll", s.signalPoll)
	}
	if s.config.hasFeature(TxikiRuntimeFeatureNet) {
		s.installNetHostFunctions(c)
	}
	if s.config.hasFeature(TxikiRuntimeFeatureHTTP) {
		s.installHTTPHostFunctions(c)
	}
	if s.config.hasFeature(TxikiRuntimeFeatureWorker) {
		s.installWorkerHostFunctions(c)
	}
}

func (s *txikiRuntimeState) sleep(this *This) (*Value, error) {
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

func (s *txikiRuntimeState) consolePrint(this *This) (*Value, error) {
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

func (s *txikiRuntimeState) cryptoRandom(this *This) (*Value, error) {
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

func (s *txikiRuntimeState) cryptoUUID(this *This) (*Value, error) {
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

func (s *txikiRuntimeState) cryptoDigest(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 2 {
		return nil, errors.New("crypto.subtle.digest requires algorithm and data")
	}

	algorithm := normalizeDigestAlgorithm(args[0].String())
	data, err := jsValueToBytes(args[1])
	if err != nil {
		return nil, err
	}

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
		return nil, fmt.Errorf("unsupported digest algorithm %q", args[0].String())
	}

	return this.Context().NewArrayBuffer(digest), nil
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

func (s *txikiRuntimeState) fetch(this *This) (*Value, error) {
	request, err := s.newFetchRequest(this)
	if err != nil {
		return nil, err
	}

	payload, err := s.doFetch(this.Context().Context, request)
	if err != nil {
		return nil, err
	}

	return ToJsValue(this.Context(), payload)
}

func (s *txikiRuntimeState) newFetchRequest(this *This) (fetchRequest, error) {
	args := this.Args()
	if len(args) < 4 {
		return fetchRequest{}, errors.New("fetch requires url, method, headers, and body")
	}

	url := args[0].String()
	method := strings.TrimSpace(args[1].String())
	if method == "" {
		method = fasthttp.MethodGet
	}

	var bodyBytes []byte
	if !args[3].IsNull() && !args[3].IsUndefined() {
		var err error
		bodyBytes, err = jsValueToBytes(args[3])
		if err != nil {
			return fetchRequest{}, err
		}
	}

	var headers map[string][]string
	if headerJSON := args[2].String(); headerJSON != "" {
		if err := json.Unmarshal([]byte(headerJSON), &headers); err != nil {
			return fetchRequest{}, fmt.Errorf("invalid fetch headers: %w", err)
		}
	}

	return fetchRequest{url: url, method: method, headers: headers, body: bodyBytes}, nil
}

func (s *txikiRuntimeState) doFetch(ctx context.Context, request fetchRequest) (fetchPayload, error) {
	currentURL, err := url.Parse(request.url)
	if err != nil {
		return fetchPayload{}, err
	}

	method := request.method
	body := request.body
	client := s.config.fetchClient
	if client == nil {
		client = &fasthttp.Client{}
	}

	for redirects := 0; redirects <= 20; redirects++ {
		if err := ctx.Err(); err != nil {
			return fetchPayload{}, err
		}

		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		req.SetRequestURI(currentURL.String())
		req.Header.SetMethod(method)
		for name, values := range request.headers {
			for _, value := range values {
				req.Header.Add(name, value)
			}
		}
		if body != nil {
			req.SetBody(body)
		}

		err := client.Do(req, resp)
		fasthttp.ReleaseRequest(req)
		if err != nil {
			fasthttp.ReleaseResponse(resp)
			return fetchPayload{}, err
		}

		status := resp.StatusCode()
		location := string(resp.Header.Peek("Location"))
		if isFetchRedirectStatus(status) && location != "" {
			nextURL, err := currentURL.Parse(location)
			fasthttp.ReleaseResponse(resp)
			if err != nil {
				return fetchPayload{}, err
			}
			if shouldFetchRedirectSwitchToGet(status, method) {
				method = fasthttp.MethodGet
				body = nil
			}
			currentURL = nextURL

			continue
		}

		responseBody := append([]byte(nil), resp.Body()...)
		headers := map[string][]string{}
		resp.Header.VisitAll(func(key, value []byte) {
			name := string(key)
			headers[name] = append(headers[name], string(value))
		})
		payload := fetchPayload{
			URL:        currentURL.String(),
			Status:     status,
			StatusText: fasthttp.StatusMessage(status),
			Headers:    headers,
			Body:       responseBody,
		}
		fasthttp.ReleaseResponse(resp)

		return payload, nil
	}

	return fetchPayload{}, errors.New("fetch stopped after too many redirects")
}

func isFetchRedirectStatus(status int) bool {
	switch status {
	case fasthttp.StatusMovedPermanently,
		fasthttp.StatusFound,
		fasthttp.StatusSeeOther,
		fasthttp.StatusTemporaryRedirect,
		fasthttp.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func shouldFetchRedirectSwitchToGet(status int, method string) bool {
	if status == fasthttp.StatusSeeOther {
		return method != fasthttp.MethodGet && method != fasthttp.MethodHead
	}

	return (status == fasthttp.StatusMovedPermanently || status == fasthttp.StatusFound) && method == fasthttp.MethodPost
}

func (s *txikiRuntimeState) fsReadFile(this *This) (*Value, error) {
	path, err := s.pathArg(this)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return this.Context().NewArrayBuffer(data), nil
}

func (s *txikiRuntimeState) fsReadText(this *This) (*Value, error) {
	path, err := s.pathArg(this)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return this.Context().NewString(string(data)), nil
}

func (s *txikiRuntimeState) fsWriteFile(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 2 {
		return nil, errors.New("writeFile requires path and data")
	}

	path, err := s.resolvePath(args[0].String())
	if err != nil {
		return nil, err
	}

	data, err := jsValueToBytes(args[1])
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, err
	}

	return this.Context().NewUndefined(), nil
}

func (s *txikiRuntimeState) fsMkdir(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("mkdir requires a path")
	}

	path, err := s.resolvePath(args[0].String())
	if err != nil {
		return nil, err
	}

	recursive := len(args) > 1 && args[1].Bool()
	if recursive {
		err = os.MkdirAll(path, 0o755)
	} else {
		err = os.Mkdir(path, 0o755)
	}
	if err != nil {
		return nil, err
	}

	return this.Context().NewUndefined(), nil
}

func (s *txikiRuntimeState) fsReaddir(this *This) (*Value, error) {
	path, err := s.pathArg(this)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	return ToJsValue(this.Context(), names)
}

func (s *txikiRuntimeState) fsStat(this *This) (*Value, error) {
	path, err := s.pathArg(this)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	return ToJsValue(this.Context(), fileInfoToStat(info))
}

func (s *txikiRuntimeState) fsExists(this *This) (*Value, error) {
	path, err := s.pathArg(this)
	if err != nil {
		return nil, err
	}

	_, err = os.Stat(path)
	if err == nil {
		return this.Context().NewBool(true), nil
	}

	if errors.Is(err, os.ErrNotExist) {
		return this.Context().NewBool(false), nil
	}

	return nil, err
}

func (s *txikiRuntimeState) fsRemove(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("remove requires a path")
	}

	path, err := s.resolvePath(args[0].String())
	if err != nil {
		return nil, err
	}

	recursive := len(args) > 1 && args[1].Bool()
	if recursive {
		err = os.RemoveAll(path)
	} else {
		err = os.Remove(path)
	}
	if err != nil {
		return nil, err
	}

	return this.Context().NewUndefined(), nil
}

func (s *txikiRuntimeState) fsAsyncStart(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 4 {
		return nil, errors.New("async fs start requires operation, path, encoding, and recursive")
	}

	op := args[0].String()
	path, err := s.resolvePath(args[1].String())
	if err != nil {
		return nil, err
	}
	encoding := strings.ToLower(strings.TrimSpace(args[2].String()))
	recursive := args[3].Bool()

	var data []byte
	if len(args) > 4 && !args[4].IsNull() && !args[4].IsUndefined() {
		data, err = jsValueToBytes(args[4])
		if err != nil {
			return nil, err
		}
	}

	id := s.addAsyncFSJob()
	go func() {
		result, err := s.runAsyncFSOperation(op, path, encoding, recursive, data)
		s.completeAsyncFSJob(id, result, err)
	}()

	return this.Context().NewInt64(id), nil
}

func (s *txikiRuntimeState) fsAsyncPoll(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("async fs poll requires a job id")
	}

	id := args[0].Int64()
	s.asyncMu.Lock()
	job, ok := s.asyncFSJobs[id]
	if !ok {
		s.asyncMu.Unlock()
		return nil, fmt.Errorf("async fs job %d does not exist", id)
	}
	if !job.done {
		s.asyncMu.Unlock()
		return ToJsValue(this.Context(), map[string]any{"done": false})
	}
	delete(s.asyncFSJobs, id)
	s.asyncMu.Unlock()

	payload := map[string]any{"done": true}
	if job.err != nil {
		payload["error"] = job.err.Error()
	} else {
		payload["result"] = job.result
	}

	return ToJsValue(this.Context(), payload)
}

func (s *txikiRuntimeState) addAsyncFSJob() int64 {
	s.asyncMu.Lock()
	defer s.asyncMu.Unlock()

	s.nextAsyncID++
	id := s.nextAsyncID
	s.asyncFSJobs[id] = &txikiAsyncJob{}

	return id
}

func (s *txikiRuntimeState) completeAsyncFSJob(id int64, result any, err error) {
	s.asyncMu.Lock()
	defer s.asyncMu.Unlock()

	if job := s.asyncFSJobs[id]; job != nil {
		job.done = true
		job.result = result
		job.err = err
	}
}

func (s *txikiRuntimeState) runAsyncFSOperation(op, path, encoding string, recursive bool, data []byte) (any, error) {
	switch op {
	case "readFile":
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if encoding != "" {
			return string(content), nil
		}

		return content, nil
	case "writeFile":
		return nil, os.WriteFile(path, data, 0o644)
	case "mkdir":
		if recursive {
			return nil, os.MkdirAll(path, 0o755)
		}

		return nil, os.Mkdir(path, 0o755)
	case "readdir":
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		sort.Strings(names)

		return names, nil
	case "stat":
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}

		return fileInfoToStat(info), nil
	case "exists":
		_, err := os.Stat(path)
		if err == nil {
			return true, nil
		}
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}

		return nil, err
	case "remove":
		if recursive {
			return nil, os.RemoveAll(path)
		}

		return nil, os.Remove(path)
	default:
		return nil, fmt.Errorf("unsupported async fs operation %q", op)
	}
}

func fileInfoToStat(info os.FileInfo) map[string]any {
	return map[string]any{
		"name":    info.Name(),
		"size":    info.Size(),
		"mode":    info.Mode().String(),
		"modTime": info.ModTime(),
		"isFile":  !info.IsDir(),
		"isDir":   info.IsDir(),
	}
}

func (s *txikiRuntimeState) pathArg(this *This) (string, error) {
	args := this.Args()
	if len(args) == 0 {
		return "", errors.New("path is required")
	}

	return s.resolvePath(args[0].String())
}

func (s *txikiRuntimeState) currentCWD() string {
	s.cwdMu.RLock()
	defer s.cwdMu.RUnlock()

	if s.cwd != "" {
		return s.cwd
	}

	return s.config.cwd
}

func (s *txikiRuntimeState) resolvePath(name string) (string, error) {
	return s.resolvePathFrom(s.currentCWD(), name)
}

func (s *txikiRuntimeState) resolvePathFrom(base, name string) (string, error) {
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

func (s *txikiRuntimeState) chdir(path string) (string, error) {
	next, err := s.resolvePath(path)
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

func (s *txikiRuntimeState) processInfo(this *This) (*Value, error) {
	info := map[string]any{
		"pid":      os.Getpid(),
		"ppid":     os.Getppid(),
		"platform": goruntime.GOOS,
		"arch":     goruntime.GOARCH,
		"cwd":      s.currentCWD(),
		"execPath": s.config.execPath,
		"argv":     append([]string(nil), s.config.args...),
		"args":     append([]string(nil), s.config.args...),
	}

	return ToJsValue(this.Context(), info)
}

func (s *txikiRuntimeState) processCWD(this *This) (*Value, error) {
	return this.Context().NewString(s.currentCWD()), nil
}

func (s *txikiRuntimeState) processChdir(this *This) (*Value, error) {
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

func (s *txikiRuntimeState) processEnvJSON(this *This) (*Value, error) {
	data, err := json.Marshal(s.config.env)
	if err != nil {
		return nil, err
	}

	return this.Context().NewString(string(data)), nil
}

func (s *txikiRuntimeState) processKill(this *This) (*Value, error) {
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

func (s *txikiRuntimeState) execFile(this *This) (*Value, error) {
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

func (s *txikiRuntimeState) execFileAsyncStart(this *This) (*Value, error) {
	request, err := s.newExecFileRequest(this)
	if err != nil {
		return nil, err
	}

	id := s.addAsyncProcessJob()
	go func() {
		result, err := s.doExecFile(request)
		s.completeAsyncProcessJob(id, result, err)
	}()

	return this.Context().NewInt64(id), nil
}

func (s *txikiRuntimeState) execFileAsyncPoll(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("async execFile poll requires a job id")
	}

	id := args[0].Int64()
	s.asyncMu.Lock()
	job, ok := s.asyncProcJobs[id]
	if !ok {
		s.asyncMu.Unlock()
		return nil, fmt.Errorf("async execFile job %d does not exist", id)
	}
	if !job.done {
		s.asyncMu.Unlock()
		return ToJsValue(this.Context(), map[string]any{"done": false})
	}
	delete(s.asyncProcJobs, id)
	s.asyncMu.Unlock()

	payload := map[string]any{"done": true}
	if job.err != nil {
		payload["error"] = job.err.Error()
	} else {
		payload["result"] = job.result
	}

	return ToJsValue(this.Context(), payload)
}

func (s *txikiRuntimeState) addAsyncProcessJob() int64 {
	s.asyncMu.Lock()
	defer s.asyncMu.Unlock()

	s.nextAsyncID++
	id := s.nextAsyncID
	s.asyncProcJobs[id] = &txikiAsyncJob{}

	return id
}

func (s *txikiRuntimeState) completeAsyncProcessJob(id int64, result any, err error) {
	s.asyncMu.Lock()
	defer s.asyncMu.Unlock()

	if job := s.asyncProcJobs[id]; job != nil {
		job.done = true
		job.result = result
		job.err = err
	}
}

func (s *txikiRuntimeState) newExecFileRequest(this *This) (execFileRequest, error) {
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
		cwd, err = s.resolvePath(argCWD)
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

func (s *txikiRuntimeState) doExecFile(request execFileRequest) (map[string]any, error) {
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

func (s *txikiRuntimeState) signalOn(this *This) (*Value, error) {
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
	watcher := &txikiSignal{
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

func (s *txikiRuntimeState) enqueueSignal(watcher *txikiSignal) {
	if watcher == nil || watcher.closed.Load() {
		return
	}

	s.signalsMu.Lock()
	if !watcher.closed.Load() {
		s.signalEvents = append(s.signalEvents, txikiSignalEvent{ID: watcher.id, Signal: watcher.label})
	}
	s.signalsMu.Unlock()
}

func (s *txikiRuntimeState) signalPoll(this *This) (*Value, error) {
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

func (s *txikiRuntimeState) signalOff(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return this.Context().NewUndefined(), nil
	}

	s.deleteSignal(args[0].Int64())

	return this.Context().NewUndefined(), nil
}

func (s *txikiRuntimeState) deleteSignal(id int64) {
	s.signalsMu.Lock()
	watcher := s.signals[id]
	delete(s.signals, id)
	s.signalsMu.Unlock()

	if watcher != nil {
		watcher.close()
	}
}

func (s *txikiSignal) close() {
	s.closed.Store(true)
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *txikiRuntimeState) close() {
	if s.net != nil {
		s.net.close()
	}
	if s.workers != nil {
		s.workers.close()
	}

	s.signalsMu.Lock()
	signals := make([]*txikiSignal, 0, len(s.signals))
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

const txikiRuntimeScript = `
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
      return Promise.resolve(__qjs_crypto_digest(name, toArrayBuffer(data)));
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
    _key(name) { return String(name).toLowerCase(); }
    append(name, value) {
      const key = this._key(name);
      if (!this._values[key]) this._values[key] = [];
      this._values[key].push(String(value));
    }
    set(name, value) { this._values[this._key(name)] = [String(value)]; }
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

  class Request {
    constructor(input, init = {}) {
      const source = input instanceof Request ? input : null;
      this.url = String(source ? source.url : input && input.url ? input.url : input);
      if (!this.url || this.url === "undefined") throw new TypeError("Request requires a URL");
      this.method = String(init.method || (source && source.method) || "GET").toUpperCase();
      this.headers = new Headers(init.headers || (source && source.headers) || {});
      this.signal = init.signal || (source && source.signal) || null;
      const hasInitBody = Object.prototype.hasOwnProperty.call(init, "body");
      this._body = hasInitBody ? toArrayBuffer(init.body) : source && source._body ? source._body.slice(0) : null;
      this.bodyUsed = false;
    }
    arrayBuffer() {
      this.bodyUsed = true;
      return Promise.resolve((this._body || new ArrayBuffer(0)).slice(0));
    }
    text() {
      return this.arrayBuffer().then(decodeBytes);
    }
    json() {
      return this.text().then(JSON.parse);
    }
    clone() {
      return new Request(this);
    }
  }
  define(globalThis, "Request", Request);

  class Response {
    constructor(bodyOrPayload = null, init = undefined) {
      const hostPayload = init === undefined &&
        bodyOrPayload &&
        typeof bodyOrPayload === "object" &&
        Object.prototype.hasOwnProperty.call(bodyOrPayload, "status") &&
        Object.prototype.hasOwnProperty.call(bodyOrPayload, "body");
      const payload = hostPayload ? bodyOrPayload : {
        url: "",
        status: init && init.status !== undefined ? init.status : 200,
        statusText: init && init.statusText !== undefined ? init.statusText : "",
        headers: init && init.headers ? init.headers : {},
        body: toArrayBuffer(bodyOrPayload) || new ArrayBuffer(0)
      };
      this.url = payload.url || "";
      this.status = payload.status || 0;
      this.statusText = payload.statusText || "";
      this.ok = this.status >= 200 && this.status <= 299;
      this.headers = new Headers(payload.headers || {});
      this._body = toArrayBuffer(payload.body || new ArrayBuffer(0));
      this.bodyUsed = false;
    }
    arrayBuffer() {
      this.bodyUsed = true;
      return Promise.resolve(this._body.slice(0));
    }
    text() {
      this.bodyUsed = true;
      return Promise.resolve(decodeBytes(this._body));
    }
    json() {
      return this.text().then(JSON.parse);
    }
    clone() {
      return new Response({
        url: this.url,
        status: this.status,
        statusText: this.statusText,
        headers: this.headers.toObject(),
        body: this._body.slice(0)
      });
    }
  }
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
      return Promise.resolve(__qjs_fetch(request.url, request.method, JSON.stringify(headersToObject(request.headers)), request._body)).then(payload => new Response(payload));
    });
  }

  if (feature("fs")) {
    function fsAsync(op, path, options, data) {
      const encoding = typeof options === "string" ? options : options && options.encoding ? options.encoding : "";
      const recursive = !!(options && typeof options === "object" && options.recursive);
      return new Promise((resolve, reject) => {
        let id;
        try {
          id = __qjs_fs_async_start(String(op), String(path), String(encoding || ""), recursive, data === undefined ? null : data);
        } catch (error) {
          reject(error);
          return;
        }
        const poll = () => {
          let payload;
          try {
            payload = __qjs_fs_async_poll(id);
          } catch (error) {
            reject(error);
            return;
          }
          if (!payload.done) {
            setTimeout(poll, 1);
            return;
          }
          if (payload.error) reject(new Error(payload.error));
          else resolve(payload.result);
        };
        setTimeout(poll, 0);
      });
    }

    const fs = qjs.fs || {};
    fs.readFileSync = function readFileSync(path, options) {
      const encoding = typeof options === "string" ? options : options && options.encoding;
      return encoding ? __qjs_fs_read_text(String(path), String(encoding)) : __qjs_fs_read_file(String(path));
    };
    fs.readFileTextSync = path => __qjs_fs_read_text(String(path), "utf8");
    fs.writeFileSync = (path, data) => __qjs_fs_write_file(String(path), data);
    fs.mkdirSync = (path, options = {}) => __qjs_fs_mkdir(String(path), !!options.recursive);
    fs.readdirSync = path => __qjs_fs_readdir(String(path || "."));
    fs.statSync = path => __qjs_fs_stat(String(path));
    fs.existsSync = path => __qjs_fs_exists(String(path));
    fs.removeSync = (path, options = {}) => __qjs_fs_remove(String(path), !!options.recursive);
    fs.readFile = (path, options) => fsAsync("readFile", path, options);
    fs.readFileText = path => fsAsync("readFile", path, "utf8");
    fs.writeFile = (path, data, options = {}) => fsAsync("writeFile", path, options, data);
    fs.mkdir = (path, options = {}) => fsAsync("mkdir", path, options);
    fs.readdir = path => fsAsync("readdir", path || ".", {});
    fs.stat = path => fsAsync("stat", path, {});
    fs.exists = path => fsAsync("exists", path, {});
    fs.remove = (path, options = {}) => fsAsync("remove", path, options);
    fs.rm = fs.remove;
    fs.rmSync = fs.removeSync;
    fs.readDir = fs.readdir;
    fs.makeDir = fs.mkdir;
    const fsPromises = fs.promises || {};
    fsPromises.readFile = fs.readFile;
    fsPromises.readFileText = fs.readFileText;
    fsPromises.writeFile = fs.writeFile;
    fsPromises.mkdir = fs.mkdir;
    fsPromises.readdir = fs.readdir;
    fsPromises.readDir = fs.readdir;
    fsPromises.stat = fs.stat;
    fsPromises.exists = fs.exists;
    fsPromises.remove = fs.remove;
    fsPromises.rm = fs.remove;
    define(fs, "promises", fsPromises, true);
    define(qjs, "fs", fs, true);
  }
  if (typeof globalThis.tjs === "undefined") define(globalThis, "tjs", qjs);

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
    processObj.cwd = () => __qjs_process_cwd();
    processObj.chdir = path => __qjs_process_chdir(String(path));
    processObj.kill = (pid, signal = "SIGTERM") => __qjs_process_kill(Number(pid), String(signal));
    processObj.exitCode = 0;

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
    function pollAsyncJob(pollFn, id, resolve, reject) {
      let payload;
      try {
        payload = pollFn(id);
      } catch (error) {
        reject(error);
        return;
      }
      if (!payload.done) {
        setTimeout(() => pollAsyncJob(pollFn, id, resolve, reject), 1);
        return;
      }
      if (payload.error) reject(new Error(payload.error));
      else resolve(payload.result);
    }
    processObj.execFileSync = function execFileSync(file, args = [], options = {}) {
      return __qjs_exec_file(...execFileArgs(file, args, options));
    };
    processObj.execFile = function execFile(file, args = [], options = {}) {
      return new Promise((resolve, reject) => {
        let id;
        try {
          id = __qjs_exec_file_async_start(...execFileArgs(file, args, options));
        } catch (error) {
          reject(error);
          return;
        }
        setTimeout(() => pollAsyncJob(__qjs_exec_file_async_poll, id, resolve, reject), 0);
      });
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
    define(qjs, "process", processObj, true);
    define(globalThis, "process", processObj);
  }
})();
`

const txikiFSModuleScript = `
const fs = globalThis.qjs && globalThis.qjs.fs;
if (!fs) throw new Error("qjs fs runtime is not installed");
const promises = fs.promises;
const readFile = fs.readFile;
const readFileText = fs.readFileText;
const writeFile = fs.writeFile;
const mkdir = fs.mkdir;
const makeDir = fs.makeDir;
const readdir = fs.readdir;
const readDir = fs.readDir;
const stat = fs.stat;
const exists = fs.exists;
const remove = fs.remove;
const rm = fs.rm;
const readFileSync = fs.readFileSync;
const readFileTextSync = fs.readFileTextSync;
const writeFileSync = fs.writeFileSync;
const mkdirSync = fs.mkdirSync;
const readdirSync = fs.readdirSync;
const statSync = fs.statSync;
const existsSync = fs.existsSync;
const removeSync = fs.removeSync;
const rmSync = fs.rmSync;
export {
  promises,
  readFile,
  readFileText,
  writeFile,
  mkdir,
  makeDir,
  readdir,
  readDir,
  stat,
  exists,
  remove,
  rm,
  readFileSync,
  readFileTextSync,
  writeFileSync,
  mkdirSync,
  readdirSync,
  statSync,
  existsSync,
  removeSync,
  rmSync
};
export default fs;
`

const txikiFSPromisesModuleScript = `
const fs = globalThis.qjs && globalThis.qjs.fs;
if (!fs) throw new Error("qjs fs runtime is not installed");
const promises = fs.promises;
const readFile = promises.readFile;
const readFileText = promises.readFileText;
const writeFile = promises.writeFile;
const mkdir = promises.mkdir;
const makeDir = promises.mkdir;
const readdir = promises.readdir;
const readDir = promises.readDir;
const stat = promises.stat;
const exists = promises.exists;
const remove = promises.remove;
const rm = promises.rm;
export {
  readFile,
  readFileText,
  writeFile,
  mkdir,
  makeDir,
  readdir,
  readDir,
  stat,
  exists,
  remove,
  rm
};
export default promises;
`

const txikiProcessModuleScript = `
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
  kill,
  execFile,
  execFileSync,
  onSignal,
  pollSignals
};
export default process;
`
