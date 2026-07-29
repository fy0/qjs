package qjs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

type hostWorkerManager struct {
	mu      sync.Mutex
	nextID  int64
	workers map[int64]*hostWorker
}

type hostWorker struct {
	id             int64
	source         string
	filename       string
	module         bool
	config         hostRuntimeConfig
	cancel         context.CancelFunc
	parentToWorker chan string
	workerToParent chan string
	done           chan struct{}
	stopped        atomic.Bool
	errMu          sync.Mutex
	err            error
}

type hostWorkerCreateOptions struct {
	Eval bool   `json:"eval"`
	Type string `json:"type"`
	Name string `json:"name"`
}

func newHostWorkerManager() *hostWorkerManager {
	return &hostWorkerManager{
		workers: map[int64]*hostWorker{},
	}
}

func (s *hostRuntimeState) installWorkerHostFunctions(c *Context) {
	c.SetFunc("__qjs_worker_create", s.workerCreate)
	c.SetFunc("__qjs_worker_post", s.workerPost)
	c.SetFunc("__qjs_worker_poll", s.workerPoll)
	c.SetFunc("__qjs_worker_error", s.workerError)
	c.SetFunc("__qjs_worker_terminate", s.workerTerminate)
}

func (m *hostWorkerManager) add(worker *hostWorker) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextID++
	worker.id = m.nextID
	m.workers[worker.id] = worker

	return worker.id
}

func (m *hostWorkerManager) get(id int64) (*hostWorker, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	worker, ok := m.workers[id]
	if !ok {
		return nil, fmt.Errorf("worker %d is closed or does not exist", id)
	}

	return worker, nil
}

func (m *hostWorkerManager) delete(id int64) *hostWorker {
	m.mu.Lock()
	defer m.mu.Unlock()

	worker := m.workers[id]
	delete(m.workers, id)

	return worker
}

func (m *hostWorkerManager) close() {
	m.mu.Lock()
	workers := m.workers
	m.workers = map[int64]*hostWorker{}
	m.mu.Unlock()

	for _, worker := range workers {
		worker.stop()
	}
}

func (s *hostRuntimeState) workerCreate(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("Worker requires a script source or path")
	}

	sourceOrPath := args[0].String()
	var options hostWorkerCreateOptions
	if len(args) > 1 {
		if raw := args[1].String(); raw != "" {
			if err := json.Unmarshal([]byte(raw), &options); err != nil {
				return nil, fmt.Errorf("invalid Worker options: %w", err)
			}
		}
	}

	source := sourceOrPath
	filename := options.Name
	if filename == "" {
		filename = "<worker>"
	}

	if !options.Eval {
		data, err := s.fsys.readFile(sourceOrPath)
		if err != nil {
			return nil, err
		}

		source = string(data)
		filename, err = s.fsys.realPath(sourceOrPath)
		if err != nil {
			return nil, err
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	worker := &hostWorker{
		source:         source,
		filename:       filename,
		module:         options.Type == "module",
		config:         cloneHostRuntimeConfig(s.config),
		cancel:         cancel,
		parentToWorker: make(chan string, 64),
		workerToParent: make(chan string, 64),
		done:           make(chan struct{}),
	}

	id := s.workers.add(worker)
	go worker.run(ctx)

	return this.Context().NewInt64(id), nil
}

func cloneHostRuntimeConfig(config hostRuntimeConfig) hostRuntimeConfig {
	config.args = append([]string(nil), config.args...)
	config.env = cloneStringMap(config.env)
	config.fs.Mounts = append([]FileSystemMount(nil), config.fs.Mounts...)
	return config
}

func (s *hostRuntimeState) workerPost(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 2 {
		return nil, errors.New("Worker.postMessage requires worker id and message")
	}

	worker, err := s.workers.get(args[0].Int64())
	if err != nil {
		return nil, err
	}

	if worker.stopped.Load() {
		return nil, errors.New("worker is terminated")
	}

	select {
	case worker.parentToWorker <- args[1].String():
		return this.Context().NewUndefined(), nil
	default:
		return nil, errors.New("worker message queue is full")
	}
}

func (s *hostRuntimeState) workerPoll(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("Worker.pollMessages requires worker id")
	}

	worker, err := s.workers.get(args[0].Int64())
	if err != nil {
		return nil, err
	}

	messages := []string{}
	for {
		select {
		case message, ok := <-worker.workerToParent:
			if !ok {
				return ToJsValue(this.Context(), messages)
			}
			messages = append(messages, message)
		default:
			return ToJsValue(this.Context(), messages)
		}
	}
}

func (s *hostRuntimeState) workerError(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("Worker.error requires worker id")
	}

	worker, err := s.workers.get(args[0].Int64())
	if err != nil {
		return nil, err
	}

	if err := worker.error(); err != nil {
		return this.Context().NewString(err.Error()), nil
	}

	return this.Context().NewString(""), nil
}

func (s *hostRuntimeState) workerTerminate(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return this.Context().NewUndefined(), nil
	}

	worker := s.workers.delete(args[0].Int64())
	if worker != nil {
		worker.stop()
	}

	return this.Context().NewUndefined(), nil
}

func (w *hostWorker) run(ctx context.Context) {
	defer w.stopped.Store(true)
	defer close(w.done)
	defer close(w.workerToParent)

	rt, err := New(Option{
		CWD:     w.config.cwd,
		Context: ctx,
		Stdout:  w.config.stdout,
		Stderr:  w.config.stderr,
	})
	if err != nil {
		w.setError(err)
		return
	}
	defer rt.Close()

	if err := rt.InstallHostRuntime(HostRuntimeOptions{
		CWD:                  w.config.cwd,
		Args:                 w.config.args,
		Env:                  w.config.env,
		ExecPath:             w.config.execPath,
		Profile:              HostRuntimeProfileBare,
		EnableFeatures:       w.config.features,
		FileSystem:           w.config.fs,
		Stdin:                w.config.stdin,
		Stdout:               w.config.stdout,
		Stderr:               w.config.stderr,
		FetchClient:          w.config.fetchClient,
		MaxBufferedBodyBytes: w.config.maxBodySize,
	}); err != nil {
		w.setError(err)
		return
	}

	ctxJS := rt.Context()
	workerBridge := &hostWorkerBridge{worker: w}
	ctxJS.SetFunc("__qjs_worker_post_parent", workerBridge.postParent)
	ctxJS.SetFunc("__qjs_worker_close_self", workerBridge.closeSelf)

	if result, err := ctxJS.Eval("worker-bootstrap.js", Code(hostWorkerBootstrapScript)); err != nil {
		w.setError(err)
		return
	} else if result != nil {
		result.Free()
	}

	evalOptions := []EvalOptionFunc{Code(w.source)}
	if w.module {
		evalOptions = append(evalOptions, TypeModule())
	}
	result, err := ctxJS.Eval(w.filename, evalOptions...)
	if result != nil {
		result.Free()
	}
	if err != nil {
		w.setError(err)
		return
	}

	dispatch := ctxJS.Global().GetPropertyStr("__qjsWorkerDispatch")
	defer dispatch.Free()
	if !dispatch.IsFunction() {
		w.setError(errors.New("worker bootstrap did not install message dispatcher"))
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case message, ok := <-w.parentToWorker:
			if !ok {
				return
			}

			arg := ctxJS.NewString(message)
			result, err := ctxJS.Invoke(dispatch, ctxJS.Global(), arg)
			arg.Free()
			if result != nil {
				result.Free()
			}
			if err != nil {
				w.setError(err)
				return
			}
		}
	}
}

func (w *hostWorker) stop() {
	if w.stopped.Swap(true) {
		return
	}

	if w.cancel != nil {
		w.cancel()
	}
	<-w.done
}

func (w *hostWorker) setError(err error) {
	if err == nil {
		return
	}

	w.errMu.Lock()
	w.err = err
	w.errMu.Unlock()
}

func (w *hostWorker) error() error {
	w.errMu.Lock()
	defer w.errMu.Unlock()

	return w.err
}

type hostWorkerBridge struct {
	worker *hostWorker
}

func (b *hostWorkerBridge) postParent(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return this.Context().NewUndefined(), nil
	}

	select {
	case b.worker.workerToParent <- args[0].String():
		return this.Context().NewUndefined(), nil
	default:
		return nil, errors.New("parent worker message queue is full")
	}
}

func (b *hostWorkerBridge) closeSelf(this *This) (*Value, error) {
	if b.worker.cancel != nil {
		b.worker.cancel()
	}

	return this.Context().NewUndefined(), nil
}

const hostWorkerBootstrapScript = `
(function () {
  function parseMessage(raw) {
    try {
      return JSON.parse(raw);
    } catch (_) {
      return raw;
    }
  }

  function stringifyMessage(value) {
    return JSON.stringify(value);
  }

  const listeners = new Map();
  const selfRef = globalThis.self || globalThis;
  globalThis.self = selfRef;

  selfRef.postMessage = function postMessage(value) {
    return __qjs_worker_post_parent(stringifyMessage(value));
  };
  selfRef.close = function close() {
    return __qjs_worker_close_self();
  };
  selfRef.addEventListener = function addEventListener(type, callback) {
    type = String(type);
    if (!listeners.has(type)) listeners.set(type, new Set());
    listeners.get(type).add(callback);
  };
  selfRef.removeEventListener = function removeEventListener(type, callback) {
    const callbacks = listeners.get(String(type));
    if (callbacks) callbacks.delete(callback);
  };
  selfRef.dispatchEvent = function dispatchEvent(event) {
    const callbacks = listeners.get(event.type);
    if (callbacks) {
      for (const callback of Array.from(callbacks)) callback.call(selfRef, event);
    }
    const handler = selfRef["on" + event.type];
    if (typeof handler === "function") handler.call(selfRef, event);
    return !event.defaultPrevented;
  };
  globalThis.__qjsWorkerDispatch = function __qjsWorkerDispatch(raw) {
    const event = {
      type: "message",
      data: parseMessage(raw),
      target: selfRef,
      currentTarget: selfRef,
      defaultPrevented: false,
      preventDefault() { this.defaultPrevented = true; }
    };
    selfRef.dispatchEvent(event);
  };
})();
`
