package qjs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
)

type txikiWorkerManager struct {
	mu      sync.Mutex
	nextID  int64
	workers map[int64]*txikiWorker
}

type txikiWorker struct {
	id             int64
	source         string
	filename       string
	module         bool
	config         txikiRuntimeConfig
	cancel         context.CancelFunc
	parentToWorker chan string
	workerToParent chan string
	done           chan struct{}
	stopped        atomic.Bool
	errMu          sync.Mutex
	err            error
}

type txikiWorkerCreateOptions struct {
	Eval bool   `json:"eval"`
	Type string `json:"type"`
	Name string `json:"name"`
}

func newTxikiWorkerManager() *txikiWorkerManager {
	return &txikiWorkerManager{
		workers: map[int64]*txikiWorker{},
	}
}

func (s *txikiRuntimeState) installWorkerHostFunctions(c *Context) {
	c.SetFunc("__qjs_worker_create", s.workerCreate)
	c.SetFunc("__qjs_worker_post", s.workerPost)
	c.SetFunc("__qjs_worker_poll", s.workerPoll)
	c.SetFunc("__qjs_worker_error", s.workerError)
	c.SetFunc("__qjs_worker_terminate", s.workerTerminate)
}

func (m *txikiWorkerManager) add(worker *txikiWorker) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextID++
	worker.id = m.nextID
	m.workers[worker.id] = worker

	return worker.id
}

func (m *txikiWorkerManager) get(id int64) (*txikiWorker, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	worker, ok := m.workers[id]
	if !ok {
		return nil, fmt.Errorf("worker %d is closed or does not exist", id)
	}

	return worker, nil
}

func (m *txikiWorkerManager) delete(id int64) *txikiWorker {
	m.mu.Lock()
	defer m.mu.Unlock()

	worker := m.workers[id]
	delete(m.workers, id)

	return worker
}

func (m *txikiWorkerManager) close() {
	m.mu.Lock()
	workers := m.workers
	m.workers = map[int64]*txikiWorker{}
	m.mu.Unlock()

	for _, worker := range workers {
		worker.stop()
	}
}

func (s *txikiRuntimeState) workerCreate(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("Worker requires a script source or path")
	}

	sourceOrPath := args[0].String()
	var options txikiWorkerCreateOptions
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
		path, err := s.resolvePath(sourceOrPath)
		if err != nil {
			return nil, err
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		source = string(data)
		filename = path
	}

	ctx, cancel := context.WithCancel(context.Background())
	worker := &txikiWorker{
		source:         source,
		filename:       filename,
		module:         options.Type == "module",
		config:         s.config,
		cancel:         cancel,
		parentToWorker: make(chan string, 64),
		workerToParent: make(chan string, 64),
		done:           make(chan struct{}),
	}

	id := s.workers.add(worker)
	go worker.run(ctx)

	return this.Context().NewInt64(id), nil
}

func (s *txikiRuntimeState) workerPost(this *This) (*Value, error) {
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

func (s *txikiRuntimeState) workerPoll(this *This) (*Value, error) {
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

func (s *txikiRuntimeState) workerError(this *This) (*Value, error) {
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

func (s *txikiRuntimeState) workerTerminate(this *This) (*Value, error) {
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

func (w *txikiWorker) run(ctx context.Context) {
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

	if err := rt.InstallTxikiRuntime(TxikiRuntimeOptions{
		CWD:         w.config.cwd,
		Stdout:      w.config.stdout,
		Stderr:      w.config.stderr,
		FetchClient: w.config.fetchClient,
	}); err != nil {
		w.setError(err)
		return
	}

	ctxJS := rt.Context()
	workerBridge := &txikiWorkerBridge{worker: w}
	ctxJS.SetFunc("__qjs_worker_post_parent", workerBridge.postParent)
	ctxJS.SetFunc("__qjs_worker_close_self", workerBridge.closeSelf)

	if result, err := ctxJS.Eval("worker-bootstrap.js", Code(txikiWorkerBootstrapScript)); err != nil {
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

func (w *txikiWorker) stop() {
	if w.stopped.Swap(true) {
		return
	}

	if w.cancel != nil {
		w.cancel()
	}
	close(w.parentToWorker)
	<-w.done
}

func (w *txikiWorker) setError(err error) {
	if err == nil {
		return
	}

	w.errMu.Lock()
	w.err = err
	w.errMu.Unlock()
}

func (w *txikiWorker) error() error {
	w.errMu.Lock()
	defer w.errMu.Unlock()

	return w.err
}

type txikiWorkerBridge struct {
	worker *txikiWorker
}

func (b *txikiWorkerBridge) postParent(this *This) (*Value, error) {
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

func (b *txikiWorkerBridge) closeSelf(this *This) (*Value, error) {
	if b.worker.cancel != nil {
		b.worker.cancel()
	}

	return this.Context().NewUndefined(), nil
}

const txikiWorkerBootstrapScript = `
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
