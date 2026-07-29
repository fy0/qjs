package qjs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
)

type hostAsyncManager struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	nextID int64
	jobs   map[int64]*hostAsyncJob
	closed bool
	wg     sync.WaitGroup
}

type hostAsyncJob struct {
	cancel context.CancelFunc
	done   bool
	result any
	err    error
}

type hostErrorPayload struct {
	Name    string `json:"name,omitempty"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
	Errno   int64  `json:"errno,omitempty"`
	Syscall string `json:"syscall,omitempty"`
	Path    string `json:"path,omitempty"`
	Dest    string `json:"dest,omitempty"`
}

type hostOperationError struct {
	Err  error
	Op   string
	Path string
	Dest string
}

func (e *hostOperationError) Error() string { return e.Err.Error() }
func (e *hostOperationError) Unwrap() error { return e.Err }

func newHostAsyncManager(parent context.Context) *hostAsyncManager {
	ctx, cancel := context.WithCancel(parent)
	return &hostAsyncManager{
		ctx:    ctx,
		cancel: cancel,
		jobs:   make(map[int64]*hostAsyncJob),
	}
}

func (m *hostAsyncManager) start(fn func(context.Context) (any, error)) (int64, error) {
	if fn == nil {
		return 0, errors.New("async operation is required")
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, errors.New("host runtime is closed")
	}
	m.nextID++
	id := m.nextID
	ctx, cancel := context.WithCancel(m.ctx)
	m.jobs[id] = &hostAsyncJob{cancel: cancel}
	m.wg.Add(1)
	m.mu.Unlock()

	go func() {
		defer m.wg.Done()
		result, err := fn(ctx)

		m.mu.Lock()
		if job := m.jobs[id]; job != nil {
			job.done = true
			job.result = result
			job.err = err
		}
		m.mu.Unlock()
	}()

	return id, nil
}

func (m *hostAsyncManager) poll(id int64) (map[string]any, error) {
	m.mu.Lock()
	job, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("async operation %d does not exist", id)
	}
	if !job.done {
		m.mu.Unlock()
		return map[string]any{"done": false}, nil
	}
	delete(m.jobs, id)
	job.cancel()
	m.mu.Unlock()

	payload := map[string]any{"done": true}
	if job.err != nil {
		payload["error"] = makeHostError(job.err, "", "", "")
	} else {
		payload["result"] = job.result
	}

	return payload, nil
}

func (m *hostAsyncManager) cancelJob(id int64) {
	m.mu.Lock()
	if job := m.jobs[id]; job != nil {
		job.cancel()
	}
	m.mu.Unlock()
}

func (m *hostAsyncManager) close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.cancel()
	for _, job := range m.jobs {
		job.cancel()
	}
	m.mu.Unlock()

	m.wg.Wait()

	m.mu.Lock()
	m.jobs = make(map[int64]*hostAsyncJob)
	m.mu.Unlock()
}

func makeHostError(err error, op, path, dest string) hostErrorPayload {
	payload := hostErrorPayload{Message: err.Error(), Syscall: op, Path: path, Dest: dest}
	if errors.Is(err, context.Canceled) {
		payload.Name = "AbortError"
		payload.Code = "ABORT_ERR"
		payload.Message = "The operation was aborted"
		return payload
	}
	if errors.Is(err, context.DeadlineExceeded) {
		payload.Name = "TimeoutError"
		payload.Code = "ETIMEDOUT"
		return payload
	}
	var operationErr *hostOperationError
	if errors.As(err, &operationErr) {
		if payload.Syscall == "" {
			payload.Syscall = operationErr.Op
		}
		if payload.Path == "" {
			payload.Path = operationErr.Path
		}
		if payload.Dest == "" {
			payload.Dest = operationErr.Dest
		}
		err = operationErr.Err
	}

	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		if payload.Syscall == "" {
			payload.Syscall = pathErr.Op
		}
		if payload.Path == "" {
			payload.Path = pathErr.Path
		}
		err = pathErr.Err
	}
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		if payload.Syscall == "" {
			payload.Syscall = linkErr.Op
		}
		if payload.Path == "" {
			payload.Path = linkErr.Old
		}
		if payload.Dest == "" {
			payload.Dest = linkErr.New
		}
		err = linkErr.Err
	}

	var codedErr *hostCodedError
	if errors.As(err, &codedErr) {
		payload.Code = codedErr.code
		payload.Errno = codedErr.errno
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		payload.Errno = -int64(errno)
		payload.Code = errnoCode(errno)
	}
	if payload.Code == "" {
		switch {
		case errors.Is(err, os.ErrNotExist):
			payload.Code = "ENOENT"
		case errors.Is(err, os.ErrExist):
			payload.Code = "EEXIST"
		case errors.Is(err, os.ErrPermission):
			payload.Code = "EACCES"
		case errors.Is(err, os.ErrInvalid):
			payload.Code = "EINVAL"
		}
	}

	return payload
}

func errnoCode(errno syscall.Errno) string {
	switch errno {
	case syscall.ENOENT:
		return "ENOENT"
	case syscall.EEXIST:
		return "EEXIST"
	case syscall.EACCES:
		return "EACCES"
	case syscall.EPERM:
		return "EPERM"
	case syscall.ENOTDIR:
		return "ENOTDIR"
	case syscall.EISDIR:
		return "EISDIR"
	case syscall.EINVAL:
		return "EINVAL"
	case syscall.EBADF:
		return "EBADF"
	default:
		return ""
	}
}

func (s *hostRuntimeState) asyncPoll(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("async poll requires an operation id")
	}
	payload, err := s.async.poll(args[0].Int64())
	if err != nil {
		return nil, err
	}
	return ToJsValue(this.Context(), payload)
}

func (s *hostRuntimeState) asyncCancel(this *This) (*Value, error) {
	if args := this.Args(); len(args) > 0 {
		s.async.cancelJob(args[0].Int64())
	}
	return this.Context().NewUndefined(), nil
}
