package qjs

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
)

const maxFetchRedirects = 20

type hostFetchState struct {
	ctx    context.Context
	cancel context.CancelFunc
	client *http.Client

	mu     sync.Mutex
	nextID int64
	bodies map[int64]*hostFetchBody
	closed bool
}

type hostFetchBody struct {
	body   io.ReadCloser
	cancel context.CancelFunc
	readMu sync.Mutex
	once   sync.Once
}

type hostFetchRequest struct {
	URL      string
	Method   string
	Headers  http.Header
	Body     []byte
	Redirect string
}

func newHostFetchState(parent context.Context, client *http.Client) *hostFetchState {
	ctx, cancel := context.WithCancel(parent)
	if client == nil {
		client = &http.Client{}
	}
	return &hostFetchState{
		ctx:    ctx,
		cancel: cancel,
		client: client,
		bodies: make(map[int64]*hostFetchBody),
	}
}

func (f *hostFetchState) addBody(body io.ReadCloser, cancel context.CancelFunc) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		_ = body.Close()
		cancel()
		return 0, errors.New("host runtime is closed")
	}
	f.nextID++
	f.bodies[f.nextID] = &hostFetchBody{body: body, cancel: cancel}
	return f.nextID, nil
}

func (f *hostFetchState) body(id int64) (*hostFetchBody, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body := f.bodies[id]
	if body == nil {
		return nil, fmt.Errorf("fetch response body %d is closed", id)
	}
	return body, nil
}

func (f *hostFetchState) closeBody(id int64) {
	f.mu.Lock()
	body := f.bodies[id]
	delete(f.bodies, id)
	f.mu.Unlock()
	if body != nil {
		body.close()
	}
}

func (b *hostFetchBody) close() {
	b.once.Do(func() {
		b.cancel()
		_ = b.body.Close()
	})
}

func (f *hostFetchState) close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	bodies := f.bodies
	f.bodies = make(map[int64]*hostFetchBody)
	f.mu.Unlock()
	f.cancel()
	for _, body := range bodies {
		body.close()
	}
}

func (s *hostRuntimeState) fetchStart(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 5 {
		return nil, errors.New("fetch requires url, method, headers, body, and redirect mode")
	}
	request := hostFetchRequest{
		URL:      args[0].String(),
		Method:   strings.ToUpper(strings.TrimSpace(args[1].String())),
		Headers:  make(http.Header),
		Redirect: args[4].String(),
	}
	if request.Method == "" {
		request.Method = http.MethodGet
	}
	if request.Redirect == "" {
		request.Redirect = "follow"
	}
	if raw := args[2].String(); raw != "" {
		var headers map[string][]string
		if err := json.Unmarshal([]byte(raw), &headers); err != nil {
			return nil, fmt.Errorf("invalid fetch headers: %w", err)
		}
		for name, values := range headers {
			for _, value := range values {
				request.Headers.Add(name, value)
			}
		}
	}
	if !args[3].IsNull() && !args[3].IsUndefined() {
		body, err := jsValueToBytes(args[3])
		if err != nil {
			return nil, err
		}
		request.Body = body
	}

	id, err := s.async.start(func(ctx context.Context) (any, error) {
		return s.doHostFetch(ctx, request)
	})
	if err != nil {
		return nil, err
	}
	return this.Context().NewInt64(id), nil
}

func (s *hostRuntimeState) doHostFetch(jobCtx context.Context, request hostFetchRequest) (map[string]any, error) {
	parsed, err := url.Parse(request.URL)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "data" {
		return s.fetchDataURL(parsed)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported fetch protocol %q", parsed.Scheme)
	}

	requestCtx, cancel := context.WithCancel(s.fetchState.ctx)
	stopBridge := make(chan struct{})
	go func() {
		select {
		case <-jobCtx.Done():
			cancel()
		case <-stopBridge:
		}
	}()

	client := *s.fetchState.client
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	currentURL := parsed
	method := request.Method
	body := request.Body
	headers := request.Headers.Clone()
	redirected := false

	for redirects := 0; redirects <= maxFetchRedirects; redirects++ {
		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(requestCtx, method, currentURL.String(), bodyReader)
		if err != nil {
			close(stopBridge)
			cancel()
			return nil, err
		}
		req.Header = headers.Clone()
		if req.Header.Get("Accept-Encoding") == "" {
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		}
		resp, err := client.Do(req)
		if err != nil {
			close(stopBridge)
			cancel()
			return nil, err
		}

		if isHTTPRedirect(resp.StatusCode) && resp.Header.Get("Location") != "" {
			switch request.Redirect {
			case "manual":
				return s.finishFetchResponse(resp, cancel, stopBridge, redirected)
			case "error":
				_ = resp.Body.Close()
				close(stopBridge)
				cancel()
				return nil, errors.New("redirect mode is set to error")
			case "follow":
			default:
				_ = resp.Body.Close()
				close(stopBridge)
				cancel()
				return nil, fmt.Errorf("invalid redirect mode %q", request.Redirect)
			}
			if redirects == maxFetchRedirects {
				_ = resp.Body.Close()
				close(stopBridge)
				cancel()
				return nil, errors.New("fetch stopped after too many redirects")
			}
			nextURL, err := currentURL.Parse(resp.Header.Get("Location"))
			_, _ = io.CopyN(io.Discard, resp.Body, 4096)
			_ = resp.Body.Close()
			if err != nil {
				close(stopBridge)
				cancel()
				return nil, err
			}
			if shouldRedirectToGet(resp.StatusCode, method) {
				method = http.MethodGet
				body = nil
				headers.Del("Content-Length")
				headers.Del("Content-Type")
				headers.Del("Transfer-Encoding")
			}
			if !sameOrigin(currentURL, nextURL) {
				headers.Del("Authorization")
				headers.Del("Cookie")
				headers.Del("Proxy-Authorization")
			}
			currentURL = nextURL
			redirected = true
			continue
		}

		return s.finishFetchResponse(resp, cancel, stopBridge, redirected)
	}

	close(stopBridge)
	cancel()
	return nil, errors.New("fetch stopped after too many redirects")
}

func (s *hostRuntimeState) finishFetchResponse(
	resp *http.Response,
	cancel context.CancelFunc,
	stopBridge chan struct{},
	redirected bool,
) (map[string]any, error) {
	body, err := decodeResponseBody(resp)
	if err != nil {
		_ = resp.Body.Close()
		close(stopBridge)
		cancel()
		return nil, err
	}
	bodyID, err := s.fetchState.addBody(body, cancel)
	if err != nil {
		close(stopBridge)
		return nil, err
	}
	close(stopBridge)
	headers := make(map[string][]string, len(resp.Header))
	for name, values := range resp.Header {
		headers[name] = append([]string(nil), values...)
	}
	return map[string]any{
		"url":        resp.Request.URL.String(),
		"status":     resp.StatusCode,
		"statusText": http.StatusText(resp.StatusCode),
		"headers":    headers,
		"bodyId":     bodyID,
		"redirected": redirected,
	}, nil
}

func decodeResponseBody(resp *http.Response) (io.ReadCloser, error) {
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	switch encoding {
	case "", "identity":
		return resp.Body, nil
	case "gzip":
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		return &combinedReadCloser{Reader: reader, closers: []io.Closer{reader, resp.Body}}, nil
	case "deflate":
		reader, err := zlib.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		return &combinedReadCloser{Reader: reader, closers: []io.Closer{reader, resp.Body}}, nil
	case "deflate-raw":
		reader := flate.NewReader(resp.Body)
		return &combinedReadCloser{Reader: reader, closers: []io.Closer{reader, resp.Body}}, nil
	case "br":
		return &combinedReadCloser{Reader: brotli.NewReader(resp.Body), closers: []io.Closer{resp.Body}}, nil
	default:
		return resp.Body, nil
	}
}

type combinedReadCloser struct {
	io.Reader
	closers []io.Closer
}

func (r *combinedReadCloser) Close() error {
	var result error
	for _, closer := range r.closers {
		result = errors.Join(result, closer.Close())
	}
	return result
}

func (s *hostRuntimeState) fetchDataURL(parsed *url.URL) (map[string]any, error) {
	raw := strings.TrimPrefix(parsed.String(), "data:")
	meta, encoded, ok := strings.Cut(raw, ",")
	if !ok {
		return nil, errors.New("invalid data URL")
	}
	mediaType := meta
	var data []byte
	var err error
	if strings.HasSuffix(strings.ToLower(meta), ";base64") {
		mediaType = meta[:len(meta)-7]
		data, err = base64.StdEncoding.DecodeString(encoded)
	} else {
		var decoded string
		decoded, err = url.PathUnescape(encoded)
		data = []byte(decoded)
	}
	if err != nil {
		return nil, err
	}
	if mediaType == "" {
		mediaType = "text/plain;charset=US-ASCII"
	}
	_, cancel := context.WithCancel(s.fetchState.ctx)
	bodyID, err := s.fetchState.addBody(io.NopCloser(bytes.NewReader(data)), cancel)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"url":        parsed.String(),
		"status":     http.StatusOK,
		"statusText": http.StatusText(http.StatusOK),
		"headers":    map[string][]string{"Content-Type": []string{mediaType}, "Content-Length": []string{strconv.Itoa(len(data))}},
		"bodyId":     bodyID,
		"redirected": false,
	}, nil
}

func (s *hostRuntimeState) fetchBodyReadStart(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("fetch body id is required")
	}
	bodyID := args[0].Int64()
	maxBytes := int64(64 << 10)
	if len(args) > 1 && args[1].Int64() > 0 {
		maxBytes = args[1].Int64()
	}
	if maxBytes > 1<<20 {
		maxBytes = 1 << 20
	}
	body, err := s.fetchState.body(bodyID)
	if err != nil {
		return nil, err
	}
	id, err := s.async.start(func(ctx context.Context) (any, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		body.readMu.Lock()
		buf := make([]byte, maxBytes)
		n, readErr := body.body.Read(buf)
		body.readMu.Unlock()
		if n > 0 {
			final := errors.Is(readErr, io.EOF)
			if final {
				s.fetchState.closeBody(bodyID)
			}
			return map[string]any{"done": false, "final": final, "data": buf[:n]}, nil
		}
		if errors.Is(readErr, io.EOF) {
			s.fetchState.closeBody(bodyID)
			return map[string]any{"done": true, "data": []byte{}}, nil
		}
		if readErr != nil {
			s.fetchState.closeBody(bodyID)
			return nil, readErr
		}
		return map[string]any{"done": false, "final": false, "data": buf[:n]}, nil
	})
	if err != nil {
		return nil, err
	}
	return this.Context().NewInt64(id), nil
}

func (s *hostRuntimeState) fetchBodyClose(this *This) (*Value, error) {
	if args := this.Args(); len(args) > 0 {
		s.fetchState.closeBody(args[0].Int64())
	}
	return this.Context().NewUndefined(), nil
}

func isHTTPRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func shouldRedirectToGet(status int, method string) bool {
	if status == http.StatusSeeOther {
		return method != http.MethodGet && method != http.MethodHead
	}
	return (status == http.StatusMovedPermanently || status == http.StatusFound) && method == http.MethodPost
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(canonicalURLHost(a), canonicalURLHost(b))
}

func canonicalURLHost(value *url.URL) string {
	host := value.Hostname()
	port := value.Port()
	if port == "" {
		if value.Scheme == "http" {
			port = "80"
		} else if value.Scheme == "https" {
			port = "443"
		}
	}
	return strings.ToLower(host) + ":" + port
}
