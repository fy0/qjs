package qjs

import (
	"bufio"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

const webSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type hostHTTPServer struct {
	id        int64
	server    *fasthttp.Server
	listener  net.Listener
	requests  chan *hostHTTPRequest
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

type hostHTTPRequest struct {
	id       int64
	serverID int64
	method   string
	url      string
	path     string
	headers  map[string][]string
	body     []byte
	ws       bool
	ctx      *fasthttp.RequestCtx
	response chan hostHTTPResponse
}

type hostHTTPResponse struct {
	status        int
	headers       map[string][]string
	body          []byte
	upgrade       bool
	upgradeResult chan hostHTTPUpgradeResult
}

type hostHTTPUpgradeResult struct {
	info map[string]any
	err  error
}

type hostWebSocketConn struct {
	id       int64
	conn     net.Conn
	isClient bool
	mu       syncMutex
	ready    chan struct{}
	done     chan struct{}
	err      error
	once     sync.Once
}

type syncMutex struct {
	ch chan struct{}
}

func newSyncMutex() syncMutex {
	return syncMutex{ch: make(chan struct{}, 1)}
}

func newHostWebSocketConn(conn net.Conn, isClient bool) *hostWebSocketConn {
	ws := &hostWebSocketConn{
		conn:     conn,
		isClient: isClient,
		mu:       newSyncMutex(),
		ready:    make(chan struct{}),
		done:     make(chan struct{}),
	}
	if conn != nil {
		close(ws.ready)
	}

	return ws
}

func (ws *hostWebSocketConn) setConn(conn net.Conn) {
	ws.conn = conn
	close(ws.ready)
}

func (ws *hostWebSocketConn) fail(err error) {
	ws.err = err
	close(ws.ready)
	ws.closeDone()
}

func (ws *hostWebSocketConn) waitConn() (net.Conn, error) {
	<-ws.ready
	if ws.err != nil {
		return nil, ws.err
	}
	if ws.conn == nil {
		return nil, net.ErrClosed
	}

	return ws.conn, nil
}

func (ws *hostWebSocketConn) closeDone() {
	ws.once.Do(func() {
		close(ws.done)
	})
}

func (m syncMutex) lock() {
	m.ch <- struct{}{}
}

func (m syncMutex) unlock() {
	<-m.ch
}

func (s *hostRuntimeState) installHTTPHostFunctions(c *Context) {
	c.SetFunc("__qjs_http_listen", s.httpListen)
	c.SetFunc("__qjs_http_accept", s.httpAccept)
	c.SetFunc("__qjs_http_respond", s.httpRespond)
	c.SetFunc("__qjs_http_upgrade", s.httpUpgrade)
	c.SetFunc("__qjs_http_close", s.httpClose)
	c.SetFunc("__qjs_ws_connect", s.wsConnect)
	c.SetFunc("__qjs_ws_read", s.wsRead)
	c.SetFunc("__qjs_ws_send", s.wsSend)
	c.SetFunc("__qjs_ws_close", s.wsClose)
}

func (n *hostNetState) addHTTPServer(server *hostHTTPServer) int64 {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := n.nextResourceIDLocked()
	server.id = id
	n.httpServers[id] = server

	return id
}

func (n *hostNetState) httpServer(id int64) (*hostHTTPServer, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	server, ok := n.httpServers[id]
	if !ok {
		return nil, fmt.Errorf("http server %d is closed or does not exist", id)
	}

	return server, nil
}

func (n *hostNetState) addHTTPRequest(request *hostHTTPRequest) int64 {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := n.nextResourceIDLocked()
	request.id = id
	n.httpRequests[id] = request

	return id
}

func (n *hostNetState) takeHTTPRequest(id int64) (*hostHTTPRequest, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	request, ok := n.httpRequests[id]
	if !ok {
		return nil, fmt.Errorf("http request %d is already handled or does not exist", id)
	}
	delete(n.httpRequests, id)

	return request, nil
}

func (n *hostNetState) addWebSocket(ws *hostWebSocketConn) int64 {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := n.nextResourceIDLocked()
	ws.id = id
	n.webSockets[id] = ws

	return id
}

func (n *hostNetState) webSocket(id int64) (*hostWebSocketConn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	ws, ok := n.webSockets[id]
	if !ok {
		return nil, fmt.Errorf("websocket %d is closed or does not exist", id)
	}

	return ws, nil
}

func (n *hostNetState) closeWebSocket(id int64) error {
	n.mu.Lock()
	ws := n.webSockets[id]
	delete(n.webSockets, id)
	n.mu.Unlock()

	if ws == nil {
		return nil
	}

	return ws.close()
}

func (s *hostRuntimeState) httpListen(this *This) (*Value, error) {
	args := this.Args()
	host := "127.0.0.1"
	if len(args) > 0 && strings.TrimSpace(args[0].String()) != "" {
		host = args[0].String()
	}

	port := int64(0)
	if len(args) > 1 {
		port = args[1].Int64()
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.FormatInt(port, 10)))
	if err != nil {
		return nil, err
	}

	serverCtx, cancel := context.WithCancel(s.async.ctx)
	server := &hostHTTPServer{
		listener: listener,
		requests: make(chan *hostHTTPRequest),
		ctx:      serverCtx,
		cancel:   cancel,
	}
	server.server = &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			server.handle(s, ctx)
		},
	}

	id := s.net.addHTTPServer(server)
	go func() {
		err := server.server.Serve(listener)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			_ = err
		}
	}()

	localHost, localPort := splitAddr(listener.Addr())

	return ToJsValue(this.Context(), map[string]any{
		"id":           id,
		"localAddress": localHost,
		"localPort":    localPort,
	})
}

func (s *hostRuntimeState) httpAccept(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("http accept requires a server id")
	}

	server, err := s.net.httpServer(args[0].Int64())
	if err != nil {
		return nil, err
	}

	var request *hostHTTPRequest
	select {
	case request = <-server.requests:
	case <-server.ctx.Done():
		return nil, errors.New("http server is closed")
	}
	if request == nil {
		return nil, errors.New("http server is closed")
	}

	return ToJsValue(this.Context(), map[string]any{
		"id":        request.id,
		"serverId":  request.serverID,
		"method":    request.method,
		"url":       request.url,
		"path":      request.path,
		"headers":   map[string][]string(request.headers),
		"body":      request.body,
		"websocket": request.ws,
	})
}

func (s *hostRuntimeState) httpRespond(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 4 {
		return nil, errors.New("http respond requires request id, status, headers, and body")
	}

	request, err := s.net.takeHTTPRequest(args[0].Int64())
	if err != nil {
		return nil, err
	}

	headers, err := parseHTTPHeaders(args[2].String())
	if err != nil {
		return nil, err
	}

	body, err := jsValueToBytes(args[3])
	if err != nil {
		return nil, err
	}

	request.response <- hostHTTPResponse{
		status:  int(args[1].Int64()),
		headers: headers,
		body:    body,
	}

	return this.Context().NewUndefined(), nil
}

func (s *hostRuntimeState) httpUpgrade(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("http upgrade requires request id")
	}

	request, err := s.net.takeHTTPRequest(args[0].Int64())
	if err != nil {
		return nil, err
	}

	result := make(chan hostHTTPUpgradeResult, 1)
	request.response <- hostHTTPResponse{
		upgrade:       true,
		upgradeResult: result,
	}

	upgradeResult := <-result
	if upgradeResult.err != nil {
		return nil, upgradeResult.err
	}

	return ToJsValue(this.Context(), upgradeResult.info)
}

func (s *hostRuntimeState) httpClose(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return this.Context().NewUndefined(), nil
	}

	s.net.mu.Lock()
	server := s.net.httpServers[args[0].Int64()]
	delete(s.net.httpServers, args[0].Int64())
	s.net.mu.Unlock()

	if server != nil {
		server.close()
	}

	return this.Context().NewUndefined(), nil
}

func (server *hostHTTPServer) handle(state *hostRuntimeState, ctx *fasthttp.RequestCtx) {
	body := append([]byte(nil), ctx.PostBody()...)
	headers := map[string][]string{}
	ctx.Request.Header.VisitAll(func(key, value []byte) {
		name := string(key)
		headers[name] = append(headers[name], string(value))
	})
	request := &hostHTTPRequest{
		serverID: server.id,
		method:   string(ctx.Method()),
		url:      ctx.URI().String(),
		path:     string(ctx.Path()),
		headers:  headers,
		body:     body,
		ws:       isWebSocketRequest(ctx),
		ctx:      ctx,
		response: make(chan hostHTTPResponse, 1),
	}
	state.net.addHTTPRequest(request)

	select {
	case server.requests <- request:
	case <-server.ctx.Done():
		state.net.takeHTTPRequestIgnore(request.id)
		return
	case <-ctx.Done():
		state.net.takeHTTPRequestIgnore(request.id)
		return
	}

	var response hostHTTPResponse
	select {
	case response = <-request.response:
	case <-server.ctx.Done():
		state.net.takeHTTPRequestIgnore(request.id)
		return
	case <-ctx.Done():
		state.net.takeHTTPRequestIgnore(request.id)
		return
	}
	if response.upgrade {
		info, err := state.upgradeHTTPRequest(request)
		response.upgradeResult <- hostHTTPUpgradeResult{info: info, err: err}
		return
	}

	if response.status == 0 {
		response.status = fasthttp.StatusOK
	}
	for name, values := range response.headers {
		for _, value := range values {
			ctx.Response.Header.Add(name, value)
		}
	}
	ctx.SetStatusCode(response.status)
	ctx.SetBody(response.body)
}

func (n *hostNetState) takeHTTPRequestIgnore(id int64) {
	n.mu.Lock()
	delete(n.httpRequests, id)
	n.mu.Unlock()
}

func (server *hostHTTPServer) close() {
	server.closeOnce.Do(func() {
		server.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.listener.Close()
		_ = server.server.ShutdownWithContext(ctx)
	})
}

func parseHTTPHeaders(raw string) (map[string][]string, error) {
	headers := map[string][]string{}
	if strings.TrimSpace(raw) == "" {
		return headers, nil
	}

	var values map[string][]string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, err
	}

	for name, list := range values {
		for _, value := range list {
			headers[name] = append(headers[name], value)
		}
	}

	return headers, nil
}

func isWebSocketRequest(ctx *fasthttp.RequestCtx) bool {
	return strings.EqualFold(string(ctx.Request.Header.Peek("Upgrade")), "websocket") &&
		strings.Contains(strings.ToLower(string(ctx.Request.Header.Peek("Connection"))), "upgrade") &&
		len(ctx.Request.Header.Peek("Sec-WebSocket-Key")) > 0
}

func (s *hostRuntimeState) upgradeHTTPRequest(request *hostHTTPRequest) (map[string]any, error) {
	if !request.ws {
		return nil, errors.New("request is not a websocket upgrade")
	}

	accept := computeWebSocketAccept(string(request.ctx.Request.Header.Peek("Sec-WebSocket-Key")))
	ws := newHostWebSocketConn(nil, false)
	id := s.net.addWebSocket(ws)
	request.ctx.HijackSetNoResponse(true)
	request.ctx.Hijack(func(conn net.Conn) {
		response := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		if _, err := io.WriteString(conn, response); err != nil {
			ws.fail(err)
			_ = conn.Close()
			return
		}
		ws.setConn(conn)
		<-ws.done
	})

	return map[string]any{
		"id":   id,
		"url":  request.url,
		"path": request.path,
	}, nil
}

func (s *hostRuntimeState) wsConnect(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("websocket connect requires a url")
	}

	rawURL := args[0].String()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "ws" {
		return nil, errors.New("only ws:// websocket URLs are currently supported")
	}

	host := parsed.Host
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "80")
	}

	conn, err := net.DialTimeout("tcp", host, 30*time.Second)
	if err != nil {
		return nil, err
	}

	keyBytes := make([]byte, 16)
	if _, err := cryptorand.Read(keyBytes); err != nil {
		_ = conn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	path := parsed.RequestURI()
	if path == "" {
		path = "/"
	}

	request := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + parsed.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		_ = conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = conn.Close()
		return nil, fmt.Errorf("websocket upgrade failed with status %d", resp.StatusCode)
	}

	expectedAccept := computeWebSocketAccept(key)
	if resp.Header.Get("Sec-WebSocket-Accept") != expectedAccept {
		_ = conn.Close()
		return nil, errors.New("websocket upgrade returned invalid accept key")
	}

	ws := newHostWebSocketConn(conn, true)
	id := s.net.addWebSocket(ws)

	return ToJsValue(this.Context(), map[string]any{
		"id":  id,
		"url": rawURL,
	})
}

func (s *hostRuntimeState) wsRead(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("websocket read requires a socket id")
	}

	ws, err := s.net.webSocket(args[0].Int64())
	if err != nil {
		return nil, err
	}

	opcode, payload, err := ws.readMessage()
	if err != nil {
		return nil, err
	}

	return ToJsValue(this.Context(), map[string]any{
		"opcode": opcode,
		"text":   string(payload),
		"data":   payload,
	})
}

func (s *hostRuntimeState) wsSend(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 2 {
		return nil, errors.New("websocket send requires socket id and data")
	}

	ws, err := s.net.webSocket(args[0].Int64())
	if err != nil {
		return nil, err
	}

	data, err := jsValueToBytes(args[1])
	if err != nil {
		return nil, err
	}

	opcode := byte(1)
	if len(args) > 2 && args[2].Bool() {
		opcode = 2
	}

	if err := ws.writeFrame(opcode, data); err != nil {
		return nil, err
	}

	return this.Context().NewUndefined(), nil
}

func (s *hostRuntimeState) wsClose(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return this.Context().NewUndefined(), nil
	}

	_ = s.net.closeWebSocket(args[0].Int64())

	return this.Context().NewUndefined(), nil
}

func computeWebSocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + webSocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func (ws *hostWebSocketConn) readMessage() (byte, []byte, error) {
	for {
		opcode, payload, err := ws.readFrame()
		if err != nil {
			return 0, nil, err
		}

		switch opcode {
		case 1, 2:
			return opcode, payload, nil
		case 8:
			_ = ws.close()
			return opcode, payload, io.EOF
		case 9:
			_ = ws.writeFrame(10, payload)
		}
	}
}

func (ws *hostWebSocketConn) readFrame() (byte, []byte, error) {
	conn, err := ws.waitConn()
	if err != nil {
		return 0, nil, err
	}

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}

	opcode := header[0] & 0x0f
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7f)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(conn, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(conn, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(conn, mask[:]); err != nil {
			return 0, nil, err
		}
	}

	if length > 32*1024*1024 {
		return 0, nil, errors.New("websocket frame is too large")
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}

	return opcode, payload, nil
}

func (ws *hostWebSocketConn) writeFrame(opcode byte, payload []byte) error {
	conn, err := ws.waitConn()
	if err != nil {
		return err
	}

	ws.mu.lock()
	defer ws.mu.unlock()

	var header bytes.Buffer
	header.WriteByte(0x80 | opcode)
	maskBit := byte(0)
	if ws.isClient {
		maskBit = 0x80
	}

	switch {
	case len(payload) < 126:
		header.WriteByte(maskBit | byte(len(payload)))
	case len(payload) <= 65535:
		header.WriteByte(maskBit | 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(len(payload)))
		header.Write(ext[:])
	default:
		header.WriteByte(maskBit | 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(len(payload)))
		header.Write(ext[:])
	}

	out := payload
	if ws.isClient {
		var mask [4]byte
		if _, err := cryptorand.Read(mask[:]); err != nil {
			return err
		}
		header.Write(mask[:])
		out = append([]byte(nil), payload...)
		for i := range out {
			out[i] ^= mask[i%4]
		}
	}

	if _, err := conn.Write(header.Bytes()); err != nil {
		return err
	}
	_, err = conn.Write(out)

	return err
}

func (ws *hostWebSocketConn) close() error {
	if ws == nil {
		return nil
	}

	conn, err := ws.waitConn()
	if err != nil {
		ws.closeDone()
		return err
	}

	_ = ws.writeFrame(8, nil)
	closeErr := conn.Close()
	ws.closeDone()

	return closeErr
}
