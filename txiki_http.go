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
	"time"
)

const webSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type txikiHTTPServer struct {
	id       int64
	server   *http.Server
	listener net.Listener
	requests chan *txikiHTTPRequest
}

type txikiHTTPRequest struct {
	id       int64
	serverID int64
	method   string
	url      string
	path     string
	headers  http.Header
	body     []byte
	ws       bool
	writer   http.ResponseWriter
	request  *http.Request
	response chan txikiHTTPResponse
}

type txikiHTTPResponse struct {
	status        int
	headers       http.Header
	body          []byte
	upgrade       bool
	upgradeResult chan txikiHTTPUpgradeResult
}

type txikiHTTPUpgradeResult struct {
	info map[string]any
	err  error
}

type txikiWebSocketConn struct {
	id       int64
	conn     net.Conn
	isClient bool
	mu       syncMutex
}

type syncMutex struct {
	ch chan struct{}
}

func newSyncMutex() syncMutex {
	return syncMutex{ch: make(chan struct{}, 1)}
}

func (m syncMutex) lock() {
	m.ch <- struct{}{}
}

func (m syncMutex) unlock() {
	<-m.ch
}

func (s *txikiRuntimeState) installHTTPHostFunctions(c *Context) {
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

func (n *txikiNetState) addHTTPServer(server *txikiHTTPServer) int64 {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := n.nextResourceIDLocked()
	server.id = id
	n.httpServers[id] = server

	return id
}

func (n *txikiNetState) httpServer(id int64) (*txikiHTTPServer, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	server, ok := n.httpServers[id]
	if !ok {
		return nil, fmt.Errorf("http server %d is closed or does not exist", id)
	}

	return server, nil
}

func (n *txikiNetState) addHTTPRequest(request *txikiHTTPRequest) int64 {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := n.nextResourceIDLocked()
	request.id = id
	n.httpRequests[id] = request

	return id
}

func (n *txikiNetState) takeHTTPRequest(id int64) (*txikiHTTPRequest, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	request, ok := n.httpRequests[id]
	if !ok {
		return nil, fmt.Errorf("http request %d is already handled or does not exist", id)
	}
	delete(n.httpRequests, id)

	return request, nil
}

func (n *txikiNetState) addWebSocket(ws *txikiWebSocketConn) int64 {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := n.nextResourceIDLocked()
	ws.id = id
	n.webSockets[id] = ws

	return id
}

func (n *txikiNetState) webSocket(id int64) (*txikiWebSocketConn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	ws, ok := n.webSockets[id]
	if !ok {
		return nil, fmt.Errorf("websocket %d is closed or does not exist", id)
	}

	return ws, nil
}

func (n *txikiNetState) closeWebSocket(id int64) error {
	n.mu.Lock()
	ws := n.webSockets[id]
	delete(n.webSockets, id)
	n.mu.Unlock()

	if ws == nil {
		return nil
	}

	return ws.close()
}

func (s *txikiRuntimeState) httpListen(this *This) (*Value, error) {
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

	server := &txikiHTTPServer{
		listener: listener,
		requests: make(chan *txikiHTTPRequest),
	}
	server.server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			server.handle(s, w, r)
		}),
	}

	id := s.net.addHTTPServer(server)
	go func() {
		err := server.server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
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

func (s *txikiRuntimeState) httpAccept(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("http accept requires a server id")
	}

	server, err := s.net.httpServer(args[0].Int64())
	if err != nil {
		return nil, err
	}

	request, ok := <-server.requests
	if !ok {
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

func (s *txikiRuntimeState) httpRespond(this *This) (*Value, error) {
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

	request.response <- txikiHTTPResponse{
		status:  int(args[1].Int64()),
		headers: headers,
		body:    body,
	}

	return this.Context().NewUndefined(), nil
}

func (s *txikiRuntimeState) httpUpgrade(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("http upgrade requires request id")
	}

	request, err := s.net.takeHTTPRequest(args[0].Int64())
	if err != nil {
		return nil, err
	}

	result := make(chan txikiHTTPUpgradeResult, 1)
	request.response <- txikiHTTPResponse{
		upgrade:       true,
		upgradeResult: result,
	}

	upgradeResult := <-result
	if upgradeResult.err != nil {
		return nil, upgradeResult.err
	}

	return ToJsValue(this.Context(), upgradeResult.info)
}

func (s *txikiRuntimeState) httpClose(this *This) (*Value, error) {
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

func (server *txikiHTTPServer) handle(state *txikiRuntimeState, w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	request := &txikiHTTPRequest{
		serverID: server.id,
		method:   r.Method,
		url:      r.URL.String(),
		path:     r.URL.Path,
		headers:  r.Header.Clone(),
		body:     body,
		ws:       isWebSocketRequest(r),
		writer:   w,
		request:  r,
		response: make(chan txikiHTTPResponse, 1),
	}
	state.net.addHTTPRequest(request)

	select {
	case server.requests <- request:
	case <-r.Context().Done():
		state.net.takeHTTPRequestIgnore(request.id)
		return
	}

	response := <-request.response
	if response.upgrade {
		info, err := state.upgradeHTTPRequest(request)
		response.upgradeResult <- txikiHTTPUpgradeResult{info: info, err: err}
		return
	}

	if response.status == 0 {
		response.status = http.StatusOK
	}
	for name, values := range response.headers {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(response.status)
	_, _ = w.Write(response.body)
}

func (n *txikiNetState) takeHTTPRequestIgnore(id int64) {
	n.mu.Lock()
	delete(n.httpRequests, id)
	n.mu.Unlock()
}

func (server *txikiHTTPServer) close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = server.server.Shutdown(ctx)
	_ = server.listener.Close()
	close(server.requests)
}

func parseHTTPHeaders(raw string) (http.Header, error) {
	headers := http.Header{}
	if strings.TrimSpace(raw) == "" {
		return headers, nil
	}

	var values map[string][]string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, err
	}

	for name, list := range values {
		for _, value := range list {
			headers.Add(name, value)
		}
	}

	return headers, nil
}

func isWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") &&
		r.Header.Get("Sec-WebSocket-Key") != ""
}

func (s *txikiRuntimeState) upgradeHTTPRequest(request *txikiHTTPRequest) (map[string]any, error) {
	if !request.ws {
		return nil, errors.New("request is not a websocket upgrade")
	}

	hijacker, ok := request.writer.(http.Hijacker)
	if !ok {
		return nil, errors.New("http response writer does not support hijacking")
	}

	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}

	accept := computeWebSocketAccept(request.request.Header.Get("Sec-WebSocket-Key"))
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := rw.WriteString(response); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	ws := &txikiWebSocketConn{conn: conn, mu: newSyncMutex()}
	id := s.net.addWebSocket(ws)

	return map[string]any{
		"id":   id,
		"url":  request.url,
		"path": request.path,
	}, nil
}

func (s *txikiRuntimeState) wsConnect(this *This) (*Value, error) {
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

	ws := &txikiWebSocketConn{conn: conn, isClient: true, mu: newSyncMutex()}
	id := s.net.addWebSocket(ws)

	return ToJsValue(this.Context(), map[string]any{
		"id":  id,
		"url": rawURL,
	})
}

func (s *txikiRuntimeState) wsRead(this *This) (*Value, error) {
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

func (s *txikiRuntimeState) wsSend(this *This) (*Value, error) {
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

func (s *txikiRuntimeState) wsClose(this *This) (*Value, error) {
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

func (ws *txikiWebSocketConn) readMessage() (byte, []byte, error) {
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

func (ws *txikiWebSocketConn) readFrame() (byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(ws.conn, header); err != nil {
		return 0, nil, err
	}

	opcode := header[0] & 0x0f
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7f)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(ws.conn, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(ws.conn, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(ws.conn, mask[:]); err != nil {
			return 0, nil, err
		}
	}

	if length > 32*1024*1024 {
		return 0, nil, errors.New("websocket frame is too large")
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(ws.conn, payload); err != nil {
		return 0, nil, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}

	return opcode, payload, nil
}

func (ws *txikiWebSocketConn) writeFrame(opcode byte, payload []byte) error {
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

	if _, err := ws.conn.Write(header.Bytes()); err != nil {
		return err
	}
	_, err := ws.conn.Write(out)

	return err
}

func (ws *txikiWebSocketConn) close() error {
	_ = ws.writeFrame(8, nil)
	return ws.conn.Close()
}
