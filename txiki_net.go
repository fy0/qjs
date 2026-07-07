package qjs

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
)

type txikiNetState struct {
	mu sync.Mutex

	nextID       int64
	listeners    map[int64]net.Listener
	streams      map[int64]net.Conn
	udpSockets   map[int64]*net.UDPConn
	ownedUnix    map[int64]string
	httpServers  map[int64]*txikiHTTPServer
	httpRequests map[int64]*txikiHTTPRequest
	webSockets   map[int64]*txikiWebSocketConn
}

func newTxikiNetState() *txikiNetState {
	return &txikiNetState{
		listeners:    map[int64]net.Listener{},
		streams:      map[int64]net.Conn{},
		udpSockets:   map[int64]*net.UDPConn{},
		ownedUnix:    map[int64]string{},
		httpServers:  map[int64]*txikiHTTPServer{},
		httpRequests: map[int64]*txikiHTTPRequest{},
		webSockets:   map[int64]*txikiWebSocketConn{},
	}
}

func (s *txikiRuntimeState) installNetHostFunctions(c *Context) {
	c.SetFunc("__qjs_tcp_listen", s.tcpListen)
	c.SetFunc("__qjs_tcp_accept", s.tcpAccept)
	c.SetFunc("__qjs_tcp_connect", s.tcpConnect)
	c.SetFunc("__qjs_tcp_read", s.streamRead)
	c.SetFunc("__qjs_tcp_write", s.streamWrite)
	c.SetFunc("__qjs_tcp_close", s.streamClose)
	c.SetFunc("__qjs_udp_bind", s.udpBind)
	c.SetFunc("__qjs_udp_send", s.udpSend)
	c.SetFunc("__qjs_udp_receive", s.udpReceive)
	c.SetFunc("__qjs_udp_close", s.udpClose)
	c.SetFunc("__qjs_unix_listen", s.unixListen)
	c.SetFunc("__qjs_unix_connect", s.unixConnect)
	c.SetFunc("__qjs_unix_accept", s.tcpAccept)
}

func (n *txikiNetState) close() {
	n.mu.Lock()
	listeners := n.listeners
	streams := n.streams
	udpSockets := n.udpSockets
	ownedUnix := n.ownedUnix
	httpServers := n.httpServers
	webSockets := n.webSockets
	n.listeners = map[int64]net.Listener{}
	n.streams = map[int64]net.Conn{}
	n.udpSockets = map[int64]*net.UDPConn{}
	n.ownedUnix = map[int64]string{}
	n.httpServers = map[int64]*txikiHTTPServer{}
	n.httpRequests = map[int64]*txikiHTTPRequest{}
	n.webSockets = map[int64]*txikiWebSocketConn{}
	n.mu.Unlock()

	for _, server := range httpServers {
		server.close()
	}
	for _, listener := range listeners {
		_ = listener.Close()
	}
	for _, conn := range streams {
		_ = conn.Close()
	}
	for _, conn := range udpSockets {
		_ = conn.Close()
	}
	for _, ws := range webSockets {
		_ = ws.close()
	}
	for _, path := range ownedUnix {
		_ = os.Remove(path)
	}
}

func (n *txikiNetState) nextResourceIDLocked() int64 {
	n.nextID++
	return n.nextID
}

func (n *txikiNetState) addListener(listener net.Listener) int64 {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := n.nextResourceIDLocked()
	n.listeners[id] = listener

	return id
}

func (n *txikiNetState) addStream(conn net.Conn) int64 {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := n.nextResourceIDLocked()
	n.streams[id] = conn

	return id
}

func (n *txikiNetState) addUDPSocket(conn *net.UDPConn) int64 {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := n.nextResourceIDLocked()
	n.udpSockets[id] = conn

	return id
}

func (n *txikiNetState) listener(id int64) (net.Listener, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	listener, ok := n.listeners[id]
	if !ok {
		return nil, fmt.Errorf("listener %d is closed or does not exist", id)
	}

	return listener, nil
}

func (n *txikiNetState) stream(id int64) (net.Conn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	conn, ok := n.streams[id]
	if !ok {
		return nil, fmt.Errorf("stream %d is closed or does not exist", id)
	}

	return conn, nil
}

func (n *txikiNetState) udpSocket(id int64) (*net.UDPConn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	conn, ok := n.udpSockets[id]
	if !ok {
		return nil, fmt.Errorf("udp socket %d is closed or does not exist", id)
	}

	return conn, nil
}

func (n *txikiNetState) closeListener(id int64) error {
	n.mu.Lock()
	listener := n.listeners[id]
	delete(n.listeners, id)
	unixPath := n.ownedUnix[id]
	delete(n.ownedUnix, id)
	n.mu.Unlock()

	if listener == nil {
		return nil
	}

	err := listener.Close()
	if unixPath != "" {
		_ = os.Remove(unixPath)
	}

	return err
}

func (n *txikiNetState) closeStream(id int64) error {
	n.mu.Lock()
	conn := n.streams[id]
	delete(n.streams, id)
	n.mu.Unlock()

	if conn == nil {
		return nil
	}

	return conn.Close()
}

func (n *txikiNetState) closeUDPSocket(id int64) error {
	n.mu.Lock()
	conn := n.udpSockets[id]
	delete(n.udpSockets, id)
	n.mu.Unlock()

	if conn == nil {
		return nil
	}

	return conn.Close()
}

func (s *txikiRuntimeState) tcpListen(this *This) (*Value, error) {
	args := this.Args()
	host := "127.0.0.1"
	if len(args) > 0 && stringsTrim(args[0].String()) != "" {
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

	id := s.net.addListener(listener)
	localHost, localPort := splitAddr(listener.Addr())

	return ToJsValue(this.Context(), map[string]any{
		"id":           id,
		"localAddress": localHost,
		"localPort":    localPort,
	})
}

func (s *txikiRuntimeState) tcpAccept(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("accept requires a listener id")
	}

	listener, err := s.net.listener(args[0].Int64())
	if err != nil {
		return nil, err
	}

	conn, err := listener.Accept()
	if err != nil {
		return nil, err
	}

	id := s.net.addStream(conn)
	localHost, localPort := splitAddr(conn.LocalAddr())
	remoteHost, remotePort := splitAddr(conn.RemoteAddr())

	return ToJsValue(this.Context(), map[string]any{
		"id":            id,
		"localAddress":  localHost,
		"localPort":     localPort,
		"remoteAddress": remoteHost,
		"remotePort":    remotePort,
	})
}

func (s *txikiRuntimeState) tcpConnect(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 2 {
		return nil, errors.New("connect requires host and port")
	}

	host := args[0].String()
	port := args[1].Int64()
	timeout := 30 * time.Second
	if len(args) > 2 && args[2].Int64() > 0 {
		timeout = time.Duration(args[2].Int64()) * time.Millisecond
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.FormatInt(port, 10)), timeout)
	if err != nil {
		return nil, err
	}

	id := s.net.addStream(conn)
	localHost, localPort := splitAddr(conn.LocalAddr())
	remoteHost, remotePort := splitAddr(conn.RemoteAddr())

	return ToJsValue(this.Context(), map[string]any{
		"id":            id,
		"localAddress":  localHost,
		"localPort":     localPort,
		"remoteAddress": remoteHost,
		"remotePort":    remotePort,
	})
}

func (s *txikiRuntimeState) streamRead(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("read requires a stream id")
	}

	maxBytes := int64(65536)
	if len(args) > 1 && args[1].Int64() > 0 {
		maxBytes = args[1].Int64()
	}

	conn, err := s.net.stream(args[0].Int64())
	if err != nil {
		return nil, err
	}

	buf := make([]byte, maxBytes)
	n, err := conn.Read(buf)
	if err != nil {
		if errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
			return this.Context().NewArrayBuffer(nil), nil
		}
		if errors.Is(err, io.EOF) {
			return this.Context().NewArrayBuffer(nil), nil
		}

		return nil, err
	}

	return this.Context().NewArrayBuffer(buf[:n]), nil
}

func (s *txikiRuntimeState) streamWrite(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 2 {
		return nil, errors.New("write requires a stream id and data")
	}

	conn, err := s.net.stream(args[0].Int64())
	if err != nil {
		return nil, err
	}

	data, err := jsValueToBytes(args[1])
	if err != nil {
		return nil, err
	}

	n, err := conn.Write(data)
	if err != nil {
		return nil, err
	}

	return this.Context().NewInt64(int64(n)), nil
}

func (s *txikiRuntimeState) streamClose(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return this.Context().NewUndefined(), nil
	}

	id := args[0].Int64()
	if err := s.net.closeStream(id); err != nil {
		return nil, err
	}
	if err := s.net.closeListener(id); err != nil {
		return nil, err
	}

	return this.Context().NewUndefined(), nil
}

func (s *txikiRuntimeState) udpBind(this *This) (*Value, error) {
	args := this.Args()
	host := "127.0.0.1"
	if len(args) > 0 && stringsTrim(args[0].String()) != "" {
		host = args[0].String()
	}

	port := int64(0)
	if len(args) > 1 {
		port = args[1].Int64()
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.FormatInt(port, 10)))
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	id := s.net.addUDPSocket(conn)
	localHost, localPort := splitAddr(conn.LocalAddr())

	return ToJsValue(this.Context(), map[string]any{
		"id":           id,
		"localAddress": localHost,
		"localPort":    localPort,
	})
}

func (s *txikiRuntimeState) udpSend(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 4 {
		return nil, errors.New("udp send requires socket id, data, host, and port")
	}

	conn, err := s.net.udpSocket(args[0].Int64())
	if err != nil {
		return nil, err
	}

	data, err := jsValueToBytes(args[1])
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(args[2].String(), strconv.FormatInt(args[3].Int64(), 10)))
	if err != nil {
		return nil, err
	}

	n, err := conn.WriteToUDP(data, addr)
	if err != nil {
		return nil, err
	}

	return this.Context().NewInt64(int64(n)), nil
}

func (s *txikiRuntimeState) udpReceive(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("udp receive requires a socket id")
	}

	maxBytes := int64(65536)
	if len(args) > 1 && args[1].Int64() > 0 {
		maxBytes = args[1].Int64()
	}

	conn, err := s.net.udpSocket(args[0].Int64())
	if err != nil {
		return nil, err
	}

	buf := make([]byte, maxBytes)
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}

	return ToJsValue(this.Context(), map[string]any{
		"data":          buf[:n],
		"remoteAddress": addr.IP.String(),
		"remotePort":    addr.Port,
	})
}

func (s *txikiRuntimeState) udpClose(this *This) (*Value, error) {
	args := this.Args()
	if len(args) == 0 {
		return this.Context().NewUndefined(), nil
	}

	if err := s.net.closeUDPSocket(args[0].Int64()); err != nil {
		return nil, err
	}

	return this.Context().NewUndefined(), nil
}

func (s *txikiRuntimeState) unixListen(this *This) (*Value, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("unix sockets are not supported on windows")
	}

	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("unix listen requires a path")
	}

	path, err := s.resolvePath(args[0].String())
	if err != nil {
		return nil, err
	}

	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}

	id := s.net.addListener(listener)
	s.net.mu.Lock()
	s.net.ownedUnix[id] = path
	s.net.mu.Unlock()

	return ToJsValue(this.Context(), map[string]any{
		"id":   id,
		"path": path,
	})
}

func (s *txikiRuntimeState) unixConnect(this *This) (*Value, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("unix sockets are not supported on windows")
	}

	args := this.Args()
	if len(args) == 0 {
		return nil, errors.New("unix connect requires a path")
	}

	path, err := s.resolvePath(args[0].String())
	if err != nil {
		return nil, err
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}

	id := s.net.addStream(conn)

	return ToJsValue(this.Context(), map[string]any{
		"id":   id,
		"path": path,
	})
}

func splitAddr(addr net.Addr) (string, int) {
	if addr == nil {
		return "", 0
	}

	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
	}

	port, _ := strconv.Atoi(portText)

	return host, port
}

func stringsTrim(value string) string {
	for len(value) > 0 && (value[0] == ' ' || value[0] == '\t' || value[0] == '\n' || value[0] == '\r') {
		value = value[1:]
	}
	for len(value) > 0 {
		last := value[len(value)-1]
		if last != ' ' && last != '\t' && last != '\n' && last != '\r' {
			break
		}
		value = value[:len(value)-1]
	}

	return value
}
