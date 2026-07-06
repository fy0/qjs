package qjs_test

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/fastschema/qjs"
	"github.com/stretchr/testify/require"
)

func TestInstallTxikiRuntimeCoreAPIs(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	rt := must(qjs.New(qjs.Option{
		CWD:    t.TempDir(),
		Stdout: &stdout,
		Stderr: &stderr,
	}))
	defer rt.Close()

	require.NoError(t, rt.InstallTxikiRuntime())

	result, err := rt.Eval("txiki-core.js", qjs.Code(`
		export default await (async () => {
			console.log("hello", { api: "console" });
			qjs.fs.mkdir("nested", { recursive: true });
			qjs.fs.writeFile("nested/hello.txt", "world");
			const text = qjs.fs.readFile("nested/hello.txt", "utf8");
			const names = qjs.fs.readdir("nested");
			const stat = qjs.fs.stat("nested/hello.txt");

			const random = new Uint8Array(8);
			crypto.getRandomValues(random);
			const digest = await crypto.subtle.digest("SHA-256", new Uint8Array([97, 98, 99]));
			const digestHex = Array.from(new Uint8Array(digest)).map(v => v.toString(16).padStart(2, "0")).join("");
			const timerValue = await new Promise(resolve => setTimeout(() => resolve(42), 1));

			return {
				text,
				names,
				isFile: stat.isFile,
				randomLength: random.byteLength,
				uuidLength: crypto.randomUUID().length,
				digestHex,
				timerValue
			};
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()
	require.True(t, result.IsObject(), "result type=%s string=%q", result.Type(), result.String())

	text := result.GetPropertyStr("text")
	defer text.Free()
	require.Equal(t, "world", text.String())
	names := result.GetPropertyStr("names")
	defer names.Free()
	require.Equal(t, `["hello.txt"]`, must(names.JSONStringify()))
	isFile := result.GetPropertyStr("isFile")
	defer isFile.Free()
	require.True(t, isFile.Bool())
	randomLength := result.GetPropertyStr("randomLength")
	defer randomLength.Free()
	require.Equal(t, int32(8), randomLength.Int32())
	uuidLength := result.GetPropertyStr("uuidLength")
	defer uuidLength.Free()
	require.Equal(t, int32(36), uuidLength.Int32())
	digestHex := result.GetPropertyStr("digestHex")
	defer digestHex.Free()
	require.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", digestHex.String())
	timerValue := result.GetPropertyStr("timerValue")
	defer timerValue.Free()
	require.Equal(t, int32(42), timerValue.Int32())
	require.Contains(t, stdout.String(), "hello")
	require.Empty(t, stderr.String())
}

func TestInstallTxikiRuntimeFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "yes", r.Header.Get("X-Test"))
		w.Header().Set("X-Reply", "ok")
		_, _ = w.Write([]byte(`{"body":` + string(must(json.Marshal(string(body)))) + `}`))
	}))
	defer server.Close()

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallTxikiRuntime())

	serverURL := must(json.Marshal(server.URL))
	result, err := rt.Eval("txiki-fetch.js", qjs.Code(`
		export default await (async () => {
			const res = await fetch(`+string(serverURL)+`, {
				method: "POST",
				headers: { "X-Test": "yes" },
				body: "ping"
			});
			const body = await res.json();
			return {
				ok: res.ok,
				status: res.status,
				reply: res.headers.get("x-reply"),
				body: body.body
			};
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()

	jsonResult := must(result.JSONStringify())
	require.Contains(t, jsonResult, `"ok":true`)
	require.Contains(t, jsonResult, `"status":200`)
	require.Contains(t, jsonResult, `"reply":"ok"`)
	require.Contains(t, jsonResult, `"body":"ping"`)
}

func TestInstallTxikiRuntimeWebPlatformEvents(t *testing.T) {
	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallTxikiRuntime())

	result, err := rt.Eval("txiki-events.js", qjs.Code(`
		export default await (async () => {
			const target = new EventTarget();
			let eventSeen = "";
			target.addEventListener("ready", event => {
				eventSeen = event.type + ":" + event.target.constructor.name;
			});
			target.dispatchEvent(new Event("ready"));

			const controller = new AbortController();
			let abortSeen = false;
			controller.signal.addEventListener("abort", () => abortSeen = true);
			controller.abort("stop");

			let fetchAbort = "";
			try {
				await fetch("http://127.0.0.1:1", { signal: controller.signal });
			} catch (error) {
				fetchAbort = String(error);
			}

			return {
				eventSeen,
				abortSeen,
				aborted: controller.signal.aborted,
				reason: controller.signal.reason,
				fetchAbort
			};
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()

	jsonResult := must(result.JSONStringify())
	require.Contains(t, jsonResult, `"eventSeen":"ready:EventTarget"`)
	require.Contains(t, jsonResult, `"abortSeen":true`)
	require.Contains(t, jsonResult, `"aborted":true`)
	require.Contains(t, jsonResult, `"reason":"stop"`)
	require.Contains(t, jsonResult, `"fetchAbort":"stop"`)
}

func TestInstallTxikiRuntimeWebPlatformUtilities(t *testing.T) {
	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallTxikiRuntime())

	result, err := rt.Eval("txiki-web-utils.js", qjs.Code(`
		export default await (async () => {
			const encoded = new TextEncoder().encode("hello 世界");
			const decoded = new TextDecoder().decode(encoded);

			let microtask = "before";
			queueMicrotask(() => microtask = "after");
			await Promise.resolve();

			const original = { nested: { value: 1 }, bytes: new Uint8Array([1, 2, 3]) };
			const cloned = structuredClone(original);
			original.nested.value = 9;
			original.bytes[0] = 9;

			const blob = new Blob(["hello", new Uint8Array([32, 119, 111, 114, 108, 100])], { type: "text/plain" });
			const file = new File([blob], "greeting.txt", { type: "text/plain", lastModified: 123 });
			const form = new FormData();
			form.append("a", 1);
			form.append("a", "two");
			form.append("file", blob, "blob.txt");

			const params = new URLSearchParams("?b=two&a=one&a=again");
			params.sort();

			return {
				decoded,
				base64: atob(btoa("hello")),
				microtask,
				nowType: typeof performance.now(),
				cloneValue: cloned.nested.value,
				cloneByte: cloned.bytes[0],
				blobText: await blob.text(),
				blobSize: blob.size,
				blobType: blob.type,
				sliceText: await blob.slice(6).text(),
				fileName: file.name,
				fileLastModified: file.lastModified,
				formA: form.getAll("a").join(","),
				formFileName: form.get("file").name,
				params: params.toString(),
				selfIsGlobal: self === globalThis
			};
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()
	require.True(t, result.IsObject(), "result type=%s string=%q", result.Type(), result.String())

	assertPropString := func(name, expected string) {
		prop := result.GetPropertyStr(name)
		defer prop.Free()
		require.Equal(t, expected, prop.String(), name)
	}
	assertPropInt := func(name string, expected int32) {
		prop := result.GetPropertyStr(name)
		defer prop.Free()
		require.Equal(t, expected, prop.Int32(), name)
	}
	assertPropBool := func(name string, expected bool) {
		prop := result.GetPropertyStr(name)
		defer prop.Free()
		require.Equal(t, expected, prop.Bool(), name)
	}

	assertPropString("decoded", "hello 世界")
	assertPropString("base64", "hello")
	assertPropString("microtask", "after")
	assertPropString("nowType", "number")
	assertPropInt("cloneValue", 1)
	assertPropInt("cloneByte", 1)
	assertPropString("blobText", "hello world")
	assertPropInt("blobSize", 11)
	assertPropString("blobType", "text/plain")
	assertPropString("sliceText", "world")
	assertPropString("fileName", "greeting.txt")
	assertPropInt("fileLastModified", 123)
	assertPropString("formA", "1,two")
	assertPropString("formFileName", "blob.txt")
	assertPropString("params", "a=one&a=again&b=two")
	assertPropBool("selfIsGlobal", true)
}

func TestInstallTxikiRuntimeExecFile(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go binary is not on PATH")
	}

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallTxikiRuntime())

	goBinJSON := must(json.Marshal(goBin))
	result, err := rt.Eval("txiki-process.js", qjs.Code(`
		export default await (async () => {
			const result = await process.execFile(`+string(goBinJSON)+`, ["env", "GOVERSION"], { timeout: 10000 });
			return {
				success: result.success,
				stdout: result.stdout.trim()
			};
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()

	jsonResult := must(result.JSONStringify())
	require.Contains(t, jsonResult, `"success":true`)
	require.True(t, strings.Contains(jsonResult, `"stdout":"go`), jsonResult)
}

func TestInstallTxikiRuntimeTCPClient(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		require.NoError(t, acceptErr)
		defer conn.Close()

		buf := make([]byte, 4)
		_, readErr := io.ReadFull(conn, buf)
		require.NoError(t, readErr)
		require.Equal(t, "ping", string(buf))
		_, writeErr := conn.Write([]byte("pong"))
		require.NoError(t, writeErr)
	}()

	_, portText, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallTxikiRuntime())

	result, err := rt.Eval("txiki-tcp-client.js", qjs.Code(`
		export default await (async () => {
			const socket = new TCPSocket("127.0.0.1", `+portText+`);
			await socket.write("ping");
			const response = await socket.readText(4);
			socket.close();
			return response;
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()
	require.Equal(t, "pong", result.String())
	<-done
}

func TestInstallTxikiRuntimeTCPServer(t *testing.T) {
	port := freeTCPPort(t)
	done := make(chan string, 1)
	go func() {
		var (
			conn net.Conn
			err  error
		)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			conn, err = net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			done <- "dial: " + err.Error()
			return
		}
		defer conn.Close()

		if _, err := conn.Write([]byte("hello")); err != nil {
			done <- "write: " + err.Error()
			return
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			done <- "read: " + err.Error()
			return
		}
		done <- string(buf)
	}()

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallTxikiRuntime())

	result, err := rt.Eval("txiki-tcp-server.js", qjs.Code(`
		export default await (async () => {
			const server = new TCPServerSocket("127.0.0.1", { localPort: `+port+` });
			const socket = await server.accept();
			const request = await socket.readText(5);
			await socket.write("world");
			socket.close();
			server.close();
			return request;
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()
	require.Equal(t, "hello", result.String())
	require.Equal(t, "world", <-done)
}

func TestInstallTxikiRuntimeUDP(t *testing.T) {
	port := freeUDPPort(t)
	goAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	goConn, err := net.ListenUDP("udp", goAddr)
	require.NoError(t, err)
	defer goConn.Close()

	done := make(chan string, 1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		target, err := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", port))
		if err != nil {
			done <- "resolve: " + err.Error()
			return
		}
		if _, err := goConn.WriteToUDP([]byte("ping"), target); err != nil {
			done <- "write: " + err.Error()
			return
		}
		buf := make([]byte, 4)
		n, _, err := goConn.ReadFromUDP(buf)
		if err != nil {
			done <- "read: " + err.Error()
			return
		}
		done <- string(buf[:n])
	}()

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallTxikiRuntime())

	result, err := rt.Eval("txiki-udp.js", qjs.Code(`
		export default await (async () => {
			const socket = new UDPSocket({ localAddress: "127.0.0.1", localPort: `+port+` });
			const message = await socket.receive(16);
			const text = Array.from(new Uint8Array(message.data)).map(c => String.fromCharCode(c)).join("");
			await socket.send("pong", message.remoteAddress, message.remotePort);
			socket.close();
			return text;
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()
	require.Equal(t, "ping", result.String())
	require.Equal(t, "pong", <-done)
}

func TestInstallTxikiRuntimeHTTPServer(t *testing.T) {
	port := freeTCPPort(t)
	done := make(chan string, 1)
	go func() {
		client := http.Client{Timeout: 2 * time.Second}
		url := "http://" + net.JoinHostPort("127.0.0.1", port) + "/hello?x=1"
		var (
			resp *http.Response
			err  error
		)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			resp, err = client.Get(url)
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			done <- "get: " + err.Error()
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			done <- "read: " + err.Error()
			return
		}
		done <- resp.Status + "|" + resp.Header.Get("X-QJS") + "|" + string(body)
	}()

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallTxikiRuntime())

	result, err := rt.Eval("txiki-http-server.js", qjs.Code(`
		export default await (async () => {
			const server = qjs.http.serve({ hostname: "127.0.0.1", port: `+port+` });
			const request = await server.accept();
			request.respond("ok:" + request.path, {
				status: 201,
				headers: { "X-QJS": "yes" }
			});
			server.close();
			return request.method + " " + request.path + " " + request.websocket;
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()
	require.Equal(t, "GET /hello false", result.String())
	require.Equal(t, "201 Created|yes|ok:/hello", <-done)
}

func TestInstallTxikiRuntimeWebSocketServer(t *testing.T) {
	port := freeTCPPort(t)
	done := make(chan string, 1)
	go func() {
		conn, reader, err := dialTestWebSocket("127.0.0.1", port, "/ws")
		if err != nil {
			done <- "dial: " + err.Error()
			return
		}
		defer conn.Close()
		if err := writeMaskedTextFrame(conn, "ping"); err != nil {
			done <- "write: " + err.Error()
			return
		}
		message, err := readServerTextFrame(reader)
		if err != nil {
			done <- "read: " + err.Error()
			return
		}
		done <- message
	}()

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallTxikiRuntime())

	result, err := rt.Eval("txiki-ws-server.js", qjs.Code(`
		export default await (async () => {
			const server = qjs.http.serve({ hostname: "127.0.0.1", port: `+port+` });
			const request = await server.accept();
			if (!request.websocket) throw new Error("expected websocket request");
			const ws = await request.upgrade();
			const text = await ws.readText();
			ws.send("pong");
			ws.close();
			server.close();
			return text;
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()
	require.Equal(t, "ping", result.String())
	require.Equal(t, "pong", <-done)
}

func TestInstallTxikiRuntimeWebSocketClient(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	done := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- "accept: " + err.Error()
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			done <- "request: " + err.Error()
			return
		}
		accept := testWebSocketAccept(req.Header.Get("Sec-WebSocket-Key"))
		_, err = io.WriteString(conn,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: "+accept+"\r\n\r\n")
		if err != nil {
			done <- "handshake: " + err.Error()
			return
		}
		message, err := readClientTextFrame(reader)
		if err != nil {
			done <- "read: " + err.Error()
			return
		}
		if err := writeUnmaskedTextFrame(conn, "pong"); err != nil {
			done <- "write: " + err.Error()
			return
		}
		done <- message
	}()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallTxikiRuntime())

	result, err := rt.Eval("txiki-ws-client.js", qjs.Code(`
		export default await (async () => {
			const ws = new WebSocket("ws://127.0.0.1:`+port+`/echo");
			await ws.opened;
			const events = [];
			ws.addEventListener("message", event => events.push(event.data));
			ws.send("ping");
			const reply = await ws.readText();
			ws.close();
			return reply + ":" + events.join(",");
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()
	require.Equal(t, "pong:pong", result.String())
	require.Equal(t, "ping", <-done)
}

func TestInstallTxikiRuntimeWorker(t *testing.T) {
	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallTxikiRuntime())

	source := `
		self.postMessage({ type: "ready" });
		self.onmessage = event => {
			self.postMessage({ type: "reply", value: event.data.value + 1 });
		};
	`
	sourceJSON := must(json.Marshal(source))

	result, err := rt.Eval("txiki-worker.js", qjs.Code(`
		export default await (async () => {
			const worker = new Worker(`+string(sourceJSON)+`, { eval: true });
			const seen = [];
			worker.onmessage = event => seen.push(event.data);
			worker.addEventListener("message", event => {
				if (event.data.type === "reply") seen.push({ type: "listener", value: event.data.value });
			});

			for (let i = 0; i < 50 && seen.length < 1; i++) {
				worker.pollMessages();
				if (seen.length < 1) await new Promise(resolve => setTimeout(resolve, 5));
			}

			worker.postMessage({ value: 41 });
			for (let i = 0; i < 50 && seen.length < 3; i++) {
				worker.pollMessages();
				if (seen.length < 3) await new Promise(resolve => setTimeout(resolve, 5));
			}

			worker.terminate();
			return seen;
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()

	jsonResult := must(result.JSONStringify())
	require.Contains(t, jsonResult, `{"type":"ready"}`)
	require.Contains(t, jsonResult, `{"type":"reply","value":42}`)
	require.Contains(t, jsonResult, `{"type":"listener","value":42}`)
}

func freeTCPPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)

	return port
}

func freeUDPPort(t *testing.T) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	_, port, err := net.SplitHostPort(conn.LocalAddr().String())
	require.NoError(t, err)

	return port
}

func dialTestWebSocket(host, port, path string) (net.Conn, *bufio.Reader, error) {
	var (
		conn net.Conn
		err  error
	)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.Dial("tcp", net.JoinHostPort(host, port))
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		return nil, nil, err
	}

	key := "AAAAAAAAAAAAAAAAAAAAAA=="
	request := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + net.JoinHostPort(host, port) + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		conn.Close()
		return nil, nil, err
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, nil, errors.New(resp.Status)
	}

	return conn, reader, nil
}

func writeMaskedTextFrame(w io.Writer, text string) error {
	payload := []byte(text)
	mask := [4]byte{1, 2, 3, 4}
	frame := []byte{0x81, 0x80 | byte(len(payload))}
	frame = append(frame, mask[:]...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%4])
	}
	_, err := w.Write(frame)

	return err
}

func readServerTextFrame(r io.Reader) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", err
	}

	opcode := header[0] & 0x0f
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return "", err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return "", err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", err
	}
	if opcode != 1 {
		return "", errors.New("expected text websocket frame")
	}

	return string(payload), nil
}

func readClientTextFrame(r io.Reader) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", err
	}
	opcode := header[0] & 0x0f
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7f)
	if length == 126 {
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return "", err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return "", err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	if opcode != 1 {
		return "", errors.New("expected text websocket frame")
	}

	return string(payload), nil
}

func writeUnmaskedTextFrame(w io.Writer, text string) error {
	payload := []byte(text)
	frame := []byte{0x81, byte(len(payload))}
	frame = append(frame, payload...)
	_, err := w.Write(frame)

	return err
}

func testWebSocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}
