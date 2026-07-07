package qjs_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/fastschema/qjs"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
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
			await qjs.fs.mkdir("nested", { recursive: true });
			await qjs.fs.writeFile("nested/hello.txt", "world");
			const text = await qjs.fs.readFile("nested/hello.txt", "utf8");
			const names = await qjs.fs.readdir("nested");
			const stat = await qjs.fs.stat("nested/hello.txt");

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
	serverURL := startFastHTTPServer(t, func(ctx *fasthttp.RequestCtx) {
		switch string(ctx.Path()) {
		case "/echo":
			ctx.Response.Header.Set("Content-Type", "application/json")
			ctx.Response.Header.Set("X-Reply", "ok")
			ctx.Response.Header.Add("X-Multi", "one")
			ctx.Response.Header.Add("X-Multi", "two")
			writeJSON(t, ctx, map[string]any{
				"method": string(ctx.Method()),
				"xTest":  string(ctx.Request.Header.Peek("X-Test")),
				"body":   string(ctx.PostBody()),
				"query":  string(ctx.QueryArgs().Peek("query")),
			})
		case "/redirect":
			ctx.Response.Header.Set("Location", "/final")
			ctx.SetStatusCode(fasthttp.StatusFound)
		case "/final":
			ctx.SetBodyString("redirected")
		case "/status":
			ctx.SetStatusCode(fasthttp.StatusTeapot)
			ctx.SetBodyString("teapot")
		case "/binary":
			ctx.Response.Header.Set("Content-Type", "application/octet-stream")
			ctx.SetBody([]byte{0, 1, 255})
		case "/request":
			ctx.Response.Header.Set("Content-Type", "application/json")
			writeJSON(t, ctx, map[string]any{
				"method": string(ctx.Method()),
				"xReq":   string(ctx.Request.Header.Peek("X-Req")),
				"body":   string(ctx.PostBody()),
			})
		default:
			ctx.SetStatusCode(fasthttp.StatusNotFound)
		}
	})

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallTxikiRuntime())

	serverURLJSON := must(json.Marshal(serverURL))
	result, err := rt.Eval("txiki-fetch.js", qjs.Code(`
		export default await (async () => {
			const headers = new Headers([["X-Test", "yes"]]);
			headers.append("X-Unused", "drop");
			headers.delete("X-Unused");
			const res = await fetch(`+string(serverURLJSON)+` + "/echo?query=1", {
				method: "POST",
				headers,
				body: new Uint8Array([112, 105, 110, 103])
			});
			const cloneText = await res.clone().text();
			const body = await res.json();
			const redirected = await fetch(`+string(serverURLJSON)+` + "/redirect");
			const errorRes = await fetch(`+string(serverURLJSON)+` + "/status");
			const binaryRes = await fetch(`+string(serverURLJSON)+` + "/binary");
			const request = new Request(`+string(serverURLJSON)+` + "/request", {
				method: "PUT",
				headers: { "X-Req": "ok" },
				body: "from request"
			});
			const requestRes = await fetch(request);
			const constructed = new Response("created", { status: 201, headers: { "X-Local": "yes" } });
			return JSON.stringify({
				ok: res.ok,
				status: res.status,
				statusText: res.statusText,
				reply: res.headers.get("x-reply"),
				multi: res.headers.get("x-multi"),
				cloneText,
				body,
				redirectedURL: redirected.url,
				redirectedText: await redirected.text(),
				errorOK: errorRes.ok,
				errorStatus: errorRes.status,
				errorText: await errorRes.text(),
				binary: Array.from(new Uint8Array(await binaryRes.arrayBuffer())),
				request: await requestRes.json(),
				constructedStatus: constructed.status,
				constructedOK: constructed.ok,
				constructedHeader: constructed.headers.get("x-local"),
				constructedText: await constructed.text()
			});
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()

	jsonResult := result.String()
	require.Contains(t, jsonResult, `"ok":true`)
	require.Contains(t, jsonResult, `"status":200`)
	require.Contains(t, jsonResult, `"statusText":"OK"`)
	require.Contains(t, jsonResult, `"reply":"ok"`)
	require.Contains(t, jsonResult, `"multi":"one, two"`)
	require.Contains(t, jsonResult, `"method":"POST"`)
	require.Contains(t, jsonResult, `"xTest":"yes"`)
	require.Contains(t, jsonResult, `"body":"ping"`)
	require.Contains(t, jsonResult, `"query":"1"`)
	require.Contains(t, jsonResult, `"redirectedText":"redirected"`)
	require.Contains(t, jsonResult, `"errorOK":false`)
	require.Contains(t, jsonResult, `"errorStatus":418`)
	require.Contains(t, jsonResult, `"errorText":"teapot"`)
	require.Contains(t, jsonResult, `"binary":[0,1,255]`)
	require.Contains(t, jsonResult, `"method":"PUT"`)
	require.Contains(t, jsonResult, `"xReq":"ok"`)
	require.Contains(t, jsonResult, `"body":"from request"`)
	require.Contains(t, jsonResult, `"constructedStatus":201`)
	require.Contains(t, jsonResult, `"constructedOK":true`)
	require.Contains(t, jsonResult, `"constructedHeader":"yes"`)
	require.Contains(t, jsonResult, `"constructedText":"created"`)
}

func TestInstallTxikiRuntimeFileSystemAPIs(t *testing.T) {
	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallTxikiRuntime())

	result, err := rt.Eval("txiki-fs.js", qjs.Code(`
		import fsDefault, { promises as fsPromises, readFileSync as importedReadFileSync } from "fs";
		import { readFile as importedReadFile, writeFile as importedWriteFile, rm as importedRm } from "fs/promises";
		import nodeFSDefault, { promises as nodeFSPromises } from "node:fs";
		import { readFile as nodeReadFile } from "node:fs/promises";

		export default await (async () => {
			const mkdirPromise = qjs.fs.mkdir("dir/sub", { recursive: true });
			const mkdirIsPromise = !!mkdirPromise && typeof mkdirPromise.then === "function";
			await mkdirPromise;
			qjs.fs.writeFileSync("dir/sub/sync.txt", "sync");

			const writePromise = qjs.fs.writeFile("dir/sub/text.txt", "hello");
			const writeIsPromise = !!writePromise && typeof writePromise.then === "function";
			await writePromise;
			await qjs.fs.writeFile("dir/sub/bytes.bin", new Uint8Array([0, 1, 255]));
			await importedWriteFile("dir/sub/module.txt", "module");
			const moduleText = await importedReadFile("dir/sub/module.txt", "utf8");
			const nodeModuleText = await nodeReadFile("dir/sub/module.txt", "utf8");
			await importedRm("dir/sub/module.txt");

			const readPromise = qjs.fs.readFile("dir/sub/text.txt", { encoding: "utf8" });
			let readSettled = false;
			readPromise.then(() => { readSettled = true; });
			const readInitiallyPending = !readSettled;
			const text = await readPromise;
			const text2 = await qjs.fs.readFileText("dir/sub/text.txt");
			const bytes = Array.from(new Uint8Array(await qjs.fs.readFile("dir/sub/bytes.bin")));
			const names = await qjs.fs.readdir("dir/sub");
			const fileStat = await qjs.fs.stat("dir/sub/bytes.bin");
			const dirStat = qjs.fs.statSync("dir");
			const existsBefore = await qjs.fs.exists("dir/sub/text.txt");
			const syncText = qjs.fs.readFileSync("dir/sub/sync.txt", "utf8");
			const defaultSyncText = fsDefault.readFileSync("dir/sub/sync.txt", "utf8");
			const importedSyncText = importedReadFileSync("dir/sub/sync.txt", "utf8");

			await qjs.fs.remove("dir/sub/text.txt");
			const existsAfterFileRemove = await qjs.fs.exists("dir/sub/text.txt");

			let escapeError = "";
			try {
				await qjs.fs.writeFile("../escape.txt", "no");
			} catch (error) {
				escapeError = String(error);
			}

			await qjs.fs.remove("dir", { recursive: true });
			return JSON.stringify({
				text,
				text2,
				moduleText,
				nodeModuleText,
				syncText,
				defaultSyncText,
				importedSyncText,
				bytes,
				names,
				fileName: fileStat.name,
				fileSize: fileStat.size,
				isFile: fileStat.isFile,
				isDir: dirStat.isDir,
				existsBefore,
				existsAfterFileRemove,
				rootExistsAfterRemove: await qjs.fs.exists("dir"),
				escapeBlocked: escapeError.includes("escapes runtime CWD"),
				mkdirIsPromise,
				writeIsPromise,
				readInitiallyPending,
				syncReadIsPromise: typeof syncText?.then === "function",
				importedPromiseAPI: fsPromises.readFile === qjs.fs.readFile,
				nodePromiseAPI: nodeFSPromises.readFile === qjs.fs.readFile,
				nodeDefaultAPI: nodeFSDefault.promises === qjs.fs.promises
			});
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()

	jsonResult := result.String()
	require.Contains(t, jsonResult, `"text":"hello"`)
	require.Contains(t, jsonResult, `"text2":"hello"`)
	require.Contains(t, jsonResult, `"moduleText":"module"`)
	require.Contains(t, jsonResult, `"nodeModuleText":"module"`)
	require.Contains(t, jsonResult, `"syncText":"sync"`)
	require.Contains(t, jsonResult, `"defaultSyncText":"sync"`)
	require.Contains(t, jsonResult, `"importedSyncText":"sync"`)
	require.Contains(t, jsonResult, `"bytes":[0,1,255]`)
	require.Contains(t, jsonResult, `"names":["bytes.bin","sync.txt","text.txt"]`)
	require.Contains(t, jsonResult, `"fileName":"bytes.bin"`)
	require.Contains(t, jsonResult, `"fileSize":3`)
	require.Contains(t, jsonResult, `"isFile":true`)
	require.Contains(t, jsonResult, `"isDir":true`)
	require.Contains(t, jsonResult, `"existsBefore":true`)
	require.Contains(t, jsonResult, `"existsAfterFileRemove":false`)
	require.Contains(t, jsonResult, `"rootExistsAfterRemove":false`)
	require.Contains(t, jsonResult, `"escapeBlocked":true`)
	require.Contains(t, jsonResult, `"mkdirIsPromise":true`)
	require.Contains(t, jsonResult, `"writeIsPromise":true`)
	require.Contains(t, jsonResult, `"readInitiallyPending":true`)
	require.Contains(t, jsonResult, `"syncReadIsPromise":false`)
	require.Contains(t, jsonResult, `"importedPromiseAPI":true`)
	require.Contains(t, jsonResult, `"nodePromiseAPI":true`)
	require.Contains(t, jsonResult, `"nodeDefaultAPI":true`)
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
	shell, shellArgs := processEnvEchoCommand(t, "QJS_PROCESS_TEST")

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallTxikiRuntime())

	goBinJSON := must(json.Marshal(goBin))
	shellJSON := must(json.Marshal(shell))
	shellArgsJSON := must(json.Marshal(shellArgs))
	result, err := rt.Eval("txiki-process.js", qjs.Code(`
		import processDefault, { cwd as importedCwd, env as importedEnv } from "node:process";
		import bareProcess from "process";

		export default await (async () => {
			const originalCwd = process.cwd();
			await qjs.fs.mkdir("work", { recursive: true });
			const changedCwd = process.chdir("work");
			await qjs.fs.writeFile("cwd.txt", "cwd-ok");
			const cwdText = await qjs.fs.readFile("cwd.txt", "utf8");
			process.chdir("..");
			const rootText = await qjs.fs.readFile("work/cwd.txt", "utf8");

			process.env.QJS_PROCESS_TEST = 123;
			const envResult = await process.execFile(`+string(shellJSON)+`, `+string(shellArgsJSON)+`, { timeout: 10000 });
			const promise = process.execFile(`+string(goBinJSON)+`, ["env", "GOVERSION"], { timeout: 10000 });
			const isPromise = !!promise && typeof promise.then === "function";
			let settled = false;
			promise.then(() => { settled = true; });
			const initiallyPending = !settled;
			const result = await promise;
			const syncResult = process.execFileSync(`+string(goBinJSON)+`, ["env", "GOVERSION"], { timeout: 10000 });
			return JSON.stringify({
				pid: process.pid,
				ppid: process.ppid,
				platform: process.platform,
				arch: process.arch,
				argvIsFrozen: Object.isFrozen(process.argv),
				argsIsFrozen: Object.isFrozen(process.args),
				moduleDefaultSame: processDefault === process,
				bareDefaultSame: bareProcess === process,
				importedCwdSame: importedCwd === process.cwd,
				importedEnvSame: importedEnv === process.env,
				originalCwdIsString: typeof originalCwd === "string" && originalCwd.length > 0,
				changedCwdEndsWithWork: /work$/.test(changedCwd.replace(/\\/g, "/")),
				restoredCwd: process.cwd() === originalCwd,
				cwdText,
				rootText,
				envEcho: envResult.stdout.trim(),
				envStringified: process.env.QJS_PROCESS_TEST === "123",
				killIsFunction: typeof process.kill === "function",
				isPromise,
				initiallyPending,
				success: result.success,
				stdout: result.stdout.trim(),
				syncSuccess: syncResult.success,
				syncStdout: syncResult.stdout.trim()
			});
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()

	jsonResult := result.String()
	require.Contains(t, jsonResult, `"platform":"`+goruntime.GOOS+`"`)
	require.Contains(t, jsonResult, `"arch":"`+goruntime.GOARCH+`"`)
	require.Contains(t, jsonResult, `"argvIsFrozen":true`)
	require.Contains(t, jsonResult, `"argsIsFrozen":true`)
	require.Contains(t, jsonResult, `"moduleDefaultSame":true`)
	require.Contains(t, jsonResult, `"bareDefaultSame":true`)
	require.Contains(t, jsonResult, `"importedCwdSame":true`)
	require.Contains(t, jsonResult, `"importedEnvSame":true`)
	require.Contains(t, jsonResult, `"originalCwdIsString":true`)
	require.Contains(t, jsonResult, `"changedCwdEndsWithWork":true`)
	require.Contains(t, jsonResult, `"restoredCwd":true`)
	require.Contains(t, jsonResult, `"cwdText":"cwd-ok"`)
	require.Contains(t, jsonResult, `"rootText":"cwd-ok"`)
	require.Contains(t, jsonResult, `"envEcho":"123"`)
	require.Contains(t, jsonResult, `"envStringified":true`)
	require.Contains(t, jsonResult, `"killIsFunction":true`)
	require.Contains(t, jsonResult, `"isPromise":true`)
	require.Contains(t, jsonResult, `"initiallyPending":true`)
	require.Contains(t, jsonResult, `"success":true`)
	require.True(t, strings.Contains(jsonResult, `"stdout":"go`), jsonResult)
	require.Contains(t, jsonResult, `"syncSuccess":true`)
	require.True(t, strings.Contains(jsonResult, `"syncStdout":"go`), jsonResult)
}

func TestInstallTxikiRuntimeFeatureOptions(t *testing.T) {
	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallTxikiRuntime(qjs.TxikiRuntimeOptions{
		DisableFeatures: qjs.TxikiRuntimeFeatureProcess | qjs.TxikiRuntimeFeatureFS,
	}))

	result, err := rt.Eval("txiki-disabled-features.js", qjs.Code(`
		export default JSON.stringify({
			processGlobal: typeof globalThis.process,
			qjsProcess: typeof qjs.process,
			fs: typeof qjs.fs,
			execHost: typeof globalThis.__qjs_exec_file,
			fsHost: typeof globalThis.__qjs_fs_read_file,
			fetch: typeof globalThis.fetch
		});
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()

	jsonResult := result.String()
	require.Contains(t, jsonResult, `"processGlobal":"undefined"`)
	require.Contains(t, jsonResult, `"qjsProcess":"undefined"`)
	require.Contains(t, jsonResult, `"fs":"undefined"`)
	require.Contains(t, jsonResult, `"execHost":"undefined"`)
	require.Contains(t, jsonResult, `"fsHost":"undefined"`)
	require.Contains(t, jsonResult, `"fetch":"function"`)
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
		client := fasthttp.Client{}
		url := "http://" + net.JoinHostPort("127.0.0.1", port) + "/hello?x=1"
		var err error
		req := fasthttp.AcquireRequest()
		defer fasthttp.ReleaseRequest(req)
		req.SetRequestURI(url)
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseResponse(resp)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			resp.Reset()
			err = client.DoTimeout(req, resp, 2*time.Second)
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			done <- "get: " + err.Error()
			return
		}
		status := fmt.Sprintf("%d %s", resp.StatusCode(), fasthttp.StatusMessage(resp.StatusCode()))
		done <- status + "|" + string(resp.Header.Peek("X-QJS")) + "|" + string(resp.Body())
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

func startFastHTTPServer(t *testing.T, handler fasthttp.RequestHandler) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &fasthttp.Server{Handler: handler}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(listener)
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.ShutdownWithContext(ctx)
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("fasthttp server stopped with error: %v", err)
			}
		case <-time.After(time.Second):
			t.Errorf("fasthttp server did not stop")
		}
	})

	return "http://" + listener.Addr().String()
}

func writeJSON(t *testing.T, ctx *fasthttp.RequestCtx, value any) {
	t.Helper()

	data, err := json.Marshal(value)
	require.NoError(t, err)
	ctx.SetBody(data)
}

func processEnvEchoCommand(t *testing.T, name string) (string, []string) {
	t.Helper()

	if goruntime.GOOS == "windows" {
		shell := os.Getenv("COMSPEC")
		if shell == "" {
			var err error
			shell, err = exec.LookPath("cmd")
			require.NoError(t, err)
		}

		return shell, []string{"/c", "echo %" + name + "%"}
	}

	shell, err := exec.LookPath("sh")
	require.NoError(t, err)

	return shell, []string{"-c", "printf %s \"$" + name + "\""}
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
