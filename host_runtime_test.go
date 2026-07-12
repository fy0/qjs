package qjs_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fastschema/qjs"
	"github.com/stretchr/testify/require"
)

func TestHostRuntimeNodeToolCompatibility(t *testing.T) {
	root := t.TempDir()
	rt := must(qjs.New(qjs.Option{CWD: root}))
	defer rt.Close()
	require.NoError(t, rt.InstallHostRuntime())

	result, err := rt.Eval("node-tool-compat.js", qjs.Code(`
		import fs, { readFileSync, openSync, writeSync, closeSync } from "node:fs";
		import fsp from "node:fs/promises";
		import path from "node:path";
		import os from "node:os";
		import crypto from "node:crypto";
		import { Buffer } from "node:buffer";
		import { performance } from "node:perf_hooks";
		import processDefault from "node:process";

		export default await (async () => {
			await fsp.mkdir("work", { recursive: true });
			const file = path.join("work", "hello.txt");
			await fsp.writeFile(file, Buffer.from("hello"));
			await fsp.appendFile(file, " world");
			const callbackText = await new Promise((resolve, reject) => {
				fs.readFile(file, "utf8", (error, value) => error ? reject(error) : resolve(value));
			});
			const stat = await fsp.stat(file);
			const entries = await fsp.readdir("work", { withFileTypes: true });

			const fd = openSync("work/fd.txt", "w");
			const written = writeSync(fd, Buffer.from("fd-data"), 0, 7, null);
			closeSync(fd);

			let missingCode = "";
			try { await fsp.readFile("missing.txt"); } catch (error) { missingCode = error.code; }
			const digest = crypto.createHash("sha256").update("abc").digest("hex");
			return JSON.stringify({
				callbackText,
				syncText: readFileSync(file, "utf8"),
				fdText: readFileSync("work/fd.txt", "utf8"),
				written,
				statFile: stat.isFile(),
				direntFile: entries[0].isFile(),
				missingCode,
				digest,
				bufferHex: Buffer.from([0, 1, 255]).toString("hex"),
				platform: os.platform(),
				arch: os.arch(),
				processSame: processDefault === process,
				requireSame: require("fs") === fs,
				globalSame: global === globalThis,
				performanceType: typeof performance.now()
			});
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(result.String()), &got))
	require.Equal(t, "hello world", got["callbackText"])
	require.Equal(t, "hello world", got["syncText"])
	require.Equal(t, "fd-data", got["fdText"])
	require.Equal(t, float64(7), got["written"])
	require.Equal(t, true, got["statFile"])
	require.Equal(t, true, got["direntFile"])
	require.Equal(t, "ENOENT", got["missingCode"])
	require.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", got["digest"])
	require.Equal(t, "0001ff", got["bufferHex"])
	require.Equal(t, true, got["processSame"])
	require.Equal(t, true, got["requireSame"])
	require.Equal(t, true, got["globalSame"])
	require.Equal(t, "number", got["performanceType"])

	expectedPlatform := runtime.GOOS
	if expectedPlatform == "windows" {
		expectedPlatform = "win32"
	}
	require.Equal(t, expectedPlatform, got["platform"])
}

func TestHostRuntimeRunsBundledTypeScriptCompiler(t *testing.T) {
	bundle, err := os.ReadFile("testdata/host_runtime/typescript-5.9.3-canary.mjs")
	require.NoError(t, err)

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallHostRuntime())

	result, err := rt.Eval(
		"typescript-5.9.3-canary.mjs",
		qjs.Code(string(bundle)),
		qjs.TypeModule(),
	)
	require.NoError(t, err)
	defer result.Free()

	var got struct {
		Version     string   `json:"version"`
		Diagnostics []string `json:"diagnostics"`
		EmitSkipped bool     `json:"emitSkipped"`
		Output      string   `json:"output"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &got))
	require.Equal(t, "5.9.3", got.Version)
	require.Empty(t, got.Diagnostics)
	require.False(t, got.EmitSkipped)
	require.Contains(t, got.Output, `const greeting = `)
	require.NotContains(t, got.Output, `satisfies User`)
}

func TestHostRuntimeInstallAndCloseAreControlled(t *testing.T) {
	invalid := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	require.Error(t, invalid.InstallHostRuntime(
		qjs.HostRuntimeOptions{},
		qjs.HostRuntimeOptions{},
	))
	require.NoError(t, invalid.InstallHostRuntime())
	invalid.Close()

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	require.NoError(t, rt.InstallHostRuntime())
	require.EqualError(t, rt.InstallHostRuntime(), "host runtime is already installed")
	rt.Close()
	rt.Close()
}

func TestHostRuntimeProcessExitDoesNotExitHost(t *testing.T) {
	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallHostRuntime())

	_, err := rt.Eval("process-exit.js", qjs.Code(`process.exit(7)`))
	var exitErr *qjs.ProcessExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 7, exitErr.Code)
}

func TestHostRuntimeFilesystemModes(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600))

	t.Run("sandbox rejects parent and symlink escapes", func(t *testing.T) {
		link := filepath.Join(root, "outside-link")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}
		rt := must(qjs.New(qjs.Option{CWD: root}))
		defer rt.Close()
		require.NoError(t, rt.InstallHostRuntime())

		result, err := rt.Eval("sandbox-fs.js", qjs.Code(`
			import fsp from "node:fs/promises";
			export default await (async () => {
				const blocked = [];
				for (const path of ["../secret.txt", "outside-link/secret.txt"]) {
					try { await fsp.readFile(path, "utf8"); blocked.push(false); }
					catch (error) { blocked.push(true); }
				}
				return blocked;
			})();
		`), qjs.TypeModule())
		require.NoError(t, err)
		defer result.Free()
		require.Equal(t, `[true,true]`, must(result.JSONStringify()))
	})

	t.Run("host mode permits real absolute paths", func(t *testing.T) {
		rt := must(qjs.New(qjs.Option{CWD: root}))
		defer rt.Close()
		require.NoError(t, rt.InstallHostRuntime(qjs.HostRuntimeOptions{
			FileSystem: qjs.FileSystemOptions{Mode: qjs.FileSystemHost, Root: root},
		}))
		pathJSON := string(must(json.Marshal(filepath.Join(outside, "secret.txt"))))
		result, err := rt.Eval("host-fs.js", qjs.Code(`
			import fsp from "node:fs/promises";
			export default await fsp.readFile(`+pathJSON+`, "utf8");
		`), qjs.TypeModule())
		require.NoError(t, err)
		defer result.Free()
		require.Equal(t, "secret", result.String())
	})
}

func TestHostRuntimeFetchStreamingAbortAndRedirectSafety(t *testing.T) {
	var leakedAuthorization atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leakedAuthorization.Store(r.Header.Get("Authorization") != "")
		_, _ = w.Write([]byte("target"))
	}))
	defer target.Close()

	requestCanceled := make(chan struct{}, 1)
	bodyRequestCanceled := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stream":
			w.Header().Set("X-Stream", "yes")
			_, _ = w.Write([]byte("one"))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			time.Sleep(120 * time.Millisecond)
			_, _ = w.Write([]byte("two"))
		case "/slow":
			select {
			case <-r.Context().Done():
				select {
				case requestCanceled <- struct{}{}:
				default:
				}
			case <-time.After(2 * time.Second):
				w.WriteHeader(http.StatusNoContent)
			}
		case "/abort-body":
			_, _ = w.Write([]byte("body-start"))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			select {
			case <-r.Context().Done():
				select {
				case bodyRequestCanceled <- struct{}{}:
				default:
				}
			case <-time.After(2 * time.Second):
				_, _ = w.Write([]byte("body-end"))
			}
		case "/redirect":
			http.Redirect(w, r, target.URL, http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallHostRuntime())
	serverJSON := string(must(json.Marshal(server.URL)))

	result, err := rt.Eval("stream-fetch.js", qjs.Code(`
		const base = `+serverJSON+`;
		export default await (async () => {
			const started = performance.now();
			const response = await fetch(base + "/stream");
			const headersMs = performance.now() - started;
			const reader = response.body.getReader();
			const first = await reader.read();
			const second = await reader.read();
			const end = await reader.read();
			const decode = value => new TextDecoder().decode(value);

			const used = new Response("used");
			await used.text();
			let secondRead = "";
			try { await used.text(); } catch (error) { secondRead = error.name; }

			const controller = new AbortController();
			setTimeout(() => controller.abort(), 20);
			let abortName = "";
			try { await fetch(base + "/slow", { signal: controller.signal }); }
			catch (error) { abortName = error.name; }

			const bodyController = new AbortController();
			const bodyResponse = await fetch(base + "/abort-body", { signal: bodyController.signal });
			const bodyReader = bodyResponse.body.getReader();
			const bodyFirst = await bodyReader.read();
			setTimeout(() => bodyController.abort(), 20);
			let bodyAbortName = "";
			try { await bodyReader.read(); } catch (error) { bodyAbortName = error.name; }

			const redirected = await fetch(base + "/redirect", {
				headers: { Authorization: "Bearer secret" }
			});
			return JSON.stringify({
				headersMs,
				header: response.headers.get("x-stream"),
				first: decode(first.value),
				second: decode(second.value),
				done: end.done,
				secondRead,
				abortName,
				bodyFirst: decode(bodyFirst.value),
				bodyAbortName,
				redirected: redirected.redirected,
				redirectBody: await redirected.text()
			});
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(result.String()), &got))
	require.Less(t, got["headersMs"].(float64), float64(110), fmt.Sprintf("headers took %vms", got["headersMs"]))
	require.Equal(t, "yes", got["header"])
	require.Equal(t, "one", got["first"])
	require.Equal(t, "two", got["second"])
	require.Equal(t, true, got["done"])
	require.Equal(t, "TypeError", got["secondRead"])
	require.Equal(t, "AbortError", got["abortName"])
	require.Equal(t, "body-start", got["bodyFirst"])
	require.Equal(t, "AbortError", got["bodyAbortName"])
	require.Equal(t, true, got["redirected"])
	require.Equal(t, "target", got["redirectBody"])
	require.False(t, leakedAuthorization.Load())
	select {
	case <-requestCanceled:
	case <-time.After(time.Second):
		t.Fatal("aborted fetch did not cancel the HTTP request")
	}
	select {
	case <-bodyRequestCanceled:
	case <-time.After(time.Second):
		t.Fatal("aborting a response body did not cancel the HTTP request")
	}
}

func TestHostRuntimeFetchBufferLimitCancelsBody(t *testing.T) {
	requestCanceled := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("too-large"))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		select {
		case <-r.Context().Done():
			select {
			case requestCanceled <- struct{}{}:
			default:
			}
		case <-time.After(2 * time.Second):
			_, _ = w.Write([]byte("late"))
		}
	}))
	defer server.Close()

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallHostRuntime(qjs.HostRuntimeOptions{MaxBufferedBodyBytes: 4}))
	serverJSON := string(must(json.Marshal(server.URL)))

	result, err := rt.Eval("fetch-buffer-limit.js", qjs.Code(`
		export default await (async () => {
			try {
				await (await fetch(`+serverJSON+`)).text();
				return null;
			} catch (error) {
				return JSON.stringify({ name: error.name, code: error.code });
			}
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()
	require.JSONEq(t, `{"name":"RangeError","code":"ERR_BODY_TOO_LARGE"}`, result.String())

	select {
	case <-requestCanceled:
	case <-time.After(time.Second):
		t.Fatal("buffer limit did not cancel the HTTP response body")
	}
}

func TestHostRuntimeDefaultProfileKeepsExperimentalCapabilitiesOff(t *testing.T) {
	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallHostRuntime())
	result, err := rt.Eval("default-profile.js", qjs.Code(`JSON.stringify({
		net: typeof qjs.net,
		http: typeof qjs.http,
		worker: typeof Worker,
		fetch: typeof fetch,
		fs: typeof qjs.fs,
		child: typeof process.execFile
	})`))
	require.NoError(t, err)
	defer result.Free()
	text := result.String()
	for _, expected := range []string{
		`"net":"undefined"`, `"http":"undefined"`, `"worker":"undefined"`,
		`"fetch":"function"`, `"fs":"object"`, `"child":"undefined"`,
	} {
		require.True(t, strings.Contains(text, expected), text)
	}
}

func TestProcessExitErrorSupportsErrorsAs(t *testing.T) {
	err := error(&qjs.ProcessExitError{Code: 3})
	var target *qjs.ProcessExitError
	require.True(t, errors.As(err, &target))
}
