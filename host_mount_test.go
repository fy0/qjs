package qjs_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/fastschema/qjs"
	"github.com/stretchr/testify/require"
)

func TestHostRuntimeMultiMountValidation(t *testing.T) {
	runtimeCWD := t.TempDir()
	mountRoot := t.TempDir()

	install := func(t *testing.T, options qjs.FileSystemOptions) error {
		t.Helper()
		rt := must(qjs.New(qjs.Option{CWD: runtimeCWD}))
		defer rt.Close()
		return rt.InstallHostRuntime(qjs.HostRuntimeOptions{FileSystem: options})
	}

	t.Run("accepts independent top-level mounts", func(t *testing.T) {
		require.NoError(t, install(t, qjs.FileSystemOptions{
			Mounts: []qjs.FileSystemMount{{Path: "/data", Root: mountRoot}},
		}))
	})

	t.Run("rejects Root and Mounts together", func(t *testing.T) {
		err := install(t, qjs.FileSystemOptions{
			Root:   runtimeCWD,
			Mounts: []qjs.FileSystemMount{{Path: "/data", Root: mountRoot}},
		})
		require.ErrorContains(t, err, "Root and Mounts")
	})

	t.Run("rejects mounts in host mode", func(t *testing.T) {
		err := install(t, qjs.FileSystemOptions{
			Mode:   qjs.FileSystemHost,
			Mounts: []qjs.FileSystemMount{{Path: "/data", Root: mountRoot}},
		})
		require.ErrorContains(t, err, "mounts require sandbox mode")
	})

	t.Run("rejects VirtualCWD in single-root mode", func(t *testing.T) {
		err := install(t, qjs.FileSystemOptions{VirtualCWD: "/"})
		require.ErrorContains(t, err, "VirtualCWD requires multi-mount mode")
	})

	for _, path := range []string{"", "/", "data", "/data/", "/a/b", "/./data", "/../data", `/data\nested`, "/data\x00"} {
		path := path
		t.Run("rejects invalid mount path "+path, func(t *testing.T) {
			err := install(t, qjs.FileSystemOptions{
				Mounts: []qjs.FileSystemMount{{Path: path, Root: mountRoot}},
			})
			require.Error(t, err)
		})
	}

	t.Run("rejects duplicate virtual paths", func(t *testing.T) {
		err := install(t, qjs.FileSystemOptions{Mounts: []qjs.FileSystemMount{
			{Path: "/data", Root: mountRoot},
			{Path: "/data", Root: t.TempDir()},
		}})
		require.ErrorContains(t, err, "duplicate filesystem mount path")
	})

	t.Run("rejects missing and non-directory roots", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing")
		require.Error(t, install(t, qjs.FileSystemOptions{
			Mounts: []qjs.FileSystemMount{{Path: "/missing", Root: missing}},
		}))

		file := filepath.Join(t.TempDir(), "file.txt")
		require.NoError(t, os.WriteFile(file, []byte("file"), 0o600))
		err := install(t, qjs.FileSystemOptions{
			Mounts: []qjs.FileSystemMount{{Path: "/file", Root: file}},
		})
		require.ErrorContains(t, err, "not a directory")
	})

	t.Run("rejects equal and nested physical roots", func(t *testing.T) {
		parent := t.TempDir()
		child := filepath.Join(parent, "child")
		require.NoError(t, os.Mkdir(child, 0o700))
		for _, second := range []string{parent, child} {
			err := install(t, qjs.FileSystemOptions{Mounts: []qjs.FileSystemMount{
				{Path: "/one", Root: parent},
				{Path: "/two", Root: second},
			}})
			require.ErrorContains(t, err, "mount roots overlap")
		}
	})

	t.Run("rejects roots equal after symlink evaluation", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "root-link")
		if err := os.Symlink(mountRoot, link); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}
		err := install(t, qjs.FileSystemOptions{Mounts: []qjs.FileSystemMount{
			{Path: "/one", Root: mountRoot},
			{Path: "/two", Root: link},
		}})
		require.ErrorContains(t, err, "mount roots overlap")
	})

	t.Run("validates VirtualCWD existence and type", func(t *testing.T) {
		file := filepath.Join(mountRoot, "file.txt")
		require.NoError(t, os.WriteFile(file, []byte("file"), 0o600))

		err := install(t, qjs.FileSystemOptions{
			Mounts:     []qjs.FileSystemMount{{Path: "/data", Root: mountRoot}},
			VirtualCWD: "/missing",
		})
		require.ErrorContains(t, err, "invalid filesystem VirtualCWD")

		err = install(t, qjs.FileSystemOptions{
			Mounts:     []qjs.FileSystemMount{{Path: "/data", Root: mountRoot}},
			VirtualCWD: "/data/file.txt",
		})
		require.ErrorContains(t, err, "VirtualCWD is not a directory")
	})
}

func TestHostRuntimeSingleRootCompatibility(t *testing.T) {
	root := t.TempDir()
	work := filepath.Join(root, "work")
	require.NoError(t, os.Mkdir(work, 0o700))

	rt := must(qjs.New(qjs.Option{CWD: work}))
	defer rt.Close()
	require.NoError(t, rt.InstallHostRuntime(qjs.HostRuntimeOptions{
		FileSystem: qjs.FileSystemOptions{Root: root},
	}))

	result, err := rt.Eval("single-root-compatibility.js", qjs.Code(`
		export default await (async () => {
			await qjs.fs.writeFile("file.txt", "single-root");
			return JSON.stringify({
				cwd: process.cwd(),
				text: qjs.fs.readFileSync("file.txt", "utf8"),
				realpath: qjs.fs.realpathSync("file.txt")
			});
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()

	var got struct {
		CWD      string `json:"cwd"`
		Text     string `json:"text"`
		Realpath string `json:"realpath"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &got))
	require.Equal(t, work, got.CWD)
	require.Equal(t, "single-root", got.Text)
	require.Equal(t, filepath.Join(work, "file.txt"), got.Realpath)
}

func TestHostRuntimeMultiMountRejectsSymlinkEscape(t *testing.T) {
	mountRoot := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600))
	if err := os.Symlink(outside, filepath.Join(mountRoot, "outside")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallHostRuntime(qjs.HostRuntimeOptions{
		FileSystem: qjs.FileSystemOptions{
			Mounts: []qjs.FileSystemMount{{Path: "/data", Root: mountRoot}},
		},
	}))

	result, err := rt.Eval("multi-mount-symlink.js", qjs.Code(`
		export default await (async () => {
			const blocked = {};
			for (const [name, action] of Object.entries({
				read: () => qjs.fs.readFile("/data/outside/secret.txt"),
				write: () => qjs.fs.writeFile("/data/outside/new.txt", "blocked"),
				realpath: () => qjs.fs.realpath("/data/outside/secret.txt")
			})) {
				try { await action(); blocked[name] = false; }
				catch (_) { blocked[name] = true; }
			}
			return JSON.stringify(blocked);
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()
	require.JSONEq(t, `{"read":true,"write":true,"realpath":true}`, result.String())
	require.NoFileExists(t, filepath.Join(outside, "new.txt"))
}

func TestHostRuntimeMultiMountBasicBehavior(t *testing.T) {
	assets := t.TempDir()
	data := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(assets, "asset.txt"), []byte("asset"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(data, "work"), 0o700))

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallHostRuntime(qjs.HostRuntimeOptions{
		FileSystem: qjs.FileSystemOptions{
			Mounts: []qjs.FileSystemMount{
				{Path: "/assets", Root: assets, ReadOnly: true},
				{Path: "/data", Root: data},
			},
			VirtualCWD: "/data/work",
		},
	}))

	result, err := rt.Eval("multi-mount-basic.js", qjs.Code(`
		import fs from "node:fs";
		import fsp from "node:fs/promises";

		export default await (async () => {
			const initialCWD = process.cwd();
			const rootStat = fs.statSync("/");
			const rootNames = fs.readdirSync("/");
			const rootDirents = fs.readdirSync("/", { withFileTypes: true });
			const asset = await fsp.readFile("/assets/asset.txt", "utf8");
			await fsp.writeFile("relative.txt", "relative");
			const relative = fs.readFileSync("/data/work/relative.txt", "utf8");
			const realpath = fs.realpathSync("/assets/asset.txt");
			let missingCode = "";
			try { fs.statSync("/missing/file.txt"); } catch (error) { missingCode = error.code; }
			let rootReadCode = "";
			try { fs.readFileSync("/"); } catch (error) { rootReadCode = error.code; }
			let rootOpenCode = "";
			try { fs.openSync("/", "r"); } catch (error) { rootOpenCode = error.code; }
			process.chdir("/");
			const rootCWD = process.cwd();
			process.chdir("data/work");
			return JSON.stringify({
				initialCWD,
				rootIsDirectory: rootStat.isDirectory(),
				rootNames,
				rootDirents: rootDirents.map(entry => [entry.name, entry.isDirectory()]),
				asset,
				relative,
				realpath,
				missingCode,
				rootReadCode,
				rootOpenCode,
				rootCWD,
				finalCWD: process.cwd()
			});
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()

	var got struct {
		InitialCWD      string          `json:"initialCWD"`
		RootIsDirectory bool            `json:"rootIsDirectory"`
		RootNames       []string        `json:"rootNames"`
		RootDirents     [][]interface{} `json:"rootDirents"`
		Asset           string          `json:"asset"`
		Relative        string          `json:"relative"`
		Realpath        string          `json:"realpath"`
		MissingCode     string          `json:"missingCode"`
		RootReadCode    string          `json:"rootReadCode"`
		RootOpenCode    string          `json:"rootOpenCode"`
		RootCWD         string          `json:"rootCWD"`
		FinalCWD        string          `json:"finalCWD"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &got))
	require.Equal(t, "/data/work", got.InitialCWD)
	require.True(t, got.RootIsDirectory)
	require.Equal(t, []string{"assets", "data"}, got.RootNames)
	require.Len(t, got.RootDirents, 2)
	require.Equal(t, "asset", got.Asset)
	require.Equal(t, "relative", got.Relative)
	require.Equal(t, "/assets/asset.txt", got.Realpath)
	require.Equal(t, "ENOENT", got.MissingCode)
	require.Equal(t, "EISDIR", got.RootReadCode)
	require.Equal(t, "EISDIR", got.RootOpenCode)
	require.Equal(t, "/", got.RootCWD)
	require.Equal(t, "/data/work", got.FinalCWD)

	require.FileExists(t, filepath.Join(data, "work", "relative.txt"))
}

func TestHostRuntimeMultiMountPermissionsAndCrossMountOperations(t *testing.T) {
	assets := t.TempDir()
	data := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(assets, "asset.txt"), []byte("asset"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(data, "work"), 0o700))

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallHostRuntime(qjs.HostRuntimeOptions{
		FileSystem: qjs.FileSystemOptions{
			Mounts: []qjs.FileSystemMount{
				{Path: "/assets", Root: assets, ReadOnly: true},
				{Path: "/data", Root: data},
			},
			VirtualCWD: "/data/work",
		},
	}))

	result, err := rt.Eval("multi-mount-permissions.js", qjs.Code(`
		import fs from "fs";
		import nodeFS from "node:fs";
		import fsp from "fs/promises";
		import nodeFSP from "node:fs/promises";

		const errorInfo = error => error && ({
			code: error.code,
			path: error.path,
			dest: error.dest,
			syscall: error.syscall
		});
		const capture = fn => { try { return fn(); } catch (error) { return errorInfo(error); } };
		const captureAsync = async fn => { try { await fn(); return null; } catch (error) { return errorInfo(error); } };

		export default await (async () => {
			const errors = {};
			errors.sync = capture(() => qjs.fs.writeFileSync("../../assets/asset.txt", "blocked"));
			errors.callback = await new Promise(resolve => {
				fs.writeFile("/assets/asset.txt", "blocked", error => resolve(errorInfo(error)));
			});
			errors.promise = await captureAsync(() => nodeFSP.writeFile("/assets/asset.txt", "blocked"));
			errors.append = await captureAsync(() => fsp.appendFile("/assets/asset.txt", "blocked"));
			errors.mkdir = capture(() => nodeFS.mkdirSync("/assets/new-dir"));
			errors.unlink = await captureAsync(() => nodeFSP.unlink("/assets/asset.txt"));
			errors.utimes = capture(() => fs.utimesSync("/assets/asset.txt", 0, 0));
			errors.open = capture(() => fs.openSync("/assets/asset.txt", "r+"));

			const readFD = fs.openSync("/assets/asset.txt", "r");
			errors.readFDWrite = capture(() => fs.writeSync(readFD, "x"));
			fs.closeSync(readFD);

			await fsp.copyFile("/assets/asset.txt", "/data/work/copied.txt");
			const copied = fs.readFileSync("copied.txt", "utf8");
			errors.copyToReadOnly = await captureAsync(() => fsp.copyFile("copied.txt", "/assets/copy.txt"));

			await fsp.writeFile("rename-source.txt", "rename");
			await fsp.rename("rename-source.txt", "rename-dest.txt");
			const renamed = await nodeFSP.readFile("rename-dest.txt", "utf8");
			errors.crossRename = await captureAsync(() => nodeFSP.rename("rename-dest.txt", "/assets/renamed.txt"));

			errors.syntheticRootRemove = capture(() => fs.rmSync("/", { recursive: true }));
			errors.mountRootRemove = await captureAsync(() => fsp.rm("/data", { recursive: true }));
			errors.mountRootRename = capture(() => fs.renameSync("/data", "/assets"));

			const writeFD = fs.openSync("fd.txt", "w");
			const fdWritten = fs.writeSync(writeFD, "fd-data");
			fs.fsyncSync(writeFD);
			fs.closeSync(writeFD);

			return JSON.stringify({ errors, copied, renamed, fdWritten, fdText: fs.readFileSync("fd.txt", "utf8") });
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()

	var got struct {
		Errors map[string]*struct {
			Code    string `json:"code"`
			Path    string `json:"path"`
			Dest    string `json:"dest"`
			Syscall string `json:"syscall"`
		} `json:"errors"`
		Copied    string  `json:"copied"`
		Renamed   string  `json:"renamed"`
		FDWritten float64 `json:"fdWritten"`
		FDText    string  `json:"fdText"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &got))

	for _, name := range []string{"sync", "callback", "promise", "append", "mkdir", "unlink", "utimes", "open", "copyToReadOnly"} {
		require.NotNil(t, got.Errors[name], name)
		require.Equal(t, "EROFS", got.Errors[name].Code, name)
	}
	require.Equal(t, "../../assets/asset.txt", got.Errors["sync"].Path)
	require.Equal(t, "/assets/asset.txt", got.Errors["callback"].Path)
	require.Equal(t, "/assets/asset.txt", got.Errors["promise"].Path)
	require.Equal(t, "copied.txt", got.Errors["copyToReadOnly"].Path)
	require.Equal(t, "/assets/copy.txt", got.Errors["copyToReadOnly"].Dest)
	require.Equal(t, "EBADF", got.Errors["readFDWrite"].Code)
	require.Equal(t, "EXDEV", got.Errors["crossRename"].Code)
	require.Equal(t, "rename-dest.txt", got.Errors["crossRename"].Path)
	require.Equal(t, "/assets/renamed.txt", got.Errors["crossRename"].Dest)
	for _, name := range []string{"syntheticRootRemove", "mountRootRemove", "mountRootRename"} {
		require.Equal(t, "EBUSY", got.Errors[name].Code, name)
	}
	require.Equal(t, "asset", got.Copied)
	require.Equal(t, "rename", got.Renamed)
	require.Equal(t, float64(7), got.FDWritten)
	require.Equal(t, "fd-data", got.FDText)
	require.Equal(t, "asset", string(must(os.ReadFile(filepath.Join(assets, "asset.txt")))))
}

func TestHostRuntimeWorkerInheritsMultiMountConfiguration(t *testing.T) {
	assets := t.TempDir()
	data := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(assets, "asset.txt"), []byte("asset"), 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(assets, "worker.js"),
		[]byte(`self.postMessage({ cwd: process.cwd(), asset: qjs.fs.readFileSync("/assets/asset.txt", "utf8") });`),
		0o600,
	))

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallHostRuntime(qjs.HostRuntimeOptions{
		Profile: qjs.HostRuntimeProfileAll,
		FileSystem: qjs.FileSystemOptions{
			Mounts: []qjs.FileSystemMount{
				{Path: "/assets", Root: assets, ReadOnly: true},
				{Path: "/data", Root: data},
			},
			VirtualCWD: "/data",
		},
	}))

	workerSource := `
		const result = { cwd: process.cwd(), asset: qjs.fs.readFileSync("/assets/asset.txt", "utf8") };
		try { qjs.fs.writeFileSync("/assets/blocked.txt", "blocked"); }
		catch (error) { result.writeCode = error.code; }
		const fd = qjs.fs.openSync("worker-fd.txt", "w");
		qjs.fs.writeSync(fd, "worker");
		self.postMessage(result);
	`
	workerSourceJSON := string(must(json.Marshal(workerSource)))

	result, err := rt.Eval("multi-mount-worker.js", qjs.Code(`
		export default await (async () => {
			const parentFD = qjs.fs.openSync("parent-fd.txt", "w");
			qjs.fs.writeSync(parentFD, "before-");
			const worker = new Worker(`+workerSourceJSON+`, { eval: true });
			const messages = [];
			worker.onmessage = event => messages.push(event.data);
			for (let i = 0; i < 100 && messages.length === 0; i++) {
				worker.pollMessages();
				if (messages.length === 0) await new Promise(resolve => setTimeout(resolve, 5));
			}
			worker.terminate();
			qjs.fs.writeSync(parentFD, "after");
			qjs.fs.closeSync(parentFD);

			const pathWorker = new Worker("/assets/worker.js");
			const pathMessages = [];
			pathWorker.onmessage = event => pathMessages.push(event.data);
			for (let i = 0; i < 100 && pathMessages.length === 0; i++) {
				pathWorker.pollMessages();
				if (pathMessages.length === 0) await new Promise(resolve => setTimeout(resolve, 5));
			}
			pathWorker.terminate();
			return JSON.stringify({
				message: messages[0],
				pathMessage: pathMessages[0],
				parent: qjs.fs.readFileSync("parent-fd.txt", "utf8")
			});
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()

	var got struct {
		Message struct {
			CWD       string `json:"cwd"`
			Asset     string `json:"asset"`
			WriteCode string `json:"writeCode"`
		} `json:"message"`
		PathMessage struct {
			CWD   string `json:"cwd"`
			Asset string `json:"asset"`
		} `json:"pathMessage"`
		Parent string `json:"parent"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &got))
	require.Equal(t, "/data", got.Message.CWD)
	require.Equal(t, "asset", got.Message.Asset)
	require.Equal(t, "EROFS", got.Message.WriteCode)
	require.Equal(t, "/data", got.PathMessage.CWD)
	require.Equal(t, "asset", got.PathMessage.Asset)
	require.Equal(t, "before-after", got.Parent)
	require.Equal(t, "worker", string(must(os.ReadFile(filepath.Join(data, "worker-fd.txt")))))
}

func TestHostRuntimeMultiMountHostPathConsumers(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("Unix socket coverage is unavailable on Windows")
	}

	assets := t.TempDir()
	data := t.TempDir()
	work := filepath.Join(data, "work")
	require.NoError(t, os.Mkdir(work, 0o700))
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(data, "outside")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	shell, err := exec.LookPath("sh")
	require.NoError(t, err)
	shellJSON := string(must(json.Marshal(shell)))
	argsJSON := string(must(json.Marshal([]string{"-c", "pwd"})))

	rt := must(qjs.New(qjs.Option{CWD: t.TempDir()}))
	defer rt.Close()
	require.NoError(t, rt.InstallHostRuntime(qjs.HostRuntimeOptions{
		Profile: qjs.HostRuntimeProfileAll,
		FileSystem: qjs.FileSystemOptions{
			Mounts: []qjs.FileSystemMount{
				{Path: "/assets", Root: assets, ReadOnly: true},
				{Path: "/data", Root: data},
			},
			VirtualCWD: "/data",
		},
	}))

	result, err := rt.Eval("multi-mount-host-paths.js", qjs.Code(`
		export default (() => {
			const before = process.cwd();
			const executed = process.execFileSync(`+shellJSON+`, `+argsJSON+`, { cwd: "/data/work" });
			let readOnlySocketError = "";
			try { new PipeServerSocket("/assets/blocked.sock"); }
			catch (error) { readOnlySocketError = String(error); }
			let symlinkSocketError = "";
			try { new PipeServerSocket("/data/outside/blocked.sock"); }
			catch (error) { symlinkSocketError = String(error); }
			let symlinkExecError = "";
			try { process.execFileSync(`+shellJSON+`, `+argsJSON+`, { cwd: "/data/outside" }); }
			catch (error) { symlinkExecError = String(error); }
			const server = new PipeServerSocket("/data/runtime.sock");
			const socketPath = server.path;
			server.close();
			return JSON.stringify({
				before,
				after: process.cwd(),
				stdout: executed.stdout,
				readOnlySocketError,
				symlinkSocketError,
				symlinkExecError,
				socketPath
			});
		})();
	`), qjs.TypeModule())
	require.NoError(t, err)
	defer result.Free()

	var got struct {
		Before              string `json:"before"`
		After               string `json:"after"`
		Stdout              string `json:"stdout"`
		ReadOnlySocketError string `json:"readOnlySocketError"`
		SymlinkSocketError  string `json:"symlinkSocketError"`
		SymlinkExecError    string `json:"symlinkExecError"`
		SocketPath          string `json:"socketPath"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &got))
	require.Equal(t, "/data", got.Before)
	require.Equal(t, "/data", got.After)
	require.Equal(t, work, strings.TrimSpace(got.Stdout))
	require.Contains(t, got.ReadOnlySocketError, "read-only filesystem")
	require.Contains(t, got.SymlinkSocketError, "escapes filesystem mount")
	require.Contains(t, got.SymlinkExecError, "escapes filesystem mount")
	require.NotContains(t, got.SymlinkSocketError, outside)
	require.NotContains(t, got.SymlinkExecError, outside)
	require.Equal(t, "/data/runtime.sock", got.SocketPath)
	require.NoFileExists(t, filepath.Join(data, "runtime.sock"))
	require.NoFileExists(t, filepath.Join(outside, "blocked.sock"))
}
