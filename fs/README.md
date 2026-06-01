# fs

Two filesystems for the price of one import. Both return [`afero.Fs`](https://pkg.go.dev/github.com/spf13/afero#Fs), so your code looks the same whether it's running on a server, a phone, or in a browser tab. The backing storage swaps out per platform at build time.

```go
f := fs.Persistent()
afero.WriteFile(f, "/config.json", data, 0o644)
```

- `fs.Persistent()` keeps data around after the process exits.
- `fs.Memory()` is a RAM-only scratch space that vanishes when the process does.

Each is built once on first use (`sync.OnceValue`) and reused after that, so calling them repeatedly is cheap and you don't need any setup step.

## Where data actually goes

| Target | `Persistent()` | `Memory()` |
| --- | --- | --- |
| Windows / Linux / macOS / Android / iOS | OS filesystem | RAM |
| wasip1/wasm | OS filesystem (WASI preopened dirs) | RAM |
| js/wasm | IndexedDB (`expki`) | RAM |

Everything that has a real filesystem uses it. The browser is the exception: there's no filesystem to write to, so `Persistent()` stores data in IndexedDB instead, keyed under a database named `expki`. It survives page reloads on the same origin.

## Install

```sh
go get github.com/expki/go-common/fs
```

## Usage

It's just afero. See the [afero docs](https://pkg.go.dev/github.com/spf13/afero) for the full API.

### Persistent

For config, caches, user data, anything you want to find again later.

```go
package main

import (
	"github.com/expki/go-common/fs"
	"github.com/spf13/afero"
)

func main() {
	f := fs.Persistent()

	if err := afero.WriteFile(f, "/config.json", []byte(`{"theme":"dark"}`), 0o644); err != nil {
		panic(err)
	}

	data, err := afero.ReadFile(f, "/config.json")
	if err != nil {
		panic(err)
	}
	_ = data
}
```

### Memory

Good for tests and temporary work.

```go
f := fs.Memory()
afero.WriteFile(f, "/scratch.txt", []byte("temp"), 0o644)
```

`fs.Memory()` hands back one shared instance, so everyone sees the same files. If you want isolation (per-test, say), skip it and make your own:

```go
f := afero.NewMemMapFs()
```

## Platform notes

### Android and iOS

Nothing special to do. Go counts `GOOS=android` as `linux` and `GOOS=ios` as `darwin` for build tags, so both land on the OS filesystem automatically.

The usual sandboxing still applies at runtime: you can only touch the directories the OS hands your app. That's a permissions question, not a fs one.

### The two wasm builds aren't the same

`GOARCH=wasm` covers two different runtimes:

- **wasip1/wasm** runs under a WASI host (Wasmtime, Wasmer, WasmEdge, …) and gets a real filesystem through preopened directories. `Persistent()` reads and writes actual files.
- **js/wasm** runs in a browser, which has no filesystem, so `Persistent()` falls back to IndexedDB.

The goroutine caveat below is a browser-only thing.

### js/wasm: warm up Persistent on the main goroutine

Opening IndexedDB is async. The first `fs.Persistent()` call registers a JS callback and parks the goroutine until that callback fires on the event loop.

If you make that first call from inside a synchronous `js.Func` callback (a click handler, say), you deadlock: the callback is hogging the event loop, so the IndexedDB completion can never run, so the callback never returns.

Open it once at startup, on the main goroutine:

```go
//go:build js && wasm

func main() {
	f := fs.Persistent() // main goroutine yields to the loop, so this completes
	// register handlers that use f
	select {}
}
```

After that first call it's cached, so reusing it from a callback is fine. If you really need to reach it from a callback before it's warm, kick it to a goroutine so the callback can return:

```go
js.Global().Set("onClick", js.FuncOf(func(this js.Value, args []js.Value) any {
	go func() {
		f := fs.Persistent()
		// use f
	}()
	return nil
}))
```

None of this applies off the browser. On every other target `Persistent()` returns immediately.

## Building

```sh
go build ./...                                      # native (host)
GOOS=js GOARCH=wasm go build ./fs/                  # browser -> IndexedDB
GOOS=wasip1 GOARCH=wasm go build ./fs/              # WASI -> OS filesystem
GOOS=android GOARCH=arm64 go build ./fs/            # android
GOOS=ios GOARCH=arm64 CGO_ENABLED=1 go build ./fs/  # ios
```
