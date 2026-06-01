# search

A small wrapper around [bleve](https://github.com/blevesearch/bleve) that keeps the index on one of the [`fs`](../fs/README.md) filesystems. Same code natively and in the browser: on a server the index is files on disk, in a browser tab it's IndexedDB.

```go
idx, err := search.OpenPersistent("/data/articles", bleve.NewIndexMapping())
idx.Index("1", Article{Title: "hello world"})
res, _ := idx.Search(bleve.NewSearchRequest(bleve.NewMatchQuery("hello")))
```

- `search.OpenPersistent(path, mapping)` opens a durable index, creating it if it isn't there.
- `search.OpenMemory(mapping)` gives you a throwaway in-memory index.

Bleve makes you pick between `bleve.New` (path must not exist) and `bleve.Open` (path must exist). `OpenPersistent` picks for you.

## Why a fork of bleve

It uses [`github.com/expki/bleve`](https://github.com/expki/bleve), a fork that can store the index on any [`afero.Fs`](https://pkg.go.dev/github.com/spf13/afero#Fs), not just the OS filesystem. That's the whole trick behind browser search: the index goes through the same IndexedDB-backed filesystem the `fs` package provides. The fork is pulled in through `replace` directives (see Install).

## Where the index lives

| Target | `OpenPersistent` | `OpenMemory` |
| --- | --- | --- |
| Windows / Linux / macOS / Android / iOS | OS filesystem | RAM |
| wasip1/wasm | OS filesystem (WASI preopened dirs) | RAM |
| js/wasm | IndexedDB (`expki`) | RAM |

`OpenPersistent` uses bleve's default engine, scorch over boltdb. `OpenMemory` is the same as `bleve.NewMemOnly` (upsidedown over the in-memory gtreap store), so whatever you put in it is gone when you close it.

## Install

```sh
go get github.com/expki/go-common/search
```

That isn't enough on its own. The package pulls the bleve fork (and a few forked storage engines) through `replace` directives, and Go only honors `replace` from the main module. They don't carry over from a dependency, so you have to repeat them in your own `go.mod`. Without them the build resolves upstream bleve and won't compile:

```
replace github.com/blevesearch/bleve/v2 => github.com/expki/bleve/v2 v2.0.0-20260601001408-6dcca3e81825
replace go.etcd.io/bbolt => github.com/expki/bbolt v1.5.0-rc.0.0.20260531215528-dccadea585ba
replace github.com/couchbase/moss => github.com/expki/moss v0.3.1-0.20260531225414-59d2b052742f
replace github.com/blevesearch/goleveldb => github.com/expki/goleveldb v1.1.1-0.20260531225348-4fd0b17d74ea
replace github.com/blevesearch/zapx/v17 => github.com/expki/zapx/v17 v17.1.6-0.20260531230506-e6da921ff3d7
```

## Usage

Both functions hand back a [`bleve.Index`](https://pkg.go.dev/github.com/blevesearch/bleve/v2#Index), so the rest is plain bleve: mappings, queries, batches, facets. See the [bleve docs](https://pkg.go.dev/github.com/blevesearch/bleve/v2).

### Persistent

An index you want back after a restart.

```go
package main

import (
	"github.com/blevesearch/bleve/v2"
	"github.com/expki/go-common/search"
)

type Article struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

func main() {
	idx, err := search.OpenPersistent("/data/articles", bleve.NewIndexMapping())
	if err != nil {
		panic(err)
	}
	defer idx.Close()

	idx.Index("a1", Article{Title: "Go at scale", Body: "concurrency patterns"})

	res, err := idx.Search(bleve.NewSearchRequest(bleve.NewMatchQuery("concurrency")))
	if err != nil {
		panic(err)
	}
	for _, hit := range res.Hits {
		println(hit.ID)
	}
}
```

Run it again with the same path and it opens what's there. The mapping only matters the first time, when the index gets created.

### Memory

For tests and scratch work. Every call is a separate empty index that goes away when you close it.

```go
idx, _ := search.OpenMemory(bleve.NewIndexMapping())
defer idx.Close()
idx.Index("1", Article{Title: "temporary"})
```

### Overriding the filesystem

`OpenPersistent` defaults to `fs.Persistent()` and `OpenMemory` to `fs.Memory()`. Pass `WithFs` to use a different `afero.Fs` instead, e.g. an isolated one in tests:

```go
idx, _ := search.OpenPersistent("/idx", mapping, search.WithFs(afero.NewMemMapFs()))
```

The default is only built when you don't pass `WithFs`, so on js/wasm you can hand it your own fs and skip opening IndexedDB.

## Platform notes

### js/wasm: open the index on the main goroutine first

On js/wasm, `OpenPersistent` opens IndexedDB through `fs.Persistent()`. That's async: it parks the goroutine until the browser's event loop runs the completion. Make the first call from inside a synchronous `js.Func` callback and you deadlock. Open it once at startup on the main goroutine, or pass `WithFs` to avoid IndexedDB entirely. The [fs platform notes](../fs/README.md#jswasm-warm-up-persistent-on-the-main-goroutine) spell out why.

### The two wasm targets differ

`wasip1/wasm` writes the index to a real filesystem; `js/wasm` writes it to IndexedDB. Same code, different backing. More in the [fs README](../fs/README.md#the-two-wasm-builds-arent-the-same).

## Testing

Native:

```sh
go test ./search/
```

The browser path (bleve on IndexedDB) lives in `//go:build js && wasm` tests, run through [`wasmbrowsertest`](https://github.com/agnivade/wasmbrowsertest) in headless Chrome:

```sh
go install github.com/agnivade/wasmbrowsertest@latest
GOOS=js GOARCH=wasm go test -exec="$(go env GOPATH)/bin/wasmbrowsertest" ./search/
```

## Building

```sh
go build ./...                                          # native (host)
GOOS=js GOARCH=wasm go build ./search/                  # browser -> IndexedDB
GOOS=wasip1 GOARCH=wasm go build ./search/              # WASI -> OS filesystem
GOOS=android GOARCH=arm64 go build ./search/            # android
GOOS=ios GOARCH=arm64 CGO_ENABLED=1 go build ./search/  # ios
```
