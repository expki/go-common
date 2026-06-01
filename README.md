# go-common

A collection of common, reusable Go packages.

```sh
go get github.com/expki/go-common
```

## Cross-platform

Every package here is written to build and run on the full range of Go targets:

| Platform | `GOOS` / `GOARCH` |
| --- | --- |
| Linux | `linux` |
| Windows | `windows` |
| macOS | `darwin` |
| Android | `android` |
| iOS | `ios` |
| Browser wasm | `js/wasm` |
| WASI | `wasip1/wasm` |

Where a target needs a different implementation (the browser has no real filesystem, for example), the package handles it behind a common interface so your calling code stays the same everywhere.

## Packages

| Package | Description |
| --- | --- |
| [`fs`](./fs/README.md) | Process-wide persistent and in-memory filesystems backed by the OS, WASI, or IndexedDB depending on platform. |
| [`search`](./search/README.md) | Open-or-create bleve full-text indexes backed by the `fs` filesystems, so search works on every platform including the browser. |
| [`x509`](./x509/README.md) | Full X.509 certificate/CSR extension and SAN encode/decode — all nine Subject Alternative Name types and every RFC 5280 extension, byte-exact, wrapping `crypto/x509`. |

## License

See [LICENSE](./LICENSE).
