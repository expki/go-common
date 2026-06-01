# database

Open a ready-to-use [GORM](https://gorm.io) `*gorm.DB` for PostgreSQL or SQLite, with the right SQLite driver picked for your build target — including the browser.

```go
db, err := database.OpenSqlitePersistent("/data/app.db")
if err != nil {
	panic(err)
}
db.AutoMigrate(&User{})
```

- `database.OpenPostgresPersistent(dsn)` — PostgreSQL via `gorm.io/driver/postgres` (not available on js/wasm).
- `database.OpenSqlitePersistent(path)` — durable on-disk SQLite.
- `database.OpenSqliteMemory()` — throwaway in-memory SQLite, handy for tests.

Every connection is opened with `SkipDefaultTransaction` and `PrepareStmt` enabled. Logging is off by default; attach a GORM logger with `WithLogger`.

## Why

GORM makes you import a driver and wire up a dialector before you can call `gorm.Open`, and the SQLite driver you want differs by platform — cgo on a normal server, pure Go when cgo is off, and a WASM-friendly driver in the browser. This package makes that choice for you at build time, so the same call works everywhere.

```go
// identical calling code on a server, in WASI, or in a browser tab:
db, _ := database.OpenSqliteMemory()
```

## Which SQLite driver you get

`sqliteDialector` is selected by build constraints, so you never import a driver yourself:

| Build | SQLite driver |
| --- | --- |
| cgo enabled (default native) | [`mattn/go-sqlite3`](https://github.com/mattn/go-sqlite3) via `gorm.io/driver/sqlite` |
| native, cgo off (`CGO_ENABLED=0` / `nocgo`) | pure-Go [`modernc.org/sqlite`](https://modernc.org/sqlite) via `github.com/libtnb/sqlite` |
| `js/wasm` (browser) | wazero-based [`ncruces/go-sqlite3`](https://github.com/ncruces/go-sqlite3) via `gormlite` |

`modernc.org/sqlite` has no `js/wasm` port, which is why the browser build uses the `ncruces` driver instead.

## Postgres

`OpenPostgresPersistent` takes a standard connection string — a libpq DSN or a `postgres://` URL:

```go
db, err := database.OpenPostgresPersistent("postgres://user:pass@localhost:5432/app?sslmode=disable")
```

Postgres is available on every target **except** `js/wasm`, where there is no TCP socket to a database server; calling it there returns an error.

## Logging

By default no SQL is logged (`logger.Discard`). Pass `WithLogger` with any `gorm/logger.Writer` and `logger.Config` to turn it on:

```go
import "gorm.io/gorm/logger"

db, _ := database.OpenSqlitePersistent("/data/app.db",
	database.WithLogger(log.New(os.Stdout, "", log.LstdFlags), logger.Config{
		LogLevel: logger.Warn,
	}))
```

## Install

```sh
go get github.com/expki/go-common/database
```

## Building

```sh
go build ./database/                          # native, cgo SQLite
CGO_ENABLED=0 go build ./database/            # native, pure-Go SQLite
GOOS=js GOARCH=wasm go build ./database/      # browser (ncruces SQLite; no Postgres)
GOOS=wasip1 GOARCH=wasm go build ./database/  # WASI
```
