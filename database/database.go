// Package database opens preconfigured [gorm.DB] connections for PostgreSQL and
// SQLite. It selects the right SQLite driver for the build target — the cgo
// driver, the pure-Go driver, or the wazero-based driver on js/wasm — so the
// same calling code works on every platform the module supports. Postgres is
// available everywhere except js/wasm.
package database

import (
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// OpenPostgresPersistent opens a [gorm.DB] backed by PostgreSQL using the
// connection string path (a libpq DSN or postgres:// URL). It is not available
// on js/wasm.
func OpenPostgresPersistent(path string, opts ...Option) (*gorm.DB, error) {
	o := loadOptions(opts)
	dialector, err := postgresDialector(path)
	if err != nil {
		return nil, err
	}
	return gorm.Open(dialector, &gorm.Config{
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
		Logger:                 o.logger,
	})
}

// OpenSqlitePersistent opens a durable, on-disk SQLite [gorm.DB] at path. The
// underlying SQLite driver is selected at build time: the cgo driver
// (mattn/go-sqlite3) when cgo is enabled, the pure-Go driver (modernc.org/sqlite)
// for native builds without cgo, and the wazero-based driver
// (ncruces/go-sqlite3) on js/wasm.
func OpenSqlitePersistent(path string, opts ...Option) (*gorm.DB, error) {
	o := loadOptions(opts)
	dialector := sqliteDialector(path)
	return gorm.Open(dialector, &gorm.Config{
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
		Logger:                 o.logger,
	})
}

// OpenSqliteMemory opens an ephemeral in-memory SQLite [gorm.DB]
// (DSN file::memory:). Its contents live only for the lifetime of the returned
// connection and are lost when it is closed — useful for tests. It uses the same
// platform-selected SQLite driver as [OpenSqlitePersistent].
func OpenSqliteMemory(opts ...Option) (*gorm.DB, error) {
	o := loadOptions(opts)
	dialector := sqliteDialector("file::memory:")
	return gorm.Open(dialector, &gorm.Config{
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
		Logger:                 o.logger,
	})
}

// Option customizes how a database connection is opened. Pass options to
// [OpenPostgresPersistent], [OpenSqlitePersistent], or [OpenSqliteMemory].
type Option func(*options)

type options struct {
	logger logger.Interface
}

// WithLogger sets the GORM logger for the connection.
func WithLogger(writer logger.Writer, config logger.Config) Option {
	return func(o *options) { o.logger = logger.New(writer, config) }
}

func loadOptions(opts []Option) options {
	o := options{
		logger: logger.Discard,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
