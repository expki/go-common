//go:build js && wasm

package database

import (
	"github.com/ncruces/go-sqlite3/gormlite"
	"gorm.io/gorm"
)

// sqliteDialector returns the pure-Go WASM SQLite driver (ncruces/go-sqlite3,
// wazero-based). modernc.org/sqlite has no js/wasm port, so the wasm build uses
// this driver instead.
func sqliteDialector(dsn string) gorm.Dialector {
	return gormlite.Open(dsn)
}
