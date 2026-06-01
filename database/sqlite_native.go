//go:build (!cgo || nocgo) && (!wasm || !js)

package database

import (
	"github.com/libtnb/sqlite"
	"gorm.io/gorm"
)

// sqliteDialector returns the pure-Go SQLite driver (modernc.org/sqlite).
func sqliteDialector(dsn string) gorm.Dialector {
	return sqlite.Open(dsn)
}
