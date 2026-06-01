//go:build cgo && !nocgo && (!wasm || !js)

package database

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// sqliteDialector returns the CGO SQLite driver (mattn/go-sqlite3).
func sqliteDialector(dsn string) gorm.Dialector {
	return sqlite.Open(dsn)
}
