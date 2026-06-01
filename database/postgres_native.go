//go:build !js || !wasm

package database

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// postgresDialector returns the Postgres driver (gorm.io/driver/postgres).
func postgresDialector(dsn string) (gorm.Dialector, error) {
	return postgres.Open(dsn), nil
}
