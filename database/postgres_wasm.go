//go:build js && wasm

package database

import (
	"errors"

	"gorm.io/gorm"
)

// postgresDialector is unavailable in wasm/js.
func postgresDialector(_ string) (gorm.Dialector, error) {
	return nil, errors.New("postgres not supported in wasm")
}
