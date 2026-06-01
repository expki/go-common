//go:build windows || linux || darwin || android || ios || wasip1

package fs

import (
	"github.com/spf13/afero"
)

// newFs returns the platform filesystem: the host OS filesystem. This covers
// every target that exposes a real filesystem through the os package —
// including wasip1, where WASI preopened directories are reachable via os.
// Only js/wasm (the browser sandbox) needs a different backing. The dbName
// argument is only meaningful on js/wasm and is ignored here.
func newFs(_ string) afero.Fs {
	return afero.NewOsFs()
}
