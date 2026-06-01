// Package fs provides process-wide [afero.Fs] filesystems that behave
// consistently across native (windows/linux/darwin) and js/wasm builds.
//
// Two filesystems are offered:
//
//   - [Persistent] — durable storage that survives process restarts.
//   - [Memory]     — an ephemeral, in-process scratch filesystem.
//
// Both are lazily constructed on first call and cached for the life of the
// process, so callers can invoke them freely without coordinating setup.
// Because they return the [afero.Fs] interface, the same call sites compile and
// run on every supported platform.
//
//	f := fs.Persistent()
//	if err := afero.WriteFile(f, "/config.json", data, 0o644); err != nil {
//		return err
//	}
package fs

import (
	"sync"

	"github.com/spf13/afero"
)

// Persistent returns the process-wide durable filesystem, constructing it once
// on first call and returning the same instance thereafter.
//
// Platform behaviour:
//
//   - native (windows/linux/darwin): the host OS filesystem ([afero.NewOsFs]),
//     so paths map directly to real files on disk.
//   - js/wasm: an [afero.Fs] backed by an IndexedDB database named "expki",
//     so data persists across page reloads within the same browser origin.
//
// Use this for anything that must outlive the process: user data, caches,
// configuration.
//
// On js/wasm, the first call must run on a goroutine in main goroutine and
// not js.Func callback to open IndexedDB.
//
//	f := fs.Persistent()
//	data, err := afero.ReadFile(f, "/state.bin")
var Persistent = sync.OnceValue(func() afero.Fs { return newFs("expki") })

// Memory returns the process-wide in-memory filesystem ([afero.NewMemMapFs]),
// constructing it once on first call and returning the same instance
// thereafter.
//
// Everything written here lives only in RAM and is discarded when the process
// exits, there is no disk or IndexedDB backing on any platform. It is ideal
// for tests, temporary scratch space, and staging data before committing it to
// [Persistent].
//
// Because the instance is shared, all callers see the same files; create a
// fresh, isolated filesystem with afero.NewMemMapFs() directly when you need
// independent state (e.g. per-test isolation).
//
//	f := fs.Memory()
//	_ = afero.WriteFile(f, "/scratch.txt", []byte("temp"), 0o644)
var Memory = sync.OnceValue(func() afero.Fs { return afero.NewMemMapFs() })
