// Package search provides convenient access to a [bleve] full-text index
// backed by one of the cross-platform filesystems from the fs package.
//
//   - [OpenPersistent] opens a durable index on [fs.Persistent] (OS filesystem,
//     WASI, or IndexedDB depending on platform), creating it if it does not yet
//     exist — unlike bleve, where [bleve.New] and [bleve.Open] are separate.
//   - [OpenMemory] creates an ephemeral in-memory index on [fs.Memory].
//
// Both work on every target the fs package supports because the index's
// storage is the afero.Fs passed through to bleve as map[string]any{"fs": ...}.
// The backing filesystem can be overridden per call with [WithFs].
package search

import (
	"errors"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/index/upsidedown"
	"github.com/blevesearch/bleve/v2/mapping"
	"github.com/expki/go-common/fs"
	"github.com/spf13/afero"
)

// OpenPersistent opens the durable bleve index at path on [fs.Persistent],
// creating it with m if it does not yet exist. It uses bleve's default index
// type and kvstore (scorch over boltdb), so the index survives restarts.
func OpenPersistent(path string, m mapping.IndexMapping, opts ...Option) (bleve.Index, error) {
	o := resolve(fs.Persistent, opts)
	config := map[string]any{"fs": o.fs}

	idx, err := bleve.OpenUsing(path, config)
	if err == nil {
		return idx, nil
	}
	if !errors.Is(err, bleve.ErrorIndexPathDoesNotExist) {
		return nil, err
	}
	return bleve.NewUsing(path, m, bleve.Config.DefaultIndexType, bleve.Config.DefaultKVStore, config)
}

// OpenMemory creates an in-memory bleve index, mirroring [bleve.NewMemOnly]: the
// upsidedown index type over the in-memory gtreap kvstore. Its contents are NOT
// persisted, they live only for the lifetime of the returned index and are
// lost once it is closed. [fs.Memory] is supplied for the index metadata only.
func OpenMemory(m mapping.IndexMapping, opts ...Option) (bleve.Index, error) {
	o := resolve(fs.Memory, opts)
	config := map[string]any{"fs": o.fs}
	return bleve.NewUsing("", m, upsidedown.Name, bleve.Config.DefaultMemKVStore, config)
}

// Option customizes how an index is opened. Pass options to [OpenPersistent] or
// [OpenMemory].
type Option func(*options)

type options struct {
	fs afero.Fs
}

// WithFs overrides the afero.Fs backing the index. By default [OpenPersistent]
// uses [fs.Persistent] and [OpenMemory] uses [fs.Memory]; supply WithFs to use
// any other afero.Fs
func WithFs(filesystem afero.Fs) Option {
	return func(o *options) { o.fs = filesystem }
}

func resolve(defaultFs func() afero.Fs, opts []Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if o.fs == nil {
		o.fs = defaultFs()
	}
	return o
}
