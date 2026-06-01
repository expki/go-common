//go:build js && wasm

package search

import (
	"testing"

	"github.com/blevesearch/bleve/v2"
	"github.com/expki/go-common/fs"
)

// TestPersistentIndexOnIndexedDB exercises a durable index in a real browser,
// where fs.Persistent() is backed by IndexedDB. It proves a full bleve index
// (scorch over boltdb) can be created, written, closed, reopened, and searched
// entirely on top of the IndexedDB-backed afero.Fs.
//
// Run with the wasmbrowsertest runner:
//
//	GOOS=js GOARCH=wasm go test \
//	  -exec="$(go env GOPATH)/bin/wasmbrowsertest" ./search/
func TestPersistentIndexOnIndexedDB(t *testing.T) {
	const path = "/search-browser-test-index"

	// Start from a clean slate and remove the index from IndexedDB afterward so
	// reruns within the same browser origin are deterministic.
	if err := fs.Persistent().RemoveAll(path); err != nil {
		t.Fatalf("pre-clean: %v", err)
	}
	t.Cleanup(func() { _ = fs.Persistent().RemoveAll(path) })

	idx, err := OpenPersistent(path, bleve.NewIndexMapping())
	if err != nil {
		t.Fatalf("OpenPersistent (create): %v", err)
	}
	mustIndex(t, idx, "1", article{Title: "browser search", Body: "bleve running on indexeddb"})
	mustIndex(t, idx, "2", article{Title: "second", Body: "another stored document"})

	if res := mustSearch(t, idx, bleve.NewSearchRequest(bleve.NewMatchQuery("indexeddb"))); res.Total != 1 {
		t.Fatalf("pre-close search Total = %d, want 1", res.Total)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen: the data must still be present in IndexedDB.
	reopened, err := OpenPersistent(path, bleve.NewIndexMapping())
	if err != nil {
		t.Fatalf("OpenPersistent (reopen): %v", err)
	}
	defer reopened.Close()

	if c, err := reopened.DocCount(); err != nil || c != 2 {
		t.Fatalf("DocCount after reopen = %d (err %v), want 2", c, err)
	}
	if res := mustSearch(t, reopened, bleve.NewSearchRequest(bleve.NewMatchQuery("document"))); res.Total != 1 {
		t.Errorf("search after reopen Total = %d, want 1 (data not durable in IndexedDB)", res.Total)
	}
}

// TestMemoryIndexInBrowser confirms the in-memory index also works in the
// browser without touching IndexedDB.
func TestMemoryIndexInBrowser(t *testing.T) {
	idx, err := OpenMemory(bleve.NewIndexMapping())
	if err != nil {
		t.Fatalf("OpenMemory: %v", err)
	}
	defer idx.Close()

	mustIndex(t, idx, "1", article{Title: "ephemeral browser doc"})
	if res := mustSearch(t, idx, bleve.NewSearchRequest(bleve.NewMatchQuery("ephemeral"))); res.Total != 1 {
		t.Errorf("Total = %d, want 1", res.Total)
	}
}
