package search

import (
	"path/filepath"
	"testing"

	"github.com/blevesearch/bleve/v2"
)

type doc struct {
	Title string `json:"title"`
}

func TestOpenPersistentCreatesThenReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idx")

	// First call: index does not exist, so it is created with the mapping.
	idx, err := OpenPersistent(path, bleve.NewIndexMapping())
	if err != nil {
		t.Fatalf("OpenPersistent (create): %v", err)
	}
	if err := idx.Index("a", doc{Title: "hello world"}); err != nil {
		t.Fatalf("Index: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Second call: index now exists, so it is opened (mapping ignored).
	idx2, err := OpenPersistent(path, bleve.NewIndexMapping())
	if err != nil {
		t.Fatalf("OpenPersistent (reopen): %v", err)
	}
	defer idx2.Close()

	count, err := idx2.DocCount()
	if err != nil {
		t.Fatalf("DocCount: %v", err)
	}
	if count != 1 {
		t.Fatalf("DocCount = %d, want 1 (data did not survive reopen)", count)
	}

	res, err := idx2.Search(bleve.NewSearchRequest(bleve.NewMatchQuery("hello")))
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Total != 1 {
		t.Fatalf("search hits = %d, want 1", res.Total)
	}
}

func TestOpenMemoryIndexAndSearch(t *testing.T) {
	idx, err := OpenMemory(bleve.NewIndexMapping())
	if err != nil {
		t.Fatalf("OpenMemory: %v", err)
	}
	defer idx.Close()

	if err := idx.Index("x", doc{Title: "scratch space"}); err != nil {
		t.Fatalf("Index: %v", err)
	}
	res, err := idx.Search(bleve.NewSearchRequest(bleve.NewMatchQuery("scratch")))
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Total != 1 {
		t.Fatalf("search hits = %d, want 1", res.Total)
	}
}
