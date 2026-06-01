package search

import (
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	"github.com/blevesearch/bleve/v2"
	"github.com/spf13/afero"
)

type article struct {
	Title string   `json:"title"`
	Body  string   `json:"body"`
	Tags  []string `json:"tags"`
}

// freshIndex returns an isolated, persistent index in its own temp directory.
// Using a unique path per test keeps document counts deterministic (unlike the
// process-wide shared fs.Memory()).
func freshIndex(t *testing.T) bleve.Index {
	t.Helper()
	idx, err := OpenPersistent(filepath.Join(t.TempDir(), "idx"), bleve.NewIndexMapping())
	if err != nil {
		t.Fatalf("OpenPersistent: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	return idx
}

func mustIndex(t *testing.T, idx bleve.Index, id string, data any) {
	t.Helper()
	if err := idx.Index(id, data); err != nil {
		t.Fatalf("Index %q: %v", id, err)
	}
}

func mustSearch(t *testing.T, idx bleve.Index, req *bleve.SearchRequest) *bleve.SearchResult {
	t.Helper()
	res, err := idx.Search(req)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	return res
}

func hitIDs(res *bleve.SearchResult) []string {
	out := make([]string, len(res.Hits))
	for i, h := range res.Hits {
		out[i] = h.ID
	}
	sort.Strings(out)
	return out
}

func equalIDs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestSearchFindsOnlyMatchingDocuments(t *testing.T) {
	idx := freshIndex(t)
	mustIndex(t, idx, "1", article{Title: "Go programming", Body: "concurrency with goroutines"})
	mustIndex(t, idx, "2", article{Title: "Rust programming", Body: "ownership and borrowing"})
	mustIndex(t, idx, "3", article{Title: "Cooking", Body: "recipes and baking"})

	res := mustSearch(t, idx, bleve.NewSearchRequest(bleve.NewMatchQuery("programming")))
	if res.Total != 2 {
		t.Fatalf("Total = %d, want 2", res.Total)
	}
	if got, want := hitIDs(res), []string{"1", "2"}; !equalIDs(got, want) {
		t.Fatalf("hit IDs = %v, want %v", got, want)
	}
}

func TestSearchIsFieldScoped(t *testing.T) {
	idx := freshIndex(t)
	// "indexing" appears only in the body, "databases" only in the title.
	mustIndex(t, idx, "1", article{Title: "Databases", Body: "indexing strategies"})

	bodyQ := bleve.NewMatchQuery("indexing")
	bodyQ.SetField("body")
	if res := mustSearch(t, idx, bleve.NewSearchRequest(bodyQ)); res.Total != 1 {
		t.Errorf("body-scoped search Total = %d, want 1", res.Total)
	}

	titleQ := bleve.NewMatchQuery("indexing")
	titleQ.SetField("title")
	if res := mustSearch(t, idx, bleve.NewSearchRequest(titleQ)); res.Total != 0 {
		t.Errorf("title-scoped search for a body-only term Total = %d, want 0", res.Total)
	}
}

func TestSearchRanksMoreRelevantHigher(t *testing.T) {
	idx := freshIndex(t)
	mustIndex(t, idx, "sparse", article{Title: "mention", Body: "search appears once here"})
	mustIndex(t, idx, "dense", article{Title: "search search", Body: "search search search"})

	res := mustSearch(t, idx, bleve.NewSearchRequest(bleve.NewMatchQuery("search")))
	if res.Total != 2 {
		t.Fatalf("Total = %d, want 2", res.Total)
	}
	if res.Hits[0].ID != "dense" {
		t.Fatalf("top hit = %q, want %q (more frequent term should rank first)", res.Hits[0].ID, "dense")
	}
	if res.Hits[0].Score < res.Hits[1].Score {
		t.Errorf("scores not descending: %v then %v", res.Hits[0].Score, res.Hits[1].Score)
	}
}

func TestSearchReturnsStoredFields(t *testing.T) {
	idx := freshIndex(t)
	mustIndex(t, idx, "1", article{Title: "Hello", Body: "World"})

	req := bleve.NewSearchRequest(bleve.NewMatchQuery("hello"))
	req.Fields = []string{"title"}
	res := mustSearch(t, idx, req)
	if res.Total != 1 {
		t.Fatalf("Total = %d, want 1", res.Total)
	}
	got, ok := res.Hits[0].Fields["title"].(string)
	if !ok || got != "Hello" {
		t.Errorf("stored title = %v (ok=%v), want %q", res.Hits[0].Fields["title"], ok, "Hello")
	}
}

func TestSearchMatchesArrayField(t *testing.T) {
	idx := freshIndex(t)
	mustIndex(t, idx, "1", article{Title: "Tagged", Tags: []string{"alpha", "beta", "gamma"}})

	q := bleve.NewMatchQuery("beta")
	q.SetField("tags")
	if res := mustSearch(t, idx, bleve.NewSearchRequest(q)); res.Total != 1 {
		t.Errorf("tag search Total = %d, want 1", res.Total)
	}
}

func TestReindexUpdatesDocument(t *testing.T) {
	idx := freshIndex(t)
	mustIndex(t, idx, "1", article{Title: "obsolete heading"})
	mustIndex(t, idx, "1", article{Title: "current heading"}) // same ID overwrites

	if res := mustSearch(t, idx, bleve.NewSearchRequest(bleve.NewMatchQuery("obsolete"))); res.Total != 0 {
		t.Errorf("stale term still matches: Total = %d, want 0", res.Total)
	}
	if res := mustSearch(t, idx, bleve.NewSearchRequest(bleve.NewMatchQuery("current"))); res.Total != 1 {
		t.Errorf("updated term Total = %d, want 1", res.Total)
	}
	if c, err := idx.DocCount(); err != nil || c != 1 {
		t.Errorf("DocCount = %d (err %v), want 1", c, err)
	}
}

func TestDeleteRemovesDocument(t *testing.T) {
	idx := freshIndex(t)
	mustIndex(t, idx, "1", article{Title: "ephemeral entry"})

	if res := mustSearch(t, idx, bleve.NewSearchRequest(bleve.NewMatchQuery("ephemeral"))); res.Total != 1 {
		t.Fatalf("pre-delete Total = %d, want 1", res.Total)
	}
	if err := idx.Delete("1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if res := mustSearch(t, idx, bleve.NewSearchRequest(bleve.NewMatchQuery("ephemeral"))); res.Total != 0 {
		t.Errorf("post-delete Total = %d, want 0", res.Total)
	}
	if c, err := idx.DocCount(); err != nil || c != 0 {
		t.Errorf("DocCount = %d (err %v), want 0", c, err)
	}
}

func TestBatchIndexing(t *testing.T) {
	idx := freshIndex(t)

	batch := idx.NewBatch()
	titles := []string{"alpha", "beta", "gamma", "delta"}
	for i, title := range titles {
		if err := batch.Index(fmt.Sprintf("doc-%d", i), article{Title: title}); err != nil {
			t.Fatalf("batch.Index: %v", err)
		}
	}
	if err := idx.Batch(batch); err != nil {
		t.Fatalf("Batch: %v", err)
	}

	if c, err := idx.DocCount(); err != nil || c != uint64(len(titles)) {
		t.Fatalf("DocCount = %d (err %v), want %d", c, err, len(titles))
	}
	if res := mustSearch(t, idx, bleve.NewSearchRequest(bleve.NewMatchQuery("gamma"))); res.Total != 1 {
		t.Errorf("search after batch Total = %d, want 1", res.Total)
	}
}

func TestPhraseQuery(t *testing.T) {
	idx := freshIndex(t)
	mustIndex(t, idx, "ordered", article{Body: "the quick brown fox"})
	mustIndex(t, idx, "shuffled", article{Body: "brown the fox quick"})

	q := bleve.NewMatchPhraseQuery("quick brown fox")
	q.SetField("body")
	res := mustSearch(t, idx, bleve.NewSearchRequest(q))
	if res.Total != 1 {
		t.Fatalf("phrase query Total = %d, want 1", res.Total)
	}
	if res.Hits[0].ID != "ordered" {
		t.Errorf("phrase hit = %q, want %q", res.Hits[0].ID, "ordered")
	}
}

func TestPersistentReopenRetainsSearchableData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idx")

	idx, err := OpenPersistent(path, bleve.NewIndexMapping())
	if err != nil {
		t.Fatalf("OpenPersistent (create): %v", err)
	}
	mustIndex(t, idx, "1", article{Title: "persisted document", Body: "survives a reopen"})
	mustIndex(t, idx, "2", article{Title: "another one", Body: "also persisted"})
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := OpenPersistent(path, bleve.NewIndexMapping())
	if err != nil {
		t.Fatalf("OpenPersistent (reopen): %v", err)
	}
	defer reopened.Close()

	if c, err := reopened.DocCount(); err != nil || c != 2 {
		t.Fatalf("DocCount after reopen = %d (err %v), want 2", c, err)
	}
	if res := mustSearch(t, reopened, bleve.NewSearchRequest(bleve.NewMatchQuery("persisted"))); res.Total != 2 {
		t.Errorf("search after reopen Total = %d, want 2", res.Total)
	}
}

// TestWithFsOverridesFilesystem verifies that WithFs redirects index storage to
// a caller-supplied afero.Fs instead of the package default. Two indexes opened
// on separate filesystems stay isolated.
func TestWithFsOverridesFilesystem(t *testing.T) {
	memA := afero.NewMemMapFs()
	memB := afero.NewMemMapFs()

	idxA, err := OpenPersistent("/idx", bleve.NewIndexMapping(), WithFs(memA))
	if err != nil {
		t.Fatalf("OpenPersistent (memA): %v", err)
	}
	defer idxA.Close()
	mustIndex(t, idxA, "1", article{Title: "stored in A"})

	idxB, err := OpenPersistent("/idx", bleve.NewIndexMapping(), WithFs(memB))
	if err != nil {
		t.Fatalf("OpenPersistent (memB): %v", err)
	}
	defer idxB.Close()

	if res := mustSearch(t, idxA, bleve.NewSearchRequest(bleve.NewMatchQuery("stored"))); res.Total != 1 {
		t.Errorf("idxA Total = %d, want 1", res.Total)
	}
	if res := mustSearch(t, idxB, bleve.NewSearchRequest(bleve.NewMatchQuery("stored"))); res.Total != 0 {
		t.Errorf("idxB saw A's data: Total = %d, want 0 (filesystems not isolated)", res.Total)
	}

	// The override must have written into memA, not the real disk.
	if ok, err := afero.Exists(memA, "/idx"); err != nil || !ok {
		t.Errorf("expected index at /idx in memA (ok=%v err=%v)", ok, err)
	}
}

// TestOpenMemoryIsIndependent documents that each OpenMemory call returns its
// own ephemeral index: documents indexed in one are not visible in another.
func TestOpenMemoryIsIndependent(t *testing.T) {
	first, err := OpenMemory(bleve.NewIndexMapping())
	if err != nil {
		t.Fatalf("OpenMemory (first): %v", err)
	}
	defer first.Close()
	mustIndex(t, first, "quokka", article{Title: "quokka selfie"})
	if res := mustSearch(t, first, bleve.NewSearchRequest(bleve.NewMatchQuery("quokka"))); res.Total != 1 {
		t.Fatalf("first handle Total = %d, want 1", res.Total)
	}

	second, err := OpenMemory(bleve.NewIndexMapping())
	if err != nil {
		t.Fatalf("OpenMemory (second): %v", err)
	}
	defer second.Close()
	if res := mustSearch(t, second, bleve.NewSearchRequest(bleve.NewMatchQuery("quokka"))); res.Total != 0 {
		t.Errorf("second handle saw first handle's data: Total = %d, want 0", res.Total)
	}
}
