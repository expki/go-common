//go:build js && wasm

package fs

import (
	"io"
	"os"
	"sort"
	"testing"

	"github.com/spf13/afero"
)

// newTestFs returns a fresh IndexedDB-backed Fs. Each test uses its own
// database name so runs stay isolated within the same browser origin.
func newTestFs(t *testing.T) afero.Fs {
	t.Helper()
	fs := newFs("test-" + t.Name())
	t.Cleanup(func() { _ = fs.RemoveAll("/") })
	return fs
}

func TestWriteReadRoundTrip(t *testing.T) {
	fs := newTestFs(t)

	want := []byte("hello indexeddb")
	if err := afero.WriteFile(fs, "/greeting.txt", want, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := afero.ReadFile(fs, "/greeting.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("round trip mismatch: got %q want %q", got, want)
	}
}

func TestStatReportsSizeAndMode(t *testing.T) {
	fs := newTestFs(t)

	if err := afero.WriteFile(fs, "/data.bin", []byte("12345"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fi, err := fs.Stat("/data.bin")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Size() != 5 {
		t.Errorf("Size = %d, want 5", fi.Size())
	}
	if fi.IsDir() {
		t.Error("IsDir = true, want false")
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("Mode perm = %o, want 600", perm)
	}
}

func TestMkdirAllAndReaddir(t *testing.T) {
	fs := newTestFs(t)

	if err := fs.MkdirAll("/a/b", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	for _, name := range []string{"/a/one.txt", "/a/two.txt", "/a/three.txt"} {
		if err := afero.WriteFile(fs, name, []byte("x"), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
	}

	dir, err := fs.Open("/a")
	if err != nil {
		t.Fatalf("Open dir: %v", err)
	}
	defer dir.Close()

	names, err := dir.Readdirnames(-1)
	if err != nil {
		t.Fatalf("Readdirnames: %v", err)
	}
	sort.Strings(names)
	want := []string{"b", "one.txt", "three.txt", "two.txt"}
	if len(names) != len(want) {
		t.Fatalf("got %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("got %v, want %v", names, want)
		}
	}
}

func TestRename(t *testing.T) {
	fs := newTestFs(t)

	if err := afero.WriteFile(fs, "/old.txt", []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.Rename("/old.txt", "/new.txt"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := fs.Stat("/old.txt"); !os.IsNotExist(err) {
		t.Errorf("old path still exists, err = %v", err)
	}
	got, err := afero.ReadFile(fs, "/new.txt")
	if err != nil {
		t.Fatalf("ReadFile new: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("content = %q, want %q", got, "payload")
	}
}

func TestRenameDirectoryMovesChildren(t *testing.T) {
	fs := newTestFs(t)

	if err := fs.MkdirAll("/src/inner", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := afero.WriteFile(fs, "/src/inner/leaf.txt", []byte("deep"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.Rename("/src", "/dst"); err != nil {
		t.Fatalf("Rename dir: %v", err)
	}
	got, err := afero.ReadFile(fs, "/dst/inner/leaf.txt")
	if err != nil {
		t.Fatalf("ReadFile moved child: %v", err)
	}
	if string(got) != "deep" {
		t.Errorf("content = %q, want %q", got, "deep")
	}
}

func TestRemove(t *testing.T) {
	fs := newTestFs(t)

	if err := afero.WriteFile(fs, "/gone.txt", []byte("bye"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.Remove("/gone.txt"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := fs.Stat("/gone.txt"); !os.IsNotExist(err) {
		t.Errorf("file still present, err = %v", err)
	}
}

func TestRemoveNonEmptyDirFails(t *testing.T) {
	fs := newTestFs(t)

	if err := fs.MkdirAll("/full", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := afero.WriteFile(fs, "/full/file.txt", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.Remove("/full"); err == nil {
		t.Fatal("Remove of non-empty dir succeeded, want error")
	}
}

func TestSeekAndReadAt(t *testing.T) {
	fs := newTestFs(t)

	if err := afero.WriteFile(fs, "/seek.txt", []byte("0123456789"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := fs.Open("/seek.txt")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	if _, err := f.Seek(5, io.SeekStart); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	buf := make([]byte, 3)
	n, err := f.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "567" {
		t.Errorf("after seek read = %q, want %q", buf[:n], "567")
	}

	at := make([]byte, 2)
	if _, err := f.ReadAt(at, 1); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(at) != "12" {
		t.Errorf("ReadAt = %q, want %q", at, "12")
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	name := "persist-" + t.Name()
	fs1 := newFs(name)
	if err := afero.WriteFile(fs1, "/kept.txt", []byte("durable"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Reopen the same database; data written above must still be there.
	fs2 := newFs(name)
	t.Cleanup(func() { _ = fs2.RemoveAll("/") })
	got, err := afero.ReadFile(fs2, "/kept.txt")
	if err != nil {
		t.Fatalf("ReadFile after reopen: %v", err)
	}
	if string(got) != "durable" {
		t.Errorf("content = %q, want %q", got, "durable")
	}
}
