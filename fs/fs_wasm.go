//go:build js && wasm

package fs

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"syscall/js"
	"time"

	"github.com/spf13/afero"
)

const storeName = "files"

var (
	errIsDir    = errors.New("is a directory")
	errNotDir   = errors.New("not a directory")
	errNotEmpty = errors.New("directory not empty")
	errBadFD    = errors.New("bad file descriptor")
)

// fs is an afero.Fs backed by an IndexedDB database.
type fs struct {
	db     js.Value // the IDBDatabase handle
	dbName string
	mu     sync.Mutex // serializes operations (also avoids overlapping IDB txns)
}

// newFs opens (creating if necessary) the IndexedDB database named dbName and
// returns an afero.Fs backed by it. It must be called from a goroutine that can
// yield to the JS event loop (e.g. the main goroutine), not from within a
// synchronous js.Func callback.
func newFs(dbName string) afero.Fs {
	fs := &fs{dbName: dbName}
	if err := fs.openDB(); err != nil {
		slog.Error("fs: open database", "name", dbName, "error", err)
		panic("fs: open database " + dbName + ": " + err.Error())
	}
	// Ensure the root directory record exists.
	if _, ok, err := fs.dbGet("/"); err != nil {
		slog.Error("fs: open root", "error", err)
		panic("fs: open root: " + err.Error())
	} else if !ok {
		if err := fs.dbPut("/", makeRecord(nil, 0o755|os.ModeDir, time.Now(), true)); err != nil {
			slog.Error("fs: create root", "error", err)
			panic("fs: create root: " + err.Error())
		}
	}
	return fs
}

func (fs *fs) Name() string { return "IndexedDBFs(" + fs.dbName + ")" }

// ---------------------------------------------------------------------------
// IndexedDB plumbing
// ---------------------------------------------------------------------------

func (fs *fs) openDB() error {
	idb := js.Global().Get("indexedDB")
	if !idb.Truthy() {
		return errors.New("idbfs: indexedDB is not available in this environment")
	}
	req := idb.Call("open", fs.dbName, 1)

	upgrade := js.FuncOf(func(this js.Value, args []js.Value) any {
		db := req.Get("result")
		if !db.Get("objectStoreNames").Call("contains", storeName).Bool() {
			db.Call("createObjectStore", storeName)
		}
		return nil
	})
	defer upgrade.Release()
	req.Set("onupgradeneeded", upgrade)

	res, err := awaitRequest(req)
	if err != nil {
		return err
	}
	fs.db = res
	return nil
}

// awaitRequest registers success/error handlers on a single IDBRequest and
// blocks until one fires. Use this only for operations that complete in one
// request; cursor walks are handled separately so the transaction stays alive.
func awaitRequest(req js.Value) (js.Value, error) {
	ch := make(chan struct{})
	var result js.Value
	var failErr error

	var onSuccess, onError js.Func
	onSuccess = js.FuncOf(func(this js.Value, args []js.Value) any {
		result = req.Get("result")
		close(ch)
		return nil
	})
	onError = js.FuncOf(func(this js.Value, args []js.Value) any {
		failErr = jsError(req.Get("error"))
		close(ch)
		return nil
	})
	req.Set("onsuccess", onSuccess)
	req.Set("onerror", onError)

	<-ch
	onSuccess.Release()
	onError.Release()
	return result, failErr
}

func jsError(e js.Value) error {
	if !e.Truthy() {
		return errors.New("idbfs: unknown IndexedDB error")
	}
	return errors.New("idbfs: " + e.Get("name").String() + ": " + e.Get("message").String())
}

func (fs *fs) store(mode string) js.Value {
	txn := fs.db.Call("transaction", storeName, mode)
	return txn.Call("objectStore", storeName)
}

func (fs *fs) dbGet(key string) (js.Value, bool, error) {
	req := fs.store("readonly").Call("get", key)
	res, err := awaitRequest(req)
	if err != nil {
		return js.Undefined(), false, err
	}
	if !res.Truthy() {
		return js.Undefined(), false, nil
	}
	return res, true, nil
}

func (fs *fs) dbPut(key string, record js.Value) error {
	req := fs.store("readwrite").Call("put", record, key)
	_, err := awaitRequest(req)
	return err
}

func (fs *fs) dbDelete(key string) error {
	req := fs.store("readwrite").Call("delete", key)
	_, err := awaitRequest(req)
	return err
}

type kv struct {
	key string
	val js.Value
}

// scanRange walks every record whose key is in [lower, upper] (inclusive),
// driving the cursor entirely inside the success callback so the transaction
// stays active across steps. visit is called for each entry; if it returns
// false the walk stops early.
func (fs *fs) scanRange(lower, upper string, visit func(key string, val js.Value) bool) error {
	ch := make(chan struct{})
	var failErr error

	rng := js.Global().Get("IDBKeyRange").Call("bound", lower, upper, false, false)
	req := fs.store("readonly").Call("openCursor", rng)

	var onSuccess, onError js.Func
	onSuccess = js.FuncOf(func(this js.Value, args []js.Value) any {
		cursor := req.Get("result")
		if !cursor.Truthy() {
			close(ch)
			return nil
		}
		key := cursor.Get("key").String()
		val := cursor.Get("value")
		if !visit(key, val) {
			close(ch)
			return nil
		}
		cursor.Call("continue")
		return nil
	})
	onError = js.FuncOf(func(this js.Value, args []js.Value) any {
		failErr = jsError(req.Get("error"))
		close(ch)
		return nil
	})
	req.Set("onsuccess", onSuccess)
	req.Set("onerror", onError)

	<-ch
	onSuccess.Release()
	onError.Release()
	return failErr
}

// descendants returns every record strictly below dir (the dir's own record is
// excluded). dir must be a normalized path.
func (fs *fs) descendants(dir string) ([]kv, error) {
	prefix := dir
	if prefix != "/" {
		prefix += "/"
	}
	var out []kv
	err := fs.scanRange(prefix, prefix+"￿", func(key string, val js.Value) bool {
		if key == dir {
			return true
		}
		out = append(out, kv{key: key, val: val})
		return true
	})
	return out, err
}

// children returns FileInfos for the immediate children of dir.
func (fs *fs) children(dir string) ([]os.FileInfo, error) {
	var prefix string
	if dir == "/" {
		prefix = "/"
	} else {
		prefix = dir + "/"
	}
	var out []os.FileInfo
	err := fs.scanRange(prefix, prefix+"￿", func(key string, val js.Value) bool {
		rel := strings.TrimPrefix(key, prefix)
		if rel == "" || strings.Contains(rel, "/") {
			return true // skip self and deeper descendants
		}
		out = append(out, recordToInfo(rel, val))
		return true
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Record encoding
// ---------------------------------------------------------------------------

func makeRecord(data []byte, mode os.FileMode, modTime time.Time, isDir bool) js.Value {
	obj := js.Global().Get("Object").New()
	obj.Set("data", bytesToJS(data))
	obj.Set("mode", int(mode))
	obj.Set("modTime", float64(modTime.UnixMilli()))
	obj.Set("isDir", isDir)
	return obj
}

func recordToInfo(base string, rec js.Value) *fileInfo {
	isDir := rec.Get("isDir").Bool()
	var size int64
	if d := rec.Get("data"); d.Truthy() {
		size = int64(d.Get("length").Int())
	}
	return &fileInfo{
		name:    base,
		size:    size,
		mode:    os.FileMode(rec.Get("mode").Int()),
		modTime: time.UnixMilli(int64(rec.Get("modTime").Float())),
		isDir:   isDir,
	}
}

func bytesToJS(b []byte) js.Value {
	arr := js.Global().Get("Uint8Array").New(len(b))
	if len(b) > 0 {
		js.CopyBytesToJS(arr, b)
	}
	return arr
}

func jsToBytes(v js.Value) []byte {
	if !v.Truthy() {
		return nil
	}
	n := v.Get("length").Int()
	b := make([]byte, n)
	if n > 0 {
		js.CopyBytesToGo(b, v)
	}
	return b
}

func normalize(name string) string {
	if name == "" {
		return "/"
	}
	return path.Clean("/" + strings.ReplaceAll(name, "\\", "/"))
}

// ---------------------------------------------------------------------------
// Helpers shared by Fs methods
// ---------------------------------------------------------------------------

func (fs *fs) stat(p string) (*fileInfo, bool, error) {
	rec, ok, err := fs.dbGet(p)
	if err != nil || !ok {
		return nil, ok, err
	}
	return recordToInfo(path.Base(p), rec), true, nil
}

func (fs *fs) parentIsDir(p string) (bool, error) {
	parent := path.Dir(p)
	if parent == p { // root
		return true, nil
	}
	fi, ok, err := fs.stat(parent)
	if err != nil {
		return false, err
	}
	return ok && fi.isDir, nil
}

// ---------------------------------------------------------------------------
// afero.Fs implementation
// ---------------------------------------------------------------------------

func (fs *fs) Create(name string) (afero.File, error) {
	return fs.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}

func (fs *fs) Open(name string) (afero.File, error) {
	return fs.OpenFile(name, os.O_RDONLY, 0)
}

func (fs *fs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	p := normalize(name)
	acc := flag & 0x3 // O_RDONLY/O_WRONLY/O_RDWR live in the low two bits
	wantWrite := acc == os.O_WRONLY || acc == os.O_RDWR

	rec, ok, err := fs.dbGet(p)
	if err != nil {
		return nil, err
	}

	switch {
	case ok && flag&os.O_CREATE != 0 && flag&os.O_EXCL != 0:
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrExist}

	case !ok && flag&os.O_CREATE == 0:
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}

	case !ok: // create a new, empty file
		if okParent, err := fs.parentIsDir(p); err != nil {
			return nil, err
		} else if !okParent {
			return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
		}
		now := time.Now()
		if err := fs.dbPut(p, makeRecord(nil, perm.Perm(), now, false)); err != nil {
			return nil, err
		}
		return &file{fs: fs, name: p, flag: flag, mode: perm.Perm(), modTime: now}, nil
	}

	// The path already exists.
	info := recordToInfo(path.Base(p), rec)
	if info.isDir {
		if wantWrite {
			return nil, &os.PathError{Op: "open", Path: name, Err: errIsDir}
		}
		return &file{fs: fs, name: p, flag: flag, mode: info.mode, modTime: info.modTime, isDir: true}, nil
	}

	data := jsToBytes(rec.Get("data"))
	if wantWrite && flag&os.O_TRUNC != 0 {
		data = nil
	}
	f := &file{
		fs:      fs,
		name:    p,
		flag:    flag,
		mode:    info.mode,
		modTime: info.modTime,
		data:    data,
	}
	if flag&os.O_TRUNC != 0 && wantWrite {
		f.dirty = true
	}
	return f, nil
}

func (fs *fs) Mkdir(name string, perm os.FileMode) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.mkdir(name, perm)
}

func (fs *fs) mkdir(name string, perm os.FileMode) error {
	p := normalize(name)
	if _, ok, err := fs.dbGet(p); err != nil {
		return err
	} else if ok {
		return &os.PathError{Op: "mkdir", Path: name, Err: os.ErrExist}
	}
	if okParent, err := fs.parentIsDir(p); err != nil {
		return err
	} else if !okParent {
		return &os.PathError{Op: "mkdir", Path: name, Err: os.ErrNotExist}
	}
	return fs.dbPut(p, makeRecord(nil, perm.Perm()|os.ModeDir, time.Now(), true))
}

func (fs *fs) MkdirAll(p string, perm os.FileMode) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	target := normalize(p)
	if target == "/" {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(target, "/"), "/")
	cur := ""
	for _, part := range parts {
		cur += "/" + part
		fi, ok, err := fs.stat(cur)
		if err != nil {
			return err
		}
		if ok {
			if !fi.isDir {
				return &os.PathError{Op: "mkdir", Path: cur, Err: errNotDir}
			}
			continue
		}
		if err := fs.dbPut(cur, makeRecord(nil, perm.Perm()|os.ModeDir, time.Now(), true)); err != nil {
			return err
		}
	}
	return nil
}

func (fs *fs) Remove(name string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	p := normalize(name)
	if p == "/" {
		return &os.PathError{Op: "remove", Path: name, Err: errNotEmpty}
	}
	fi, ok, err := fs.stat(p)
	if err != nil {
		return err
	}
	if !ok {
		return &os.PathError{Op: "remove", Path: name, Err: os.ErrNotExist}
	}
	if fi.isDir {
		kids, err := fs.children(p)
		if err != nil {
			return err
		}
		if len(kids) > 0 {
			return &os.PathError{Op: "remove", Path: name, Err: errNotEmpty}
		}
	}
	return fs.dbDelete(p)
}

func (fs *fs) RemoveAll(p string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	root := normalize(p)
	kids, err := fs.descendants(root)
	if err != nil {
		return err
	}
	for _, e := range kids {
		if err := fs.dbDelete(e.key); err != nil {
			return err
		}
	}
	if root != "/" {
		if _, ok, err := fs.dbGet(root); err != nil {
			return err
		} else if ok {
			return fs.dbDelete(root)
		}
	}
	return nil
}

func (fs *fs) Rename(oldname, newname string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	op := normalize(oldname)
	np := normalize(newname)
	if op == "/" {
		return &os.PathError{Op: "rename", Path: oldname, Err: errIsDir}
	}
	if op == np {
		return nil
	}

	rec, ok, err := fs.dbGet(op)
	if err != nil {
		return err
	}
	if !ok {
		return &os.LinkError{Op: "rename", Old: oldname, New: newname, Err: os.ErrNotExist}
	}
	if okParent, err := fs.parentIsDir(np); err != nil {
		return err
	} else if !okParent {
		return &os.LinkError{Op: "rename", Old: oldname, New: newname, Err: os.ErrNotExist}
	}

	// Move descendants first (so a crash leaves the old tree intact-ish).
	kids, err := fs.descendants(op)
	if err != nil {
		return err
	}
	for _, e := range kids {
		dest := np + strings.TrimPrefix(e.key, op)
		if err := fs.dbPut(dest, e.val); err != nil {
			return err
		}
		if err := fs.dbDelete(e.key); err != nil {
			return err
		}
	}
	// Move the node itself.
	if err := fs.dbPut(np, rec); err != nil {
		return err
	}
	return fs.dbDelete(op)
}

func (fs *fs) Stat(name string) (os.FileInfo, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	p := normalize(name)
	fi, ok, err := fs.stat(p)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &os.PathError{Op: "stat", Path: name, Err: os.ErrNotExist}
	}
	return fi, nil
}

func (fs *fs) Chmod(name string, mode os.FileMode) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	p := normalize(name)
	rec, ok, err := fs.dbGet(p)
	if err != nil {
		return err
	}
	if !ok {
		return &os.PathError{Op: "chmod", Path: name, Err: os.ErrNotExist}
	}
	isDir := rec.Get("isDir").Bool()
	newMode := mode.Perm()
	if isDir {
		newMode |= os.ModeDir
	}
	rec.Set("mode", int(newMode))
	return fs.dbPut(p, rec)
}

// Chown is a no-op (the browser has no uid/gid) but validates existence.
func (fs *fs) Chown(name string, uid, gid int) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	p := normalize(name)
	if _, ok, err := fs.dbGet(p); err != nil {
		return err
	} else if !ok {
		return &os.PathError{Op: "chown", Path: name, Err: os.ErrNotExist}
	}
	return nil
}

func (fs *fs) Chtimes(name string, atime, mtime time.Time) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	p := normalize(name)
	rec, ok, err := fs.dbGet(p)
	if err != nil {
		return err
	}
	if !ok {
		return &os.PathError{Op: "chtimes", Path: name, Err: os.ErrNotExist}
	}
	rec.Set("modTime", float64(mtime.UnixMilli()))
	return fs.dbPut(p, rec)
}

// ---------------------------------------------------------------------------
// fileInfo
// ---------------------------------------------------------------------------

type fileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	isDir   bool
}

func (fi *fileInfo) Name() string { return fi.name }
func (fi *fileInfo) Size() int64  { return fi.size }
func (fi *fileInfo) Mode() os.FileMode {
	if fi.isDir {
		return fi.mode | os.ModeDir
	}
	return fi.mode
}
func (fi *fileInfo) ModTime() time.Time { return fi.modTime }
func (fi *fileInfo) IsDir() bool        { return fi.isDir }
func (fi *fileInfo) Sys() any           { return nil }

// ---------------------------------------------------------------------------
// file (afero.File)
// ---------------------------------------------------------------------------

type file struct {
	fs      *fs
	name    string
	flag    int
	mode    os.FileMode
	modTime time.Time
	isDir   bool

	mu     sync.Mutex
	data   []byte
	pos    int64
	dirty  bool
	closed bool

	// directory iteration state
	dirLoaded  bool
	dirEntries []os.FileInfo
	dirRead    int
}

func (f *file) Name() string { return f.name }

func (f *file) readable() bool {
	acc := f.flag & 0x3
	return acc == os.O_RDONLY || acc == os.O_RDWR
}

func (f *file) writable() bool {
	acc := f.flag & 0x3
	return acc == os.O_WRONLY || acc == os.O_RDWR
}

func (f *file) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	if f.isDir {
		return 0, &os.PathError{Op: "read", Path: f.name, Err: errIsDir}
	}
	if !f.readable() {
		return 0, &os.PathError{Op: "read", Path: f.name, Err: errBadFD}
	}
	if f.pos >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.pos:])
	f.pos += int64(n)
	return n, nil
}

func (f *file) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	if !f.readable() {
		return 0, &os.PathError{Op: "read", Path: f.name, Err: errBadFD}
	}
	if off < 0 {
		return 0, &os.PathError{Op: "readat", Path: f.name, Err: errors.New("negative offset")}
	}
	if off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (f *file) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	if !f.writable() {
		return 0, &os.PathError{Op: "write", Path: f.name, Err: errBadFD}
	}
	if f.flag&os.O_APPEND != 0 {
		f.pos = int64(len(f.data))
	}
	n := f.writeAt(p, f.pos)
	f.pos += int64(n)
	return n, nil
}

func (f *file) WriteAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	if !f.writable() {
		return 0, &os.PathError{Op: "write", Path: f.name, Err: errBadFD}
	}
	if off < 0 {
		return 0, &os.PathError{Op: "writeat", Path: f.name, Err: errors.New("negative offset")}
	}
	return f.writeAt(p, off), nil
}

// writeAt grows the buffer as needed and copies p in at off. Caller holds f.mu.
func (f *file) writeAt(p []byte, off int64) int {
	end := off + int64(len(p))
	if end > int64(len(f.data)) {
		grown := make([]byte, end)
		copy(grown, f.data)
		f.data = grown
	}
	n := copy(f.data[off:], p)
	if n > 0 {
		f.dirty = true
	}
	return n
}

func (f *file) WriteString(s string) (int, error) {
	return f.Write([]byte(s))
}

func (f *file) Seek(offset int64, whence int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = f.pos + offset
	case io.SeekEnd:
		abs = int64(len(f.data)) + offset
	default:
		return 0, &os.PathError{Op: "seek", Path: f.name, Err: errors.New("invalid whence")}
	}
	if abs < 0 {
		return 0, &os.PathError{Op: "seek", Path: f.name, Err: errors.New("negative position")}
	}
	f.pos = abs
	return abs, nil
}

func (f *file) Truncate(size int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return os.ErrClosed
	}
	if !f.writable() {
		return &os.PathError{Op: "truncate", Path: f.name, Err: errBadFD}
	}
	if size < 0 {
		return &os.PathError{Op: "truncate", Path: f.name, Err: errors.New("negative size")}
	}
	if size <= int64(len(f.data)) {
		f.data = f.data[:size]
	} else {
		grown := make([]byte, size)
		copy(grown, f.data)
		f.data = grown
	}
	f.dirty = true
	return nil
}

func (f *file) Sync() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sync()
}

// sync writes the buffer back to IndexedDB if dirty. Caller holds f.mu.
func (f *file) sync() error {
	if f.closed {
		return os.ErrClosed
	}
	if !f.dirty || f.isDir {
		return nil
	}
	f.modTime = time.Now()
	rec := makeRecord(f.data, f.mode, f.modTime, false)
	if err := f.fs.dbPut(f.name, rec); err != nil {
		return err
	}
	f.dirty = false
	return nil
}

func (f *file) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return os.ErrClosed
	}
	if err := f.sync(); err != nil {
		return err
	}
	f.closed = true
	return nil
}

func (f *file) Stat() (os.FileInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, os.ErrClosed
	}
	return &fileInfo{
		name:    path.Base(f.name),
		size:    int64(len(f.data)),
		mode:    f.mode,
		modTime: f.modTime,
		isDir:   f.isDir,
	}, nil
}

func (f *file) Readdir(count int) ([]os.FileInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, os.ErrClosed
	}
	if !f.isDir {
		return nil, &os.PathError{Op: "readdir", Path: f.name, Err: errNotDir}
	}
	if !f.dirLoaded {
		infos, err := f.fs.children(f.name)
		if err != nil {
			return nil, err
		}
		sort.Slice(infos, func(i, j int) bool { return infos[i].Name() < infos[j].Name() })
		f.dirEntries = infos
		f.dirLoaded = true
	}
	if count <= 0 {
		rest := f.dirEntries[f.dirRead:]
		f.dirRead = len(f.dirEntries)
		out := make([]os.FileInfo, len(rest))
		copy(out, rest)
		return out, nil
	}
	if f.dirRead >= len(f.dirEntries) {
		return nil, io.EOF
	}
	end := f.dirRead + count
	if end > len(f.dirEntries) {
		end = len(f.dirEntries)
	}
	out := f.dirEntries[f.dirRead:end]
	f.dirRead = end
	return out, nil
}

func (f *file) Readdirnames(n int) ([]string, error) {
	infos, err := f.Readdir(n)
	names := make([]string, len(infos))
	for i, fi := range infos {
		names[i] = fi.Name()
	}
	return names, err
}
