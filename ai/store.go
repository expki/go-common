package ai

import (
	"fmt"
	"os"
	"sync"

	bolt "go.etcd.io/bbolt"
)

// Store is the durable backing for conversations and their checkpoints. A
// conversation is persisted as a single opaque blob keyed by its id; the
// blob's internal shape is owned by [Conversation] (see persistedConversation).
type Store interface {
	// SaveConversation writes data under id, overwriting any prior value.
	SaveConversation(id string, data []byte) error
	// LoadConversation returns the data previously saved under id. It returns
	// a non-nil error if id is unknown.
	LoadConversation(id string) ([]byte, error)
	// DeleteConversation removes id and its data; deleting an unknown id is
	// not an error.
	DeleteConversation(id string) error
	// ListConversations returns every persisted conversation id.
	ListConversations() ([]string, error)
	// Close releases any resources held by the store (for the durable bbolt
	// store, the underlying file handle). It is safe to call on the in-memory
	// store, where it is a no-op, so callers can close any Store uniformly.
	Close() error
}

// convBucket is the single bbolt bucket holding conversation blobs.
var convBucket = []byte("conversations")

// boltStore is the durable [Store], backed by go.etcd.io/bbolt.
type boltStore struct {
	db *bolt.DB
}

// StoreOption customizes how a bbolt store is opened.
type StoreOption func(*storeOptions)

type storeOptions struct {
	fileMode uint32
}

// WithFileMode sets the unix file mode for a newly created bbolt file. The
// default is 0600.
func WithFileMode(mode uint32) StoreOption {
	return func(o *storeOptions) { o.fileMode = mode }
}

// OpenStore opens (creating if needed) a durable bbolt-backed [Store] at path.
// Conversations and their checkpoints written through it survive process
// restart and can be reloaded by id via [LoadConversation].
func OpenStore(path string, opts ...StoreOption) (Store, error) {
	o := storeOptions{fileMode: 0o600}
	for _, opt := range opts {
		opt(&o)
	}
	db, err := bolt.Open(path, os.FileMode(o.fileMode), nil)
	if err != nil {
		return nil, fmt.Errorf("ai: opening store: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(convBucket)
		return e
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ai: initializing store: %w", err)
	}
	return &boltStore{db: db}, nil
}

func (s *boltStore) SaveConversation(id string, data []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(convBucket)
		// Copy data: bbolt does not retain the caller's slice across the txn.
		cp := make([]byte, len(data))
		copy(cp, data)
		return b.Put([]byte(id), cp)
	})
}

func (s *boltStore) LoadConversation(id string) ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(convBucket)
		v := b.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("ai: conversation %q not found", id)
		}
		out = make([]byte, len(v))
		copy(out, v)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *boltStore) DeleteConversation(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(convBucket).Delete([]byte(id))
	})
}

func (s *boltStore) ListConversations() ([]string, error) {
	var ids []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(convBucket).ForEach(func(k, _ []byte) error {
			ids = append(ids, string(k))
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// Close releases the underlying bbolt file. It is exposed for callers that
// open a durable store directly; the memory store needs no closing.
func (s *boltStore) Close() error { return s.db.Close() }

// memoryStore is an ephemeral [Store] for tests and short-lived use. Its
// contents live only for the process lifetime.
type memoryStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// OpenMemoryStore returns an ephemeral in-memory [Store]. It mirrors the bbolt
// store's semantics but persists nothing across process restarts.
func OpenMemoryStore() Store {
	return &memoryStore{data: map[string][]byte{}}
}

func (s *memoryStore) SaveConversation(id string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	s.data[id] = cp
	return nil
}

func (s *memoryStore) LoadConversation(id string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[id]
	if !ok {
		return nil, fmt.Errorf("ai: conversation %q not found", id)
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

func (s *memoryStore) DeleteConversation(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
	return nil
}

func (s *memoryStore) ListConversations() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.data))
	for id := range s.data {
		ids = append(ids, id)
	}
	return ids, nil
}

// Close is a no-op for the in-memory store; it exists so the [Store] interface
// can be closed uniformly regardless of the backing implementation.
func (s *memoryStore) Close() error { return nil }
