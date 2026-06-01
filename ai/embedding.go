package ai

// Embedding is a single dense vector produced by an embeddings model. A
// provider without a native embeddings endpoint returns a non-nil zero-length
// []Embedding rather than an error (a capability gap never errors); callers
// treat len(result) == 0 as "embeddings unsupported".
type Embedding []float32
