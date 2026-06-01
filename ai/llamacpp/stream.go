package llamacpp

import (
	"bufio"
	"context"
	"encoding/json"
	"iter"
	"net/http"
	"strings"

	"github.com/expki/go-common/ai"
)

// errStream is an [ai.Stream] that yields nothing and reports a fixed error,
// used when a streaming turn fails before any event can be produced (for
// example a failed /apply-template or a non-2xx /completion).
type errStream struct{ err error }

func (s *errStream) All() iter.Seq[ai.Event] {
	return func(yield func(ai.Event) bool) {}
}

func (s *errStream) Err() error { return s.err }

// completionStream adapts the llama-server /completion SSE response to
// [ai.Stream]. It accumulates content across frames so that a
// grammar-constrained tool call (whose JSON is only whole at the end) can be
// emitted as a single [ai.EventToolCall]; plain text is streamed live as
// [ai.EventText] and reasoning as [ai.EventThinking]. Per the package contract
// it does NOT emit the terminal EventDone — the outer [ai.Conversation] owns
// that. An onDone hook fires once iteration finishes (used to save the KV
// slot best-effort).
type completionStream struct {
	ctx    context.Context
	resp   *http.Response
	tools  []ai.Tool
	onDone func()
	err    error
}

func newStream(ctx context.Context, resp *http.Response, tools []ai.Tool, onDone func()) ai.Stream {
	return &completionStream{ctx: ctx, resp: resp, tools: tools, onDone: onDone}
}

// All drives the SSE body line by line. llama-server sends each token as an
// "data: {json}" frame whose decoded form is a completionResponse; the final
// frame carries "stop": true. When tools are offered the content is buffered
// (not streamed as text) so the whole JSON envelope can be parsed into one tool
// call; otherwise text is yielded as it arrives.
func (s *completionStream) All() iter.Seq[ai.Event] {
	return func(yield func(ai.Event) bool) {
		defer s.resp.Body.Close()
		if s.onDone != nil {
			defer s.onDone()
		}

		buffering := len(s.tools) > 0
		var buf strings.Builder

		scanner := bufio.NewScanner(s.resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			if err := s.ctx.Err(); err != nil {
				s.err = err
				return
			}
			data, ok := sseData(scanner.Text())
			if !ok {
				continue
			}

			var frame completionResponse
			if err := json.Unmarshal([]byte(data), &frame); err != nil {
				// A malformed frame is treated as a stream error rather than
				// silently dropped, so callers can see the transport problem.
				s.err = err
				return
			}

			if frame.Reasoning != "" {
				if !yield(ai.Event{Kind: ai.EventThinking, Thinking: frame.Reasoning}) {
					return
				}
			}
			if frame.Content != "" {
				if buffering {
					buf.WriteString(frame.Content)
				} else if !yield(ai.Event{Kind: ai.EventText, Text: frame.Content}) {
					return
				}
			}
			if frame.Stop {
				break
			}
		}
		if err := scanner.Err(); err != nil {
			s.err = err
			return
		}

		// When buffering for a possible tool call, decide once the full content
		// is known: a valid tool envelope becomes a tool-call event, otherwise
		// it was plain text and is flushed as a text event.
		if buffering {
			content := buf.String()
			if call, ok := parseToolCall(content, s.tools); ok {
				_ = yield(ai.Event{Kind: ai.EventToolCall, ToolCall: &call})
				return
			}
			if content != "" {
				_ = yield(ai.Event{Kind: ai.EventText, Text: content})
			}
		}
	}
}

// Err returns the terminal error after iteration.
func (s *completionStream) Err() error { return s.err }

// sseData extracts the payload of a "data:" Server-Sent-Events line, reporting
// ok=false for blank lines, comments, and other field lines.
func sseData(line string) (data string, ok bool) {
	if !strings.HasPrefix(line, "data:") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(line, "data:")), true
}

// embeddingRequest is the body for POST /embedding (ai/llama.cpp.md:667).
type embeddingRequest struct {
	Content string `json:"content"`
}

// embeddingResponse decodes one element of the /embedding response array. The
// "embedding" field is an array of per-token rows; for the common pooled
// configuration it holds a single row, which is the sentence vector.
type embeddingResponse struct {
	Index     int         `json:"index"`
	Embedding [][]float32 `json:"embedding"`
}

// vector returns the pooled sentence vector: the first (and, when pooled, only)
// token row. An empty response yields a non-nil zero-length [ai.Embedding].
func (r embeddingResponse) vector() ai.Embedding {
	if len(r.Embedding) == 0 {
		return ai.Embedding{}
	}
	return ai.Embedding(r.Embedding[0])
}

// UnmarshalJSON accepts both shapes llama-server may return for /embedding: the
// array-of-objects form documented for the native endpoint, and a bare object
// when a single input is sent. It also tolerates a flat "embedding":[...] (a
// single un-nested vector) by promoting it to a one-row matrix.
func (r *embeddingResponse) UnmarshalJSON(b []byte) error {
	// Try the nested [][]float32 shape first.
	type nested struct {
		Index     int         `json:"index"`
		Embedding [][]float32 `json:"embedding"`
	}
	var n nested
	if err := json.Unmarshal(b, &n); err == nil && n.Embedding != nil {
		r.Index = n.Index
		r.Embedding = n.Embedding
		return nil
	}
	// Fall back to a flat []float32 embedding.
	type flat struct {
		Index     int       `json:"index"`
		Embedding []float32 `json:"embedding"`
	}
	var f flat
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	r.Index = f.Index
	if f.Embedding != nil {
		r.Embedding = [][]float32{f.Embedding}
	}
	return nil
}
