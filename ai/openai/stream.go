package openai

import (
	"context"
	"encoding/json"
	"iter"

	"github.com/expki/go-common/ai"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/packages/ssestream"
)

// openaiStream adapts the OpenAI SSE chunk cursor to [ai.Stream]. Text deltas
// are yielded as they arrive; tool calls arrive across multiple chunks (id and
// name in the first delta for an index, arguments accumulated thereafter) and
// are yielded once the stream completes, when each call's argument JSON is
// whole. The single terminal EventDone is emitted by the outer ai.Conversation,
// so this provider-level stream does NOT emit EventDone itself.
type openaiStream struct {
	ctx    context.Context
	cursor *ssestream.Stream[openai.ChatCompletionChunk]
	err    error
}

func newStream(ctx context.Context, cursor *ssestream.Stream[openai.ChatCompletionChunk]) ai.Stream {
	return &openaiStream{ctx: ctx, cursor: cursor}
}

// pendingToolCall accumulates a streamed tool call across delta chunks.
type pendingToolCall struct {
	id   string
	name string
	args []byte
}

// All drives the SSE cursor and yields events. Text deltas stream live; tool
// calls accumulate by their delta index and are flushed in order once the
// cursor is exhausted.
func (s *openaiStream) All() iter.Seq[ai.Event] {
	return func(yield func(ai.Event) bool) {
		// order preserves the first-seen sequence of tool-call indices so the
		// flushed calls match the model's intended order.
		var order []int64
		calls := map[int64]*pendingToolCall{}

		for s.cursor.Next() {
			if err := s.ctx.Err(); err != nil {
				s.err = err
				return
			}
			chunk := s.cursor.Current()
			if len(chunk.Choices) == 0 {
				continue
			}
			delta := chunk.Choices[0].Delta

			if delta.Content != "" && !yield(ai.Event{Kind: ai.EventText, Text: delta.Content}) {
				return
			}

			for _, tc := range delta.ToolCalls {
				pc, ok := calls[tc.Index]
				if !ok {
					pc = &pendingToolCall{}
					calls[tc.Index] = pc
					order = append(order, tc.Index)
				}
				if tc.ID != "" {
					pc.id = tc.ID
				}
				if tc.Function.Name != "" {
					pc.name = tc.Function.Name
				}
				if tc.Function.Arguments != "" {
					pc.args = append(pc.args, tc.Function.Arguments...)
				}
			}
		}
		if err := s.cursor.Err(); err != nil {
			s.err = err
			return
		}

		// Flush completed tool calls now that each call's argument JSON is whole.
		for _, idx := range order {
			pc := calls[idx]
			if pc.name == "" {
				continue
			}
			args := json.RawMessage(pc.args)
			if len(args) == 0 {
				args = json.RawMessage("{}")
			}
			call := ai.ToolCall{ID: pc.id, Name: pc.name, Arguments: args}
			if !yield(ai.Event{Kind: ai.EventToolCall, ToolCall: &call}) {
				return
			}
		}
	}
}

// Err returns the terminal error after iteration.
func (s *openaiStream) Err() error { return s.err }
