package claude

import (
	"context"
	"encoding/json"
	"iter"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/packages/ssestream"
	"github.com/expki/go-common/ai"
)

// claudeStream adapts the Anthropic SSE cursor to [ai.Stream]. Text and
// thinking deltas are yielded as they arrive; tool calls are yielded once a
// content block completes (the tool input JSON is only whole at block stop).
// The single terminal EventDone is emitted by the outer ai.Conversation, so
// this provider-level stream does NOT emit EventDone itself.
type claudeStream struct {
	ctx    context.Context
	cursor *ssestream.Stream[anthropic.MessageStreamEventUnion]
	err    error
}

func newStream(ctx context.Context, cursor *ssestream.Stream[anthropic.MessageStreamEventUnion]) ai.Stream {
	return &claudeStream{ctx: ctx, cursor: cursor}
}

// All drives the SSE cursor and yields events. It accumulates the message so
// that completed tool_use blocks can be emitted with their full input JSON,
// while still streaming text and thinking deltas live.
func (s *claudeStream) All() iter.Seq[ai.Event] {
	return func(yield func(ai.Event) bool) {
		acc := anthropic.Message{}
		for s.cursor.Next() {
			if err := s.ctx.Err(); err != nil {
				s.err = err
				return
			}
			event := s.cursor.Current()
			if err := acc.Accumulate(event); err != nil {
				s.err = err
				return
			}

			switch ev := event.AsAny().(type) {
			case anthropic.ContentBlockDeltaEvent:
				switch delta := ev.Delta.AsAny().(type) {
				case anthropic.TextDelta:
					if delta.Text != "" && !yield(ai.Event{Kind: ai.EventText, Text: delta.Text}) {
						return
					}
				case anthropic.ThinkingDelta:
					if delta.Thinking != "" && !yield(ai.Event{Kind: ai.EventThinking, Thinking: delta.Thinking}) {
						return
					}
				}
			case anthropic.ContentBlockStopEvent:
				// A content block just completed; its accumulated payload is now
				// whole. A tool_use block's input JSON can be emitted, and a
				// thinking block's signature can be surfaced for replay.
				idx := int(ev.Index)
				if idx >= 0 && idx < len(acc.Content) {
					switch blk := acc.Content[idx].AsAny().(type) {
					case anthropic.ToolUseBlock:
						call := ai.ToolCall{
							ID:        blk.ID,
							Name:      blk.Name,
							Arguments: json.RawMessage(blk.Input),
						}
						if !yield(ai.Event{Kind: ai.EventToolCall, ToolCall: &call}) {
							return
						}
					case anthropic.ThinkingBlock:
						if blk.Signature != "" {
							if !yield(ai.Event{Kind: ai.EventThinking, ThinkingSignature: blk.Signature}) {
								return
							}
						}
					}
				}
			}
		}
		s.err = s.cursor.Err()
	}
}

// Err returns the terminal error after iteration.
func (s *claudeStream) Err() error { return s.err }
