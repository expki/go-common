package ai

import "iter"

// EventKind discriminates the variants of a streaming [Event].
type EventKind int

const (
	// EventText is an incremental chunk of assistant text in [Event.Text].
	EventText EventKind = iota
	// EventThinking is an incremental chunk of reasoning in [Event.Thinking].
	EventThinking
	// EventToolCall announces that the model requested a tool call, carried
	// in [Event.ToolCall]. The [Conversation] tool-loop executes it and
	// continues the same stream with the result.
	EventToolCall
	// EventDone is the single terminal event of a stream. It carries any
	// non-fatal [Event.Caveats] for the completed span.
	EventDone
)

// Event is one item yielded by a streaming turn. Exactly which payload field
// is meaningful is determined by [Event.Kind].
type Event struct {
	// Kind discriminates the event variant.
	Kind EventKind
	// Text holds an assistant text chunk when Kind is [EventText].
	Text string
	// Thinking holds a reasoning chunk when Kind is [EventThinking].
	Thinking string
	// ThinkingSignature carries a provider-issued signature over the reasoning
	// trace on an [EventThinking] (Anthropic emits it once the thinking block
	// completes, with no text chunk). The [Conversation] records it on the
	// assembled assistant message so it can be replayed on later turns; it is
	// empty for providers that do not sign reasoning.
	ThinkingSignature string
	// ToolCall holds the requested call when Kind is [EventToolCall].
	ToolCall *ToolCall
	// Caveats carries non-fatal advisories on the terminal [EventDone],
	// mirroring the final [Message.Caveats] (for example
	// [ToolRequiredNotHonored]).
	Caveats []string
}

// Stream is a single logical streaming turn. For a [Conversation.Stream] the
// stream spans the whole multi-turn tool-loop: text, thinking, and tool-call
// events from every provider turn are yielded into one sequence, terminated by
// a single [EventDone].
//
// The idiomatic consumer pairs the range-over-func with an Err check:
//
//	s := conv.Stream(ctx, "…")
//	for ev := range s.All() {
//		switch ev.Kind {
//		case ai.EventText:
//			print(ev.Text)
//		}
//	}
//	if err := s.Err(); err != nil { /* handle */ }
type Stream interface {
	// All returns a range-over-func sequence of events. It ends when the turn
	// (and any spanned tool-loop) completes. Breaking out of the range early
	// runs the producer's cleanup deterministically — there is no goroutine
	// leak — and cancellation flows through the context passed to Stream.
	All() iter.Seq[Event]
	// Err returns the terminal error after iteration, or nil on clean
	// completion. Call it once the range loop has ended.
	//
	// A hard error (a transport failure, or a tool-loop error such as
	// [ErrToolUnbound]) ends the range WITHOUT yielding a terminal
	// [EventDone] and surfaces here: [EventDone] means clean completion only.
	// So a consumer that needs to distinguish success from failure must check
	// Err after the loop rather than relying on having seen an EventDone.
	Err() error
}
