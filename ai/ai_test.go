package ai

import (
	"context"
	"encoding/json"
	"iter"
	"sync"
)

// fakeProvider is a scripted ai.ChatModel for hermetic tests. It returns the
// next scripted Chat message / Stream event-batch on each turn, with zero
// network. forceTools, when set via fakeForcer, makes it implement ToolForcer.
type fakeProvider struct {
	mu sync.Mutex

	// chatTurns are returned one per Chat call, in order. A turn may carry
	// tool calls; the conversation runs them and calls Chat again.
	chatTurns []Message
	chatIdx   int

	// streamTurns are returned one batch per Stream call, in order. Each
	// inner slice is the events for one provider turn.
	streamTurns [][]Event
	streamIdx   int

	// chatErr, when non-nil, is returned from the next Chat call.
	chatErr error

	// hook, if set, runs at the start of each Chat call with the options it
	// received (used to assert cacheAnchor / ToolDefs).
	hook func(opts Options)
}

func (f *fakeProvider) Chat(ctx context.Context, msgs []Message, opts Options) (Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hook != nil {
		f.hook(opts)
	}
	if f.chatErr != nil {
		return Message{}, f.chatErr
	}
	if f.chatIdx >= len(f.chatTurns) {
		// Default: a terminal empty assistant turn.
		return AssistantText(""), nil
	}
	m := f.chatTurns[f.chatIdx]
	f.chatIdx++
	return m, nil
}

func (f *fakeProvider) Stream(ctx context.Context, msgs []Message, opts Options) Stream {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hook != nil {
		f.hook(opts)
	}
	var events []Event
	if f.streamIdx < len(f.streamTurns) {
		events = f.streamTurns[f.streamIdx]
		f.streamIdx++
	} else {
		events = []Event{{Kind: EventText, Text: ""}, {Kind: EventDone}}
	}
	return &fakeStream{ctx: ctx, events: events}
}

// fakeStream yields a fixed slice of events, honoring ctx cancellation.
type fakeStream struct {
	ctx    context.Context
	events []Event
	err    error
}

func (s *fakeStream) All() iter.Seq[Event] {
	return func(yield func(Event) bool) {
		for _, ev := range s.events {
			if err := s.ctx.Err(); err != nil {
				s.err = err
				return
			}
			if !yield(ev) {
				return
			}
		}
	}
}

func (s *fakeStream) Err() error { return s.err }

// fakeForcer wraps fakeProvider and implements ToolForcer with a fixed answer.
type fakeForcer struct {
	*fakeProvider
	can bool
}

func (f fakeForcer) CanForceTools() bool { return f.can }

// fakeFamilyProvider wraps fakeProvider and implements FamilyProvider.
type fakeFamilyProvider struct {
	*fakeProvider
	family string
}

func (f fakeFamilyProvider) Family() string { return f.family }

// toolCall builds a ToolCall with JSON-encoded args.
func toolCall(id, name string, args any) ToolCall {
	raw, _ := json.Marshal(args)
	return ToolCall{ID: id, Name: name, Arguments: raw}
}

// assistantWithToolCall builds an assistant message that requests one tool call.
func assistantWithToolCall(call ToolCall) Message {
	return Message{Role: RoleAssistant, ToolCalls: []ToolCall{call}}
}
