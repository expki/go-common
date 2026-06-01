package ai

import (
	"context"
	"errors"
	"testing"
)

func TestStream_TextSpan(t *testing.T) {
	fake := &fakeProvider{streamTurns: [][]Event{
		{{Kind: EventText, Text: "hel"}, {Kind: EventText, Text: "lo"}, {Kind: EventDone}},
	}}
	conv, _ := NewConversation(fake, OpenMemoryStore())
	s := conv.Stream(context.Background(), "hi")

	var text string
	var kinds []EventKind
	for ev := range s.All() {
		kinds = append(kinds, ev.Kind)
		if ev.Kind == EventText {
			text += ev.Text
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Err: %v", err)
	}
	if text != "hello" {
		t.Errorf("text = %q", text)
	}
	if kinds[len(kinds)-1] != EventDone {
		t.Errorf("last kind = %v, want EventDone", kinds[len(kinds)-1])
	}
	// assistant text appended to history.
	h := conv.Messages()
	if len(h) != 2 || h[1].Text() != "hello" {
		t.Errorf("history = %+v", h)
	}
}

func TestStream_ToolLoopSpan(t *testing.T) {
	tc := toolCall("c1", "getweather", weatherArgs{City: "Paris"})
	fake := &fakeProvider{streamTurns: [][]Event{
		{{Kind: EventToolCall, ToolCall: &tc}, {Kind: EventDone}},
		{{Kind: EventText, Text: "21C"}, {Kind: EventDone}},
	}}
	conv, _ := NewConversation(fake, OpenMemoryStore())
	_ = conv.RegisterToolFunc(GetWeather, "w")
	s := conv.Stream(context.Background(), "weather?")

	var kinds []EventKind
	var text string
	for ev := range s.All() {
		kinds = append(kinds, ev.Kind)
		if ev.Kind == EventText {
			text += ev.Text
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Err: %v", err)
	}
	// Expect: EventToolCall, EventText, EventDone (one terminal Done).
	wantSeq := []EventKind{EventToolCall, EventText, EventDone}
	if len(kinds) != len(wantSeq) {
		t.Fatalf("kinds = %v, want %v", kinds, wantSeq)
	}
	for i := range wantSeq {
		if kinds[i] != wantSeq[i] {
			t.Errorf("kinds[%d] = %v, want %v", i, kinds[i], wantSeq[i])
		}
	}
	if text != "21C" {
		t.Errorf("text = %q", text)
	}
	// history: user, assistant(toolcall), tool(result), assistant(text)
	if h := conv.Messages(); len(h) != 4 {
		t.Errorf("history len = %d, want 4: %+v", len(h), h)
	}
}

func TestStream_EarlyBreakNoLeak(t *testing.T) {
	fake := &fakeProvider{streamTurns: [][]Event{
		{{Kind: EventText, Text: "a"}, {Kind: EventText, Text: "b"}, {Kind: EventDone}},
	}}
	conv, _ := NewConversation(fake, OpenMemoryStore())
	s := conv.Stream(context.Background(), "hi")
	for ev := range s.All() {
		if ev.Kind == EventText {
			break // early exit; producer cleanup must run (endSpan)
		}
	}
	// The span must have been cleared, so a subsequent Send is allowed.
	fake2 := &fakeProvider{chatTurns: []Message{AssistantText("ok")}}
	conv.provider = fake2
	if _, err := conv.Send(context.Background(), "again"); err != nil {
		t.Errorf("Send after early break: %v (span not released?)", err)
	}
}

func TestStream_ContextCancel(t *testing.T) {
	fake := &fakeProvider{streamTurns: [][]Event{
		{{Kind: EventText, Text: "x"}, {Kind: EventText, Text: "y"}, {Kind: EventDone}},
	}}
	conv, _ := NewConversation(fake, OpenMemoryStore())
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before iterating
	s := conv.Stream(ctx, "hi")
	for range s.All() {
	}
	if !errors.Is(s.Err(), context.Canceled) {
		t.Errorf("Err = %v, want context.Canceled", s.Err())
	}
}

func TestStream_ToolRequiredCaveatOnDone(t *testing.T) {
	fake := fakeForcer{fakeProvider: &fakeProvider{streamTurns: [][]Event{
		{{Kind: EventText, Text: "no tool"}, {Kind: EventDone}},
	}}, can: false}
	conv, _ := NewConversation(fake, OpenMemoryStore())
	_ = conv.RegisterToolFunc(GetWeather, "w")
	s := conv.Stream(context.Background(), "go", Tools(ToolRequired))

	var done Event
	for ev := range s.All() {
		if ev.Kind == EventDone {
			done = ev
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Err: %v", err)
	}
	if len(done.Caveats) != 1 || done.Caveats[0] != ToolRequiredNotHonored {
		t.Errorf("EventDone caveats = %v, want [%s]", done.Caveats, ToolRequiredNotHonored)
	}
}

func TestStream_ConcurrentSpanInFlight(t *testing.T) {
	fake := &fakeProvider{streamTurns: [][]Event{
		{{Kind: EventText, Text: "x"}, {Kind: EventDone}},
	}}
	conv, _ := NewConversation(fake, OpenMemoryStore())
	s1 := conv.Stream(context.Background(), "first") // begins the span
	// Second span while first is in flight (not yet iterated) -> ErrSpanInFlight.
	s2 := conv.Stream(context.Background(), "second")
	if !errors.Is(s2.Err(), ErrSpanInFlight) {
		t.Errorf("s2.Err = %v, want ErrSpanInFlight", s2.Err())
	}
	// Drain s1 to release.
	for range s1.All() {
	}
	if err := s1.Err(); err != nil {
		t.Errorf("s1.Err = %v", err)
	}
}

// TestStream_HardToolErrorNoEventDone locks the streamed-hard-error contract
// (§ Item A): a reloaded conversation whose tool invoker was never rebound,
// asked to stream a turn that calls that tool, ends the range WITHOUT a
// terminal EventDone and surfaces ErrToolUnbound via Err(); the span is still
// released so a later Send can run.
func TestStream_HardToolErrorNoEventDone(t *testing.T) {
	store := OpenMemoryStore()
	// Persist a conversation that has the tool descriptor registered.
	seed := &fakeProvider{}
	conv, _ := NewConversation(seed, store, WithID("c"))
	if err := conv.RegisterToolFunc(GetWeather, "weather"); err != nil {
		t.Fatalf("RegisterToolFunc: %v", err)
	}
	if err := conv.Checkpoint("init"); err != nil { // forces a persist of the descriptor
		t.Fatalf("Checkpoint: %v", err)
	}

	// Reload WITHOUT rebinding the invoker (empty registry).
	tc := toolCall("c1", "getweather", weatherArgs{City: "Paris"})
	streamer := &fakeProvider{streamTurns: [][]Event{
		{{Kind: EventToolCall, ToolCall: &tc}, {Kind: EventDone}},
	}}
	conv2, err := LoadConversation(streamer, store, "c", NewToolRegistry())
	if err != nil {
		t.Fatalf("LoadConversation: %v", err)
	}

	s := conv2.Stream(context.Background(), "weather?")
	var sawDone bool
	var kinds []EventKind
	for ev := range s.All() {
		kinds = append(kinds, ev.Kind)
		if ev.Kind == EventDone {
			sawDone = true
		}
	}
	if sawDone {
		t.Errorf("hard tool error must NOT yield EventDone; kinds=%v", kinds)
	}
	if !errors.Is(s.Err(), ErrToolUnbound) {
		t.Errorf("Err = %v, want ErrToolUnbound", s.Err())
	}

	// The span must have been released: rebind and run a fresh Send.
	if err := conv2.RegisterToolFunc(GetWeather, "weather"); err != nil {
		t.Fatalf("rebind after error: %v", err)
	}
	conv2.provider = &fakeProvider{chatTurns: []Message{AssistantText("ok now")}}
	if _, err := conv2.Send(context.Background(), "again"); err != nil {
		t.Errorf("Send after hard stream error: %v (span not released?)", err)
	}
}
