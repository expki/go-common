package ai

import (
	"context"
	"errors"
	"iter"
	"sync"
	"testing"
	"time"
)

// TestConversation_SendCancelledContext verifies the synchronous tool-loop
// honors an already-cancelled context before invoking the provider, mirroring
// the streaming path, even when the provider itself ignores ctx.
func TestConversation_SendCancelledContext(t *testing.T) {
	fake := &fakeProvider{chatTurns: []Message{AssistantText("should not be reached")}}
	conv, err := NewConversation(fake, OpenMemoryStore())
	if err != nil {
		t.Fatalf("NewConversation: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := conv.Send(ctx, "hi"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send err = %v, want context.Canceled", err)
	}
	if fake.chatIdx != 0 {
		t.Errorf("provider was called %d times; want 0 on a cancelled context", fake.chatIdx)
	}
}

func TestConversation_SendBasic(t *testing.T) {
	fake := &fakeProvider{chatTurns: []Message{AssistantText("hello back")}}
	conv, _ := NewConversation(fake, OpenMemoryStore())
	msg, err := conv.Send(context.Background(), "hi")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if msg.Text() != "hello back" {
		t.Errorf("text = %q", msg.Text())
	}
	if got := conv.Messages(); len(got) != 2 || got[0].Role != RoleUser {
		t.Errorf("history = %+v", got)
	}
}

func TestConversation_SyncToolLoop(t *testing.T) {
	fake := &fakeProvider{
		chatTurns: []Message{
			assistantWithToolCall(toolCall("c1", "getweather", weatherArgs{City: "Paris"})),
			AssistantText("21 degrees"),
		},
	}
	conv, _ := NewConversation(fake, OpenMemoryStore())
	if err := conv.RegisterToolFunc(GetWeather, "weather"); err != nil {
		t.Fatalf("register: %v", err)
	}
	msg, err := conv.Send(context.Background(), "weather?")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if msg.Text() != "21 degrees" {
		t.Errorf("final = %q", msg.Text())
	}
	// history: user, assistant(toolcall), tool(result), assistant(final)
	h := conv.Messages()
	if len(h) != 4 {
		t.Fatalf("history len = %d, want 4: %+v", len(h), h)
	}
	if h[2].Role != RoleTool || len(h[2].Content) != 1 {
		t.Errorf("expected tool-result message at [2]: %+v", h[2])
	}
	tr := h[2].Content[0].ToolResult
	if tr == nil || tr.CallID != "c1" {
		t.Errorf("tool result = %+v", tr)
	}
}

func TestConversation_ToolLoopBound(t *testing.T) {
	// A provider that always asks for a tool call should be capped.
	turns := make([]Message, 20)
	for i := range turns {
		turns[i] = assistantWithToolCall(toolCall("c", "getweather", weatherArgs{City: "X"}))
	}
	fake := &fakeProvider{chatTurns: turns}
	conv, _ := NewConversation(fake, OpenMemoryStore(), WithMaxToolIterations(3))
	_ = conv.RegisterToolFunc(GetWeather, "weather")
	if _, err := conv.Send(context.Background(), "go"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if fake.chatIdx != 3 {
		t.Errorf("chat calls = %d, want 3 (bound)", fake.chatIdx)
	}
}

func TestConversation_CheckpointRestoreOrphan(t *testing.T) {
	fake := &fakeProvider{chatTurns: []Message{
		AssistantText("a1"), AssistantText("a2"), AssistantText("a3"),
	}}
	conv, _ := NewConversation(fake, OpenMemoryStore())
	_, _ = conv.Send(context.Background(), "u1") // history: u1,a1
	if err := conv.Checkpoint("cp1"); err != nil {
		t.Fatalf("cp1: %v", err)
	}
	_, _ = conv.Send(context.Background(), "u2") // u1,a1,u2,a2
	if err := conv.Checkpoint("cp2"); err != nil {
		t.Fatalf("cp2: %v", err)
	}
	_, _ = conv.Send(context.Background(), "u3") // u1,a1,u2,a2,u3,a3
	if len(conv.Messages()) != 6 {
		t.Fatalf("pre-restore len = %d", len(conv.Messages()))
	}

	if err := conv.Restore("cp1"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got := conv.Messages(); len(got) != 2 {
		t.Errorf("post-restore len = %d, want 2", len(got))
	}
	// cp2 was after cp1 -> orphaned.
	if err := conv.Restore("cp2"); err == nil {
		t.Error("expected cp2 to be orphaned/unknown after restoring cp1")
	}
}

func TestConversation_ToolRequiredCaveat(t *testing.T) {
	// Provider cannot force tools and returns no tool call.
	t.Run("not forceable -> caveat", func(t *testing.T) {
		fake := fakeForcer{fakeProvider: &fakeProvider{chatTurns: []Message{AssistantText("no tool")}}, can: false}
		conv, _ := NewConversation(fake, OpenMemoryStore())
		_ = conv.RegisterToolFunc(GetWeather, "w")
		msg, err := conv.Send(context.Background(), "go", Tools(ToolRequired))
		if err != nil {
			t.Fatalf("Send: %v", err)
		}
		if len(msg.Caveats) != 1 || msg.Caveats[0] != ToolRequiredNotHonored {
			t.Errorf("caveats = %v, want [%s]", msg.Caveats, ToolRequiredNotHonored)
		}
	})

	t.Run("forceable -> no caveat", func(t *testing.T) {
		fake := fakeForcer{fakeProvider: &fakeProvider{chatTurns: []Message{AssistantText("no tool")}}, can: true}
		conv, _ := NewConversation(fake, OpenMemoryStore())
		_ = conv.RegisterToolFunc(GetWeather, "w")
		msg, err := conv.Send(context.Background(), "go", Tools(ToolRequired))
		if err != nil {
			t.Fatalf("Send: %v", err)
		}
		if len(msg.Caveats) != 0 {
			t.Errorf("caveats = %v, want none", msg.Caveats)
		}
	})

	t.Run("no ToolForcer -> caveat", func(t *testing.T) {
		fake := &fakeProvider{chatTurns: []Message{AssistantText("no tool")}}
		conv, _ := NewConversation(fake, OpenMemoryStore())
		msg, err := conv.Send(context.Background(), "go", Tools(ToolRequired))
		if err != nil {
			t.Fatalf("Send: %v", err)
		}
		if len(msg.Caveats) != 1 {
			t.Errorf("caveats = %v, want one", msg.Caveats)
		}
	})
}

func TestConversation_CacheAnchor(t *testing.T) {
	var seen []int
	fake := &fakeProvider{
		chatTurns: []Message{AssistantText("a1"), AssistantText("a2")},
		hook: func(o Options) {
			idx, ok := o.CacheAnchor()
			if !ok {
				seen = append(seen, -1)
			} else {
				seen = append(seen, idx)
			}
		},
	}
	conv, _ := NewConversation(fake, OpenMemoryStore())
	_, _ = conv.Send(context.Background(), "u1") // no checkpoint yet -> anchor absent
	_ = conv.Checkpoint("cp")                    // anchor at len=2
	_, _ = conv.Send(context.Background(), "u2") // anchor present at 2
	if len(seen) != 2 {
		t.Fatalf("hook calls = %d", len(seen))
	}
	if seen[0] != -1 {
		t.Errorf("first anchor = %d, want absent(-1)", seen[0])
	}
	if seen[1] != 2 {
		t.Errorf("second anchor = %d, want 2", seen[1])
	}
}

func TestConversation_ConcurrentSendSpanInFlight(t *testing.T) {
	// A provider whose Chat blocks until released, so the second Send overlaps.
	release := make(chan struct{})
	started := make(chan struct{})
	fake := &blockingProvider{started: started, release: release, reply: AssistantText("done")}
	conv, _ := NewConversation(fake, OpenMemoryStore())

	var wg sync.WaitGroup
	var firstErr, secondErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, firstErr = conv.Send(context.Background(), "first")
	}()
	<-started // first Send is now mid-round-trip
	_, secondErr = conv.Send(context.Background(), "second")
	close(release)
	wg.Wait()

	if firstErr != nil {
		t.Errorf("first Send err = %v", firstErr)
	}
	if !errors.Is(secondErr, ErrSpanInFlight) {
		t.Errorf("second Send err = %v, want ErrSpanInFlight", secondErr)
	}
}

func TestConversation_MessagesPromptMidSpan(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	fake := &blockingProvider{started: started, release: release, reply: AssistantText("done")}
	conv, _ := NewConversation(fake, OpenMemoryStore())

	go func() { _, _ = conv.Send(context.Background(), "first") }()
	<-started

	done := make(chan int, 1)
	go func() { done <- len(conv.Messages()) }()
	select {
	case n := <-done:
		if n < 1 {
			t.Errorf("Messages returned %d entries mid-span", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Messages() blocked while a span was in flight (lock held across round-trip)")
	}
	close(release)
}

// TestConversation_MutatorsBlockedDuringLiveStream covers plan §4.6 test (2):
// a Restore and a Send issued DURING a live Stream span both return
// ErrSpanInFlight rather than interleaving. Run under -race.
func TestConversation_MutatorsBlockedDuringLiveStream(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	fake := &blockingStreamProvider{started: started, release: release}
	conv, _ := NewConversation(fake, OpenMemoryStore())
	// A checkpoint so Restore has a target (taken before the span starts).
	if err := conv.Checkpoint("cp"); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}

	s := conv.Stream(context.Background(), "go")
	// Drain the stream in a goroutine; it blocks mid-iteration until released.
	done := make(chan struct{})
	go func() {
		for range s.All() {
		}
		close(done)
	}()
	<-started // the stream span is now live and parked mid-round-trip

	if err := conv.Restore("cp"); !errors.Is(err, ErrSpanInFlight) {
		t.Errorf("Restore during live stream = %v, want ErrSpanInFlight", err)
	}
	if _, err := conv.Send(context.Background(), "second"); !errors.Is(err, ErrSpanInFlight) {
		t.Errorf("Send during live stream = %v, want ErrSpanInFlight", err)
	}

	close(release)
	<-done
	if err := s.Err(); err != nil {
		t.Errorf("stream Err = %v", err)
	}
	// Span released: a subsequent Restore now succeeds.
	if err := conv.Restore("cp"); err != nil {
		t.Errorf("Restore after span = %v", err)
	}
}

// blockingStreamProvider returns a stream that signals started on the first
// yield then blocks until release closes, holding the span open.
type blockingStreamProvider struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingStreamProvider) Chat(ctx context.Context, msgs []Message, opts Options) (Message, error) {
	return AssistantText("unused"), nil
}

func (b *blockingStreamProvider) Stream(ctx context.Context, msgs []Message, opts Options) Stream {
	return &blockingStream{p: b, ctx: ctx}
}

func (b *blockingStreamProvider) Embed(ctx context.Context, in []string) ([]Embedding, error) {
	return []Embedding{}, nil
}

type blockingStream struct {
	p   *blockingStreamProvider
	ctx context.Context
}

func (s *blockingStream) All() iter.Seq[Event] {
	return func(yield func(Event) bool) {
		s.p.once.Do(func() { close(s.p.started) })
		<-s.p.release
		yield(Event{Kind: EventText, Text: "done"})
	}
}

func (s *blockingStream) Err() error { return nil }

// blockingProvider signals started then blocks in Chat until release closes.
type blockingProvider struct {
	started chan struct{}
	release chan struct{}
	reply   Message
	once    sync.Once
}

func (b *blockingProvider) Chat(ctx context.Context, msgs []Message, opts Options) (Message, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return b.reply, nil
}

func (b *blockingProvider) Stream(ctx context.Context, msgs []Message, opts Options) Stream {
	return &fakeStream{ctx: ctx, events: []Event{{Kind: EventDone}}}
}

func (b *blockingProvider) Embed(ctx context.Context, in []string) ([]Embedding, error) {
	return []Embedding{}, nil
}
