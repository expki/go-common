package ollama

import (
	"context"
	"iter"

	"github.com/expki/go-common/ai"
	"github.com/ollama/ollama/api"
)

// ollamaStream adapts the api.Client chunk callback to [ai.Stream]. The Ollama
// SDK delivers each chunk by invoking a callback on its own request goroutine;
// this bridges those chunks into a pull-style iter.Seq by running the request
// in a goroutine and forwarding events over a channel. Text and thinking
// deltas are yielded as they arrive; a chunk carrying tool calls yields one
// EventToolCall per call. The single terminal EventDone is emitted by the
// outer [ai.Conversation], so this stream does not emit it.
type ollamaStream struct {
	ctx    context.Context
	client *api.Client
	req    *api.ChatRequest
	err    error
}

func newStream(ctx context.Context, client *api.Client, req *api.ChatRequest) ai.Stream {
	return &ollamaStream{ctx: ctx, client: client, req: req}
}

// All drives the Ollama chat request and yields events. The request runs in a
// goroutine so the consumer can pull events; breaking out of the range early
// cancels that goroutine via ctx and drains it, so there is no leak.
func (s *ollamaStream) All() iter.Seq[ai.Event] {
	return func(yield func(ai.Event) bool) {
		// A child context lets an early break tear down the request goroutine
		// even when the caller's ctx is still live.
		ctx, cancel := context.WithCancel(s.ctx)
		defer cancel()

		events := make(chan ai.Event)
		// runErr is written only by the request goroutine and read only after
		// done is closed, so it needs no synchronization beyond that ordering.
		var runErr error
		done := make(chan struct{})

		go func() {
			defer close(done)
			runErr = s.client.Chat(ctx, s.req, func(resp api.ChatResponse) error {
				for _, ev := range chunkEvents(resp.Message) {
					select {
					case events <- ev:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			})
			close(events)
		}()

		// s.err is written only here, in the single consumer goroutine, after
		// the request goroutine has finished (done closed), so Err() observes a
		// fully published value once iteration ends.
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					<-done
					s.err = runErr
					return
				}
				if !yield(ev) {
					// Consumer stopped early: cancel and drain the goroutine.
					cancel()
					<-done
					s.err = runErr
					return
				}
			case <-ctx.Done():
				<-done
				if runErr != nil {
					s.err = runErr
				} else {
					s.err = ctx.Err()
				}
				return
			}
		}
	}
}

// Err returns the terminal error after iteration.
func (s *ollamaStream) Err() error { return s.err }

// chunkEvents converts one streamed Ollama message chunk into the generic
// events it carries: a thinking delta, a text delta, and any tool calls.
func chunkEvents(m api.Message) []ai.Event {
	var evs []ai.Event
	if m.Thinking != "" {
		evs = append(evs, ai.Event{Kind: ai.EventThinking, Thinking: m.Thinking})
	}
	if m.Content != "" {
		evs = append(evs, ai.Event{Kind: ai.EventText, Text: m.Content})
	}
	for _, tc := range fromOllamaToolCalls(m.ToolCalls) {
		call := tc
		evs = append(evs, ai.Event{Kind: ai.EventToolCall, ToolCall: &call})
	}
	return evs
}
