package ai

import (
	"context"
	"iter"
)

// convStream is the single logical [Stream] returned by [Conversation.Stream].
// Its All sequence drives the whole multi-turn tool-loop, yielding events from
// every provider turn into one range loop and recording a terminal error.
type convStream struct {
	c    *Conversation
	ctx  context.Context
	opts Options

	beginErr error // error from beginSpan (e.g. ErrSpanInFlight)
	err      error
}

// Stream appends a user turn carrying text and returns a single [Stream] that
// spans the whole auto tool-loop: text and thinking events from each provider
// turn are yielded into one sequence, an [EventToolCall] is yielded per tool
// turn, and the sequence ends with a single [EventDone]. The loop is bounded
// by [WithMaxToolIterations]; context cancellation tears down the current
// inner provider stream and ends the sequence, after which Err reports
// ctx.Err. When [ToolRequired] was requested but the provider cannot force a
// tool call and none occurred, the terminal [EventDone] carries a
// [ToolRequiredNotHonored] caveat. A second concurrent span makes the returned
// stream's Err report [ErrSpanInFlight] with no events.
//
// A hard error during the span (a provider failure, or a tool-loop error such
// as [ErrToolUnbound] when a reloaded conversation's invoker was never
// rebound) ends the sequence WITHOUT a terminal [EventDone] and surfaces via
// [Stream.Err]; the span is still released, so a later Send or Stream may run.
func (c *Conversation) Stream(ctx context.Context, text string, opts ...PromptOption) Stream {
	s := &convStream{c: c, ctx: ctx}
	if err := c.beginSpan(); err != nil {
		s.beginErr = err
		return s
	}
	s.opts = c.buildOptions(opts)
	c.appendUser(text)
	return s
}

// Err returns the terminal error after the sequence has been consumed.
func (s *convStream) Err() error {
	if s.beginErr != nil {
		return s.beginErr
	}
	return s.err
}

// All drives the tool-loop and yields its events. It owns clearing the span
// (endSpan) and recording the terminal error, both performed before it
// returns — whether the loop completes, the consumer breaks early, or the
// context is cancelled.
func (s *convStream) All() iter.Seq[Event] {
	return func(yield func(Event) bool) {
		if s.beginErr != nil {
			return // span never started; Err reports beginErr.
		}
		defer s.c.endSpan()

		forceable := s.c.canForceTools()
		sawToolCall := false

		for iters := 0; iters < s.c.maxToolIters; iters++ {
			if err := s.ctx.Err(); err != nil {
				s.err = err
				return
			}
			inner := s.c.provider.Stream(s.ctx, s.c.snapshot(), s.opts)

			var calls []ToolCall
			var assistant Message
			stopped := false

			for ev := range inner.All() {
				switch ev.Kind {
				case EventToolCall:
					if ev.ToolCall != nil {
						calls = append(calls, *ev.ToolCall)
						assistant.ToolCalls = append(assistant.ToolCalls, *ev.ToolCall)
					}
					if !yield(ev) {
						stopped = true
					}
				case EventText:
					assistant.Content = append(assistant.Content, ContentBlock{Kind: BlockText, Text: ev.Text})
					if !yield(ev) {
						stopped = true
					}
				case EventThinking:
					// A signed thinking block surfaces its signature on a final
					// EventThinking that carries no text; record it on the
					// assembled message (for replay) without yielding an empty
					// chunk to the consumer.
					if ev.ThinkingSignature != "" {
						assistant.ThinkingSignature = ev.ThinkingSignature
					}
					if ev.Thinking != "" {
						assistant.Thinking += ev.Thinking
						if !yield(ev) {
							stopped = true
						}
					}
				case EventDone:
					// Swallow inner EventDone; the outer span emits the only
					// terminal EventDone.
				default:
					if !yield(ev) {
						stopped = true
					}
				}
				if stopped {
					break
				}
			}

			if err := inner.Err(); err != nil {
				s.err = err
				return
			}
			if stopped {
				return // consumer broke early; cleanup already deferred.
			}

			assistant.Role = RoleAssistant
			s.c.appendMessage(assistant)

			if len(calls) == 0 {
				s.finish(yield, s.opts.Tools == ToolRequired && !forceable && !sawToolCall)
				return
			}
			sawToolCall = true
			results, err := s.c.runToolCalls(s.ctx, calls)
			if err != nil {
				s.err = err
				return
			}
			s.c.appendMessage(results)
		}
		// Iteration bound hit: terminate cleanly with no caveat.
		s.finish(yield, false)
	}
}

// finish persists the span and yields the single terminal EventDone, attaching
// the ToolRequiredNotHonored caveat when caveat is true.
func (s *convStream) finish(yield func(Event) bool, caveat bool) {
	done := Event{Kind: EventDone}
	if caveat {
		done.Caveats = []string{ToolRequiredNotHonored}
		s.c.addCaveat(ToolRequiredNotHonored)
	}
	if err := s.c.persist(); err != nil {
		s.err = err
		return
	}
	yield(done)
}
