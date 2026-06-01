package ai

import "errors"

// The sentinel errors below are all configuration-time or transport errors.
// They are deliberately NOT capability-gap errors: an unsupported generic
// capability degrades silently (see the package doc), but a misconfigured tool
// binding or a cross-family reload is a programming error that must surface.
var (
	// ErrToolUnbound is returned when a reloaded conversation needs to invoke
	// a tool whose Go func was never re-bound after load (tool funcs are not
	// serializable). Re-bind the invoker by name via a [ToolRegistry] passed
	// to [LoadConversation], or by calling [Conversation.RegisterToolFunc]
	// after load, then retry.
	ErrToolUnbound = errors.New("ai: tool invoker not bound")

	// ErrToolSchemaMismatch is returned when a re-registered Go func's freshly
	// reflected JSON schema differs from the schema persisted for that tool
	// name. It catches a tool's signature silently changing between runs,
	// which would corrupt an in-flight tool-loop.
	ErrToolSchemaMismatch = errors.New("ai: tool schema mismatch on rebind")

	// ErrProviderMismatch is returned by [LoadConversation] when a persisted
	// conversation is reloaded against a provider of a different family than
	// the one that created it. Thinking, tool, and cache semantics are
	// provider-specific, so reusing a persisted conversation across families
	// is unsupported; starting a new conversation with any provider is fine.
	ErrProviderMismatch = errors.New("ai: provider family mismatch on reload")

	// ErrSpanInFlight is returned when a second [Conversation.Send] or
	// [Conversation.Stream] span, or a history-mutating call such as
	// [Conversation.Restore], is attempted on a single Conversation while a
	// span is already in flight. A single Conversation is not safe for
	// concurrent mutation; distinct Conversations are independent.
	ErrSpanInFlight = errors.New("ai: conversation span already in flight")

	// ErrStreamInFlight is a documented alias of [ErrSpanInFlight], retained
	// for source compatibility. New code returns [ErrSpanInFlight].
	ErrStreamInFlight = ErrSpanInFlight
)
