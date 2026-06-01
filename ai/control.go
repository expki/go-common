package ai

// ThinkingMode is the per-prompt reasoning control. It maps to each provider's
// native reasoning mechanism and degrades silently on models that do not
// support reasoning.
type ThinkingMode int

const (
	// ThinkingDefault leaves reasoning at the provider's own default.
	ThinkingDefault ThinkingMode = iota
	// ThinkingOn requests that the model reason before answering.
	ThinkingOn
	// ThinkingOff requests that the model not reason before answering.
	ThinkingOff
)

// ToolMode is the per-prompt tool control. It maps to each provider's native
// tool_choice.
type ToolMode int

const (
	// ToolNone forbids tool calls for the turn.
	ToolNone ToolMode = iota
	// ToolOptional offers the registered tools and lets the model decide.
	ToolOptional
	// ToolRequired demands that the model call a tool. It is the single
	// control that does not degrade silently: a provider that cannot force a
	// call surfaces a [ToolRequiredNotHonored] caveat instead (see
	// [ToolForcer]).
	ToolRequired
)

// Options is the per-turn configuration a [ChatModel] receives. The exported
// fields are app-settable through [PromptOption] functions; the unexported
// cacheAnchor is populated only by [Conversation] and is never app-settable,
// which keeps the app-facing API provider-blind.
type Options struct {
	// Thinking is the reasoning control for the turn.
	Thinking ThinkingMode
	// Tools is the tool-choice control for the turn.
	Tools ToolMode
	// ToolDefs is the set of registered tool descriptors offered on the turn.
	// Conversation populates it from the tools registered on it.
	ToolDefs []Tool

	// cacheAnchor stores the active checkpoint boundary as (message index + 1),
	// set only by Conversation, so that the zero value (a plainly-constructed
	// Options{} or any direct ChatModel call) means "no anchor". It is read
	// cross-package via the read-only [Options.CacheAnchor] accessor.
	cacheAnchor int
}

// setCacheAnchor records the active checkpoint boundary at message index idx;
// a negative idx clears the anchor. Only [Conversation] calls it.
func (o *Options) setCacheAnchor(idx int) {
	if idx < 0 {
		o.cacheAnchor = 0
		return
	}
	o.cacheAnchor = idx + 1
}

// CacheAnchor reports the message index of the active checkpoint boundary that
// best-effort provider caching should anchor to. ok is false when no anchor is
// set (for example a fresh conversation with no checkpoint, or any Options not
// produced by a Conversation). There is deliberately no setter: only
// [Conversation] populates the backing field, so apps stay provider-blind.
// Provider map code in other packages reads it as
//
//	if idx, ok := opts.CacheAnchor(); ok { /* place cache breakpoint at idx */ }
func (o Options) CacheAnchor() (index int, ok bool) {
	if o.cacheAnchor <= 0 {
		return 0, false
	}
	return o.cacheAnchor - 1, true
}

// PromptOption configures the [Options] for a single [Conversation.Send] or
// [Conversation.Stream] turn.
type PromptOption func(*Options)

// Thinking sets the reasoning mode for the turn.
func Thinking(m ThinkingMode) PromptOption {
	return func(o *Options) { o.Thinking = m }
}

// Tools sets the tool-choice mode for the turn.
func Tools(m ToolMode) PromptOption {
	return func(o *Options) { o.Tools = m }
}

// DefaultMaxToolIterations is the default bound on the number of tool turns in
// a single [Conversation.Send] or [Conversation.Stream] span.
const DefaultMaxToolIterations = 8

// ConvOption configures a [Conversation] at construction time.
type ConvOption func(*convOptions)

type convOptions struct {
	id           string
	maxToolIters int
}

// WithMaxToolIterations bounds the total number of tool turns in a single
// Send or Stream span. The default is [DefaultMaxToolIterations]. A value of
// n <= 0 leaves the default in place.
func WithMaxToolIterations(n int) ConvOption {
	return func(o *convOptions) {
		if n > 0 {
			o.maxToolIters = n
		}
	}
}

// WithID assigns an explicit conversation id instead of a generated one. The
// id is the bbolt key under which the conversation persists.
func WithID(id string) ConvOption {
	return func(o *convOptions) { o.id = id }
}

func resolveConvOptions(opts []ConvOption) convOptions {
	o := convOptions{maxToolIters: DefaultMaxToolIterations}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
