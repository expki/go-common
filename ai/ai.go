// Package ai is a provider-agnostic interface for large-language-model
// backends. Application code programs against this package once and runs
// unchanged across Claude, OpenAI, Ollama, and llama.cpp: only the constructor
// line (e.g. [github.com/expki/go-common/ai/claude].NewChat) names a concrete
// backend; everything after it is identical.
//
// The design is a narrow [ChatModel] interface — single-turn generation only —
// plus a stateful [Conversation] owned by this package that adds running
// history, named checkpoints, an automatic tool-execution loop, and durable
// persistence on top of any ChatModel. Providers are thin adapters that
// translate generic verbs and controls into native SDK or HTTP calls; the
// orchestration that is hardest to get right (the tool-loop, checkpoint and
// restore, the bbolt store) is written once here and inherited by every
// backend.
//
// # Two capabilities, constructed separately
//
// Chat and embeddings are distinct capabilities, each obtained from its own
// constructor. Every provider package exposes NewChat, returning a [ChatModel]
// for [Conversation]; a provider whose backend has a native embeddings endpoint
// also exposes NewEmbed, returning an [Embedder]. Claude has no native
// embeddings endpoint, so it offers only NewChat — embed alongside Claude chat
// by constructing a separate [Embedder] from another provider (for example
// [github.com/expki/go-common/ai/openai].NewEmbed).
//
// # Generic verbs and controls
//
// The app-facing verbs are chat ([Conversation.Send]), streaming chat
// ([Conversation.Stream]), embeddings ([Embedder.Embed]), and tool-augmented
// chat (register a Go func with [Conversation.RegisterToolFunc] and the loop
// calls it automatically). The per-prompt controls are thinking on/off
// ([Thinking]) and tool mode none/optional/required ([Tools]). No
// provider-specific knob ever appears in an app-facing signature.
//
// # Silent degradation
//
// A generic capability that the active model cannot honor degrades silently
// rather than erroring: an [Embedder] with no vectors to produce (for example
// an empty input) returns a non-nil zero-length slice, and Thinking(On) on a
// non-reasoning model simply runs without thinking. The single exception is
// [ToolRequired]: a chat model that cannot force a tool call must not silently
// pretend it did — instead the run completes with a non-fatal
// "ToolRequiredNotHonored" caveat on the resulting [Message] (see [ToolForcer]).
// Configuration errors (an unbindable tool invoker after reload, a schema
// mismatch) are not capability gaps and do error.
package ai

import "context"

// ChatModel is the chat interface every backend implements and apps program
// against. It performs single-turn generation only; multi-turn state, the
// tool-loop, and checkpoints are owned by [Conversation]. Embeddings are a
// separate capability obtained from each provider's NewEmbed constructor (see
// [Embedder]).
type ChatModel interface {
	// Chat performs one synchronous generation turn over the supplied
	// messages and returns the assistant message it produced.
	Chat(ctx context.Context, msgs []Message, opts Options) (Message, error)
	// Stream performs one streaming generation turn over the supplied
	// messages; iterate the returned [Stream] and check its Err afterwards.
	Stream(ctx context.Context, msgs []Message, opts Options) Stream
}

// Embedder is the embedding capability, constructed separately from chat via
// each provider's NewEmbed constructor (for example
// [github.com/expki/go-common/ai/openai].NewEmbed). Backends without a native
// embeddings endpoint (Claude) expose no NewEmbed; embed alongside such a
// backend by constructing an [Embedder] from another provider.
type Embedder interface {
	// Embed returns one vector per input. An empty input yields a non-nil
	// zero-length slice rather than an error.
	Embed(ctx context.Context, inputs []string) ([]Embedding, error)
}

// ToolForcer is an OPTIONAL, read-only capability probe. Providers that can
// force a tool call (for example via tool_choice=required or any) implement it
// returning true. It is introspection, never a tuning knob, so it does not
// breach the provider-blind contract. A provider that does not implement
// ToolForcer is assumed unable to force tools, in which case [ToolRequired]
// degrades to a surfaced "ToolRequiredNotHonored" caveat rather than a silent
// downgrade.
type ToolForcer interface {
	// CanForceTools reports whether ToolRequired can be honored as a hard
	// force on this provider.
	CanForceTools() bool
}

// ToolRequiredNotHonored is the non-fatal caveat surfaced on a [Message] (and
// on the terminal EventDone of a [Stream]) when [ToolRequired] was requested
// but the active provider cannot force a tool call and the turn produced none.
// It appears as a string in [Message.Caveats] and [Event.Caveats].
const ToolRequiredNotHonored = "ToolRequiredNotHonored"
