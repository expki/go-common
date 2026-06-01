// Package llamacpp is the llama.cpp (llama-server) adapter for the
// provider-agnostic github.com/expki/go-common/ai interface. Construct a chat
// model with [NewChat] and program against [ai.Conversation] exactly as for any
// other backend; for embeddings construct a separate [ai.Embedder] with
// [NewEmbed]. The only llama.cpp-specific code an app writes is the [NewChat] /
// [NewEmbed] call and its options.
//
// There is no official Go SDK for llama-server, so this adapter speaks its HTTP
// API directly (see ai/llama.cpp.md): chat and streaming render the generic
// messages through POST /apply-template and generate with POST /completion (SSE
// when streaming); embeddings use POST /embedding; the generic thinking control
// maps to the reasoning request fields (silently ignored on non-reasoning
// models); and tool calling is elicited with json_schema-constrained
// generation parsed back into tool calls.
//
// # Tools cannot be hard-forced
//
// llama-server's /completion has no native tool_choice, so this provider
// deliberately does NOT implement [ai.ToolForcer]. Per the package contract,
// [ai.ToolRequired] therefore degrades to a surfaced
// [ai.ToolRequiredNotHonored] caveat rather than a silent downgrade; the
// caveat is applied by [ai.Conversation], not here.
//
// # Slots are a pure latency optimization
//
// When [WithSlotSavePath] is set this adapter saves and restores the
// llama-server KV slot cache around checkpoints to warm prompt processing. Slot
// operations have NO correctness role: the local [ai.Conversation] history is
// always authoritative, every slot failure is swallowed, and a stale or
// colliding slot is merely a cache miss. See slots.go and §4.8 of the design.
package llamacpp

import (
	"context"

	"github.com/expki/go-common/ai"
)

// family is the provider-family identifier recorded with persisted
// conversations (see [ai.FamilyProvider]).
const family = "llamacpp"

// chatModel is the llama-server-backed [ai.ChatModel]. It is constructed by
// [NewChat] and is safe for concurrent use (the underlying *http.Client is).
type chatModel struct {
	client       *client
	model        string
	reasoning    bool
	slotSavePath string
}

// NewChat constructs a llama.cpp-backed [ai.ChatModel] talking to the
// llama-server at baseURL (for example "http://localhost:8080"). Pass options
// such as [WithModel], [WithReasoning], [WithSlotSavePath], [WithAPIKey], or
// [WithHTTPClient] to customize it.
func NewChat(baseURL string, opts ...Option) ai.ChatModel {
	o := resolve(opts)
	return &chatModel{
		client:       newClient(baseURL, o.apiKey, o.http),
		model:        o.model,
		reasoning:    o.reasoning,
		slotSavePath: o.slotSavePath,
	}
}

// Family reports the provider family for persisted-conversation validation.
func (p *chatModel) Family() string { return family }

// Chat performs one synchronous generation turn: it renders the messages
// through /apply-template, restores the conversation's KV slot best-effort,
// generates with /completion, then saves the slot best-effort. The returned
// message carries either assistant text or a parsed tool call.
func (p *chatModel) Chat(ctx context.Context, msgs []ai.Message, opts ai.Options) (ai.Message, error) {
	prompt, err := p.renderPrompt(ctx, msgs)
	if err != nil {
		return ai.Message{}, err
	}

	req := p.buildCompletion(prompt, opts, false)
	p.restoreSlot(ctx, opts)

	var resp completionResponse
	if err := p.client.postJSON(ctx, "/completion", req, &resp); err != nil {
		return ai.Message{}, err
	}

	p.saveSlot(ctx, opts)
	return fromCompletion(resp, opts.ToolDefs), nil
}

// Stream performs one streaming generation turn over the SSE form of
// /completion. The returned [ai.Stream] yields reasoning and text chunks and,
// if the constrained output forms a tool call, a single [ai.EventToolCall]; it
// never emits the terminal EventDone (the outer [ai.Conversation] owns that).
func (p *chatModel) Stream(ctx context.Context, msgs []ai.Message, opts ai.Options) ai.Stream {
	prompt, err := p.renderPrompt(ctx, msgs)
	if err != nil {
		return &errStream{err: err}
	}

	req := p.buildCompletion(prompt, opts, true)
	p.restoreSlot(ctx, opts)

	resp, err := p.client.postStream(ctx, "/completion", req)
	if err != nil {
		return &errStream{err: err}
	}
	return newStream(ctx, resp, opts.ToolDefs, func() { p.saveSlot(ctx, opts) })
}

// embedder is the llama-server-backed [ai.Embedder]. It is constructed by
// [NewEmbed] and is safe for concurrent use (the underlying *http.Client is).
type embedder struct {
	client *client
}

// NewEmbed constructs a llama.cpp-backed [ai.Embedder] talking to the
// llama-server at baseURL (for example "http://localhost:8080"). The server
// must have been started in embedding mode. Pass [WithAPIKey] or
// [WithHTTPClient] to customize it; chat-only options ([WithModel],
// [WithReasoning], [WithSlotSavePath]) are accepted but have no embedding role.
func NewEmbed(baseURL string, opts ...Option) ai.Embedder {
	o := resolve(opts)
	return &embedder{
		client: newClient(baseURL, o.apiKey, o.http),
	}
}

// Embed returns one vector per input via POST /embedding. A server not started
// in embedding mode returns an error, which propagates; an empty input list
// returns a non-nil zero-length slice without contacting the server.
func (e *embedder) Embed(ctx context.Context, inputs []string) ([]ai.Embedding, error) {
	out := make([]ai.Embedding, 0, len(inputs))
	for _, in := range inputs {
		var resp embeddingResponse
		if err := e.client.postJSON(ctx, "/embedding", embeddingRequest{Content: in}, &resp); err != nil {
			return nil, err
		}
		out = append(out, resp.vector())
	}
	return out, nil
}

// renderPrompt converts the generic messages into a single prompt string using
// the server's chat template (POST /apply-template).
func (p *chatModel) renderPrompt(ctx context.Context, msgs []ai.Message) (string, error) {
	var resp applyTemplateResponse
	req := applyTemplateRequest{Messages: toTemplateMessages(msgs)}
	if err := p.client.postJSON(ctx, "/apply-template", req, &resp); err != nil {
		return "", err
	}
	return resp.Prompt, nil
}

// restoreSlot best-effort restores the conversation's KV slot before
// generation (a cache warm-up). All failures are swallowed (§4.8).
func (p *chatModel) restoreSlot(ctx context.Context, opts ai.Options) {
	id, file, ok := p.slotTarget(opts)
	if !ok {
		return
	}
	p.doSlot(ctx, slotRestore, id, file)
}

// saveSlot best-effort saves the conversation's KV slot after generation. All
// failures are swallowed (§4.8).
func (p *chatModel) saveSlot(ctx context.Context, opts ai.Options) {
	id, file, ok := p.slotTarget(opts)
	if !ok {
		return
	}
	p.doSlot(ctx, slotSave, id, file)
}

// slotTarget computes the pinned id_slot and deterministic slot-cache filename
// for the active checkpoint boundary, or ok=false when slot caching is
// disabled (no --slot-save-path configured) or there is no checkpoint anchor to
// key on. Without an anchor there is no stable boundary to name a file from, so
// caching is skipped — still correct, just no warm cache.
func (p *chatModel) slotTarget(opts ai.Options) (id int, filename string, ok bool) {
	if p.slotSavePath == "" {
		return 0, "", false
	}
	boundary, has := opts.CacheAnchor()
	if !has {
		return 0, "", false
	}
	key := conversationKey(opts)
	return slotID(key), slotFilename(key, boundary), true
}
