// Package ollama is the Ollama adapter for the provider-agnostic
// github.com/expki/go-common/ai interface. Construct a chat model with
// [NewChat] and program against [ai.Conversation] exactly as for any other
// backend; for embeddings construct a separate [ai.Embedder] with [NewEmbed].
// The only Ollama-specific code an app writes is the [NewChat] / [NewEmbed]
// call.
//
// The adapter maps the generic verbs and controls to a local Ollama server via
// github.com/ollama/ollama/api: chat maps to /api/chat, streaming chat to the
// same endpoint read chunk by chunk, the thinking control to the native think
// parameter (silently ignored by non-thinking models), tool mode and reflected
// tool schemas to the tools array plus the message tool-call/tool-role loop,
// and embeddings to /api/embed. Ollama reuses its KV cache implicitly, so the
// conversation's checkpoint boundary ([ai.Options.CacheAnchor]) is ignored.
//
// Ollama cannot hard-force a tool call, so this adapter does not implement
// [ai.ToolForcer]: an [ai.ToolRequired] turn that produces no tool call
// completes with a surfaced "ToolRequiredNotHonored" caveat rather than an
// error (see the ai package docs).
package ollama

import (
	"context"
	"net/url"

	"github.com/expki/go-common/ai"
	"github.com/ollama/ollama/api"
)

// family is the provider-family identifier recorded with persisted
// conversations (see [ai.FamilyProvider]).
const family = "ollama"

// newAPIClient parses baseURL into an api.Client, preserving the
// construct-never-panics contract: a malformed baseURL produces a nil host that
// the api.Client surfaces as an error on the first request rather than
// panicking at construction.
func newAPIClient(baseURL string, o options) *api.Client {
	base, err := url.Parse(baseURL)
	if err != nil {
		base = &url.URL{}
	}
	return api.NewClient(base, o.http)
}

// chatModel is the Ollama-backed [ai.ChatModel]. It is constructed by [NewChat]
// and is safe for concurrent use (the underlying api.Client and *http.Client
// are).
type chatModel struct {
	client    *api.Client
	model     string
	keepAlive *api.Duration
}

// NewChat constructs an Ollama-backed [ai.ChatModel] talking to the server at
// baseURL (for example "http://localhost:11434"). Pass options such as
// [WithModel] (sets the chat model), [WithKeepAlive], or [WithHTTPClient] to
// customize it. A malformed baseURL yields a chat model whose calls fail when
// invoked rather than panicking at construction.
func NewChat(baseURL string, opts ...Option) ai.ChatModel {
	o := resolve(opts)
	model := o.model
	if model == "" {
		model = defaultModel
	}
	p := &chatModel{
		client: newAPIClient(baseURL, o),
		model:  model,
	}
	if o.keepAlive != nil {
		p.keepAlive = &api.Duration{Duration: *o.keepAlive}
	}
	return p
}

// Family reports the provider family for persisted-conversation validation.
func (p *chatModel) Family() string { return family }

// Chat performs one synchronous Ollama generation turn and maps the result
// back into an [ai.Message]. Streaming is disabled so the callback fires once
// with the complete message.
func (p *chatModel) Chat(ctx context.Context, msgs []ai.Message, opts ai.Options) (ai.Message, error) {
	req := p.buildChatRequest(msgs, opts, false)

	var final api.ChatResponse
	err := p.client.Chat(ctx, req, func(resp api.ChatResponse) error {
		final = resp
		return nil
	})
	if err != nil {
		return ai.Message{}, err
	}
	return fromOllamaMessage(final.Message), nil
}

// Stream performs one streaming Ollama generation turn, bridging the api.Client
// chunk callback into an [ai.Stream] that yields text, thinking, and tool-call
// events. The single terminal EventDone is emitted by the outer
// [ai.Conversation], so this provider-level stream does not emit it.
func (p *chatModel) Stream(ctx context.Context, msgs []ai.Message, opts ai.Options) ai.Stream {
	req := p.buildChatRequest(msgs, opts, true)
	return newStream(ctx, p.client, req)
}

// embedder is the Ollama-backed [ai.Embedder]. It is constructed by [NewEmbed]
// and is safe for concurrent use.
type embedder struct {
	client    *api.Client
	model     string
	keepAlive *api.Duration
}

// NewEmbed constructs an Ollama-backed [ai.Embedder] talking to the server at
// baseURL (for example "http://localhost:11434"). Pass [WithModel] to select
// the embeddings model (defaulting to "all-minilm"), plus [WithKeepAlive] or
// [WithHTTPClient] as needed. A malformed baseURL yields an embedder whose
// calls fail when invoked rather than panicking at construction.
func NewEmbed(baseURL string, opts ...Option) ai.Embedder {
	o := resolve(opts)
	model := o.model
	if model == "" {
		model = defaultEmbedModel
	}
	e := &embedder{
		client: newAPIClient(baseURL, o),
		model:  model,
	}
	if o.keepAlive != nil {
		e.keepAlive = &api.Duration{Duration: *o.keepAlive}
	}
	return e
}

// Embed returns one vector per input via Ollama's /api/embed endpoint using the
// configured embeddings model. A model that cannot embed surfaces as an error
// from the server; a successful call with no vectors yields a non-nil
// zero-length result.
func (e *embedder) Embed(ctx context.Context, inputs []string) ([]ai.Embedding, error) {
	// Short-circuit empty input with a non-nil zero-length slice and no network
	// call, matching the OpenAI and llama.cpp adapters (ai.Embedder contract).
	if len(inputs) == 0 {
		return []ai.Embedding{}, nil
	}
	req := &api.EmbedRequest{
		Model:     e.model,
		Input:     inputs,
		KeepAlive: e.keepAlive,
	}
	resp, err := e.client.Embed(ctx, req)
	if err != nil {
		return nil, err
	}
	out := make([]ai.Embedding, 0, len(resp.Embeddings))
	for _, vec := range resp.Embeddings {
		out = append(out, ai.Embedding(vec))
	}
	return out, nil
}
