// Package openai is the OpenAI adapter for the provider-agnostic
// github.com/expki/go-common/ai interface. Construct a chat model with
// [NewChat] and program against [ai.Conversation] exactly as for any other
// backend; for embeddings construct a separate [ai.Embedder] with [NewEmbed].
// The only OpenAI-specific code an app writes is the [NewChat] / [NewEmbed]
// call.
//
// The adapter maps the generic verbs and controls to the OpenAI Chat
// Completions API via github.com/openai/openai-go: thinking maps to
// reasoning_effort (best-effort, silently degrading on non-reasoning models),
// tool mode to tool_choice, reflected tool schemas to function tool
// definitions, and embeddings to the text-embedding-3-* models. OpenAI's prompt
// caching is automatic with no API control, so the conversation's checkpoint
// boundary ([ai.Options.CacheAnchor]) is a no-op here.
package openai

import (
	"context"

	"github.com/expki/go-common/ai"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/shared"
)

// family is the provider-family identifier recorded with persisted
// conversations (see [ai.FamilyProvider]).
const family = "openai"

// chatModel is the OpenAI-backed [ai.ChatModel]. It is constructed by [NewChat]
// and is safe for concurrent use.
type chatModel struct {
	client openai.Client
	model  shared.ChatModel
}

// newRequestOptions builds the SDK request options shared by [NewChat] and
// [NewEmbed] from resolved options.
func newRequestOptions(o options) []option.RequestOption {
	reqOpts := []option.RequestOption{option.WithAPIKey(o.apiKey)}
	if o.baseURL != "" {
		reqOpts = append(reqOpts, option.WithBaseURL(o.baseURL))
	}
	if o.http != nil {
		reqOpts = append(reqOpts, option.WithHTTPClient(o.http))
	}
	return reqOpts
}

// NewChat constructs an OpenAI-backed [ai.ChatModel]. apiKey is the OpenAI API
// key; pass options such as [WithModel] (sets the chat model), [WithBaseURL],
// or [WithHTTPClient] to customize it.
func NewChat(apiKey string, opts ...Option) ai.ChatModel {
	o := resolve(apiKey, opts)
	model := o.model
	if model == "" {
		model = defaultModel
	}
	return &chatModel{
		client: openai.NewClient(newRequestOptions(o)...),
		model:  model,
	}
}

// Family reports the provider family for persisted-conversation validation.
func (p *chatModel) Family() string { return family }

// CanForceTools reports that OpenAI can hard-force a tool call
// (tool_choice=required), so [ai.ToolRequired] is honored natively rather than
// surfaced as a caveat.
func (p *chatModel) CanForceTools() bool { return true }

// Chat performs one synchronous OpenAI generation turn and maps the result
// back into an [ai.Message].
func (p *chatModel) Chat(ctx context.Context, msgs []ai.Message, opts ai.Options) (ai.Message, error) {
	params := p.buildParams(msgs, opts)
	resp, err := p.client.Chat.Completions.New(ctx, params)
	if err != nil {
		return ai.Message{}, err
	}
	return fromCompletion(resp), nil
}

// Stream performs one streaming OpenAI generation turn, wrapping the SDK SSE
// cursor in an [ai.Stream] that yields text and tool-call events.
func (p *chatModel) Stream(ctx context.Context, msgs []ai.Message, opts ai.Options) ai.Stream {
	params := p.buildParams(msgs, opts)
	cursor := p.client.Chat.Completions.NewStreaming(ctx, params)
	return newStream(ctx, cursor)
}

// embedder is the OpenAI-backed [ai.Embedder]. It is constructed by [NewEmbed]
// and is safe for concurrent use.
type embedder struct {
	client openai.Client
	model  string
}

// NewEmbed constructs an OpenAI-backed [ai.Embedder]. apiKey is the OpenAI API
// key; pass [WithModel] to select the embeddings model (defaulting to
// text-embedding-3-small), plus [WithBaseURL] or [WithHTTPClient] as needed.
func NewEmbed(apiKey string, opts ...Option) ai.Embedder {
	o := resolve(apiKey, opts)
	model := o.model
	if model == "" {
		model = defaultEmbedModel
	}
	return &embedder{
		client: openai.NewClient(newRequestOptions(o)...),
		model:  string(model),
	}
}

// Embed returns one vector per input via the OpenAI embeddings endpoint using
// the model selected with [WithModel] (defaulting to text-embedding-3-small).
// The result preserves input order. An empty input slice returns a non-nil
// zero-length result without contacting the API.
func (e *embedder) Embed(ctx context.Context, inputs []string) ([]ai.Embedding, error) {
	if len(inputs) == 0 {
		return []ai.Embedding{}, nil
	}
	resp, err := e.client.Embeddings.New(ctx, openai.EmbeddingNewParams{
		Model: e.model,
		Input: openai.EmbeddingNewParamsInputUnion{OfArrayOfStrings: inputs},
	})
	if err != nil {
		return nil, err
	}
	return fromEmbeddings(resp), nil
}
