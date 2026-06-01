// Package claude is the Anthropic Claude adapter for the provider-agnostic
// github.com/expki/go-common/ai interface. Construct a chat model with
// [NewChat] and program against [ai.Conversation] exactly as for any other
// backend; the only Claude-specific code an app writes is the [NewChat] call.
//
// Claude has no native embeddings endpoint, so this package exposes only
// [NewChat] and no NewEmbed. To embed alongside Claude chat, construct a
// separate [ai.Embedder] from another provider (for example
// github.com/expki/go-common/ai/openai.NewEmbed).
//
// The adapter maps the generic verbs and controls to the Anthropic Messages
// API via github.com/anthropics/anthropic-sdk-go: thinking maps to adaptive
// thinking, tool mode to tool_choice, reflected tool schemas to Anthropic tool
// definitions, and the conversation's checkpoint boundary (read via
// [ai.Options.CacheAnchor]) to a best-effort cache_control breakpoint.
package claude

import (
	"context"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/expki/go-common/ai"
)

// family is the provider-family identifier recorded with persisted
// conversations (see [ai.FamilyProvider]).
const family = "claude"

// chatModel is the Anthropic-backed [ai.ChatModel]. It is constructed by
// [NewChat] and is safe for concurrent use.
type chatModel struct {
	client    anthropic.Client
	model     anthropic.Model
	maxTokens int64
}

// NewChat constructs a Claude-backed [ai.ChatModel]. apiKey is the Anthropic
// API key; pass options such as [WithModel], [WithMaxTokens], [WithBaseURL], or
// [WithHTTPClient] to customize it.
func NewChat(apiKey string, opts ...Option) ai.ChatModel {
	o := resolve(apiKey, opts)

	reqOpts := []option.RequestOption{option.WithAPIKey(o.apiKey)}
	if o.baseURL != "" {
		reqOpts = append(reqOpts, option.WithBaseURL(o.baseURL))
	}
	if o.http != nil {
		reqOpts = append(reqOpts, option.WithHTTPClient(o.http))
	}

	return &chatModel{
		client:    anthropic.NewClient(reqOpts...),
		model:     o.model,
		maxTokens: o.maxTokens,
	}
}

// Family reports the provider family for persisted-conversation validation.
func (p *chatModel) Family() string { return family }

// CanForceTools reports that Claude can hard-force a tool call (tool_choice
// any/tool), so [ai.ToolRequired] is honored natively rather than surfaced as
// a caveat.
func (p *chatModel) CanForceTools() bool { return true }

// Chat performs one synchronous Anthropic generation turn and maps the result
// back into an [ai.Message].
func (p *chatModel) Chat(ctx context.Context, msgs []ai.Message, opts ai.Options) (ai.Message, error) {
	params := p.buildParams(msgs, opts)
	resp, err := p.client.Messages.New(ctx, params)
	if err != nil {
		return ai.Message{}, err
	}
	return fromAnthropicMessage(resp), nil
}

// Stream performs one streaming Anthropic generation turn, wrapping the SDK
// cursor in an [ai.Stream] that yields text, thinking, and tool-call events.
func (p *chatModel) Stream(ctx context.Context, msgs []ai.Message, opts ai.Options) ai.Stream {
	params := p.buildParams(msgs, opts)
	cursor := p.client.Messages.NewStreaming(ctx, params)
	return newStream(ctx, cursor)
}
