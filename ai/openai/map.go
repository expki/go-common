package openai

import (
	"encoding/json"
	"strings"

	"github.com/expki/go-common/ai"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/packages/param"
	"github.com/openai/openai-go/shared"
)

// buildParams maps generic messages and per-turn options into
// ChatCompletionNewParams: it translates each message into its native role
// shape, the thinking control into reasoning_effort, and the tool control into
// tool definitions plus tool_choice.
//
// OpenAI's prompt caching is automatic with no API control, so the checkpoint
// boundary read via opts.CacheAnchor() is deliberately ignored here (§4.7); the
// accessor is still the contractual way the anchor would be consumed, so it is
// not read at all rather than read into a discarded field.
func (p *chatModel) buildParams(msgs []ai.Message, opts ai.Options) openai.ChatCompletionNewParams {
	params := openai.ChatCompletionNewParams{
		Model:    p.model,
		Messages: toMessages(msgs),
	}
	mapThinking(&params, opts.Thinking, p.model)
	mapTools(&params, opts)
	return params
}

// toMessages maps the generic history into OpenAI message params, preserving
// system framing, assistant tool calls, and tool results.
func toMessages(msgs []ai.Message) []openai.ChatCompletionMessageParamUnion {
	out := make([]openai.ChatCompletionMessageParamUnion, 0, len(msgs))
	for _, m := range msgs {
		switch m.Role {
		case ai.RoleSystem:
			out = append(out, openai.SystemMessage(m.Text()))
		case ai.RoleAssistant:
			out = append(out, toAssistantMessage(m))
		case ai.RoleTool:
			// A tool turn carries one or more tool-result blocks, each of which
			// becomes its own OpenAI tool message keyed by the call id.
			for _, b := range m.Content {
				if b.Kind == ai.BlockToolResult && b.ToolResult != nil {
					out = append(out, openai.ToolMessage(string(b.ToolResult.Content), b.ToolResult.CallID))
				}
			}
		default:
			// User turns (and any tool results that rode on a user turn) map to
			// a user message for the text and standalone tool messages for any
			// results.
			if text := m.Text(); text != "" {
				out = append(out, openai.UserMessage(text))
			}
			for _, b := range m.Content {
				if b.Kind == ai.BlockToolResult && b.ToolResult != nil {
					out = append(out, openai.ToolMessage(string(b.ToolResult.Content), b.ToolResult.CallID))
				}
			}
		}
	}
	return out
}

// toAssistantMessage maps a generic assistant turn into an OpenAI assistant
// message param, carrying its text content and any tool calls it requested.
func toAssistantMessage(m ai.Message) openai.ChatCompletionMessageParamUnion {
	var am openai.ChatCompletionAssistantMessageParam
	if text := m.Text(); text != "" {
		am.Content.OfString = param.NewOpt(text)
	}
	for _, tc := range m.ToolCalls {
		am.ToolCalls = append(am.ToolCalls, openai.ChatCompletionMessageToolCallParam{
			ID: tc.ID,
			Function: openai.ChatCompletionMessageToolCallFunctionParam{
				Name:      tc.Name,
				Arguments: string(tc.Arguments),
			},
		})
	}
	return openai.ChatCompletionMessageParamUnion{OfAssistant: &am}
}

// mapThinking translates the generic thinking control into reasoning_effort.
// ThinkingOn requests high effort and ThinkingOff requests minimal effort.
// reasoning_effort is set ONLY for reasoning models: the OpenAI Chat
// Completions API rejects the field with a 400 on a non-reasoning model (for
// example the default gpt-4o) rather than ignoring it, so sending it there
// would turn a capability gap into a hard error. Gating on the model keeps the
// thinking control a silent degrade per Principle 3. ThinkingDefault leaves the
// field unset (provider default).
func mapThinking(params *openai.ChatCompletionNewParams, mode ai.ThinkingMode, model shared.ChatModel) {
	if !isReasoningModel(model) {
		return
	}
	switch mode {
	case ai.ThinkingOn:
		params.ReasoningEffort = shared.ReasoningEffortHigh
	case ai.ThinkingOff:
		// "low" is the least reasoning a reasoning model will do via this field.
		params.ReasoningEffort = shared.ReasoningEffortLow
	}
}

// isReasoningModel reports whether model is an OpenAI reasoning model that
// accepts the reasoning_effort parameter. The reasoning families are the o-
// series (o1/o3/o4…) and gpt-5; everything else (gpt-4o, gpt-4.1, …) is a
// standard chat model that rejects the field. The check is a prefix match so
// dated and sized variants (o3-mini, gpt-5-2025-…) are covered.
func isReasoningModel(model shared.ChatModel) bool {
	m := string(model)
	for _, prefix := range []string{"o1", "o3", "o4", "gpt-5"} {
		if m == prefix || strings.HasPrefix(m, prefix+"-") {
			return true
		}
	}
	return false
}

// mapTools translates the registered tool descriptors and the generic tool
// mode into OpenAI function tool definitions and tool_choice.
func mapTools(params *openai.ChatCompletionNewParams, opts ai.Options) {
	if opts.Tools == ai.ToolNone || len(opts.ToolDefs) == 0 {
		if opts.Tools == ai.ToolNone {
			params.ToolChoice = openai.ChatCompletionToolChoiceOptionUnionParam{
				OfAuto: param.NewOpt(string(openai.ChatCompletionToolChoiceOptionAutoNone)),
			}
		}
		return
	}

	tools := make([]openai.ChatCompletionToolParam, 0, len(opts.ToolDefs))
	for _, t := range opts.ToolDefs {
		var schema map[string]any
		_ = json.Unmarshal(t.Schema, &schema)
		tools = append(tools, openai.ChatCompletionToolParam{
			Function: shared.FunctionDefinitionParam{
				Name:        t.Name,
				Description: param.NewOpt(t.Description),
				Parameters:  shared.FunctionParameters(schema),
			},
		})
	}
	params.Tools = tools

	switch opts.Tools {
	case ai.ToolOptional:
		params.ToolChoice = openai.ChatCompletionToolChoiceOptionUnionParam{
			OfAuto: param.NewOpt(string(openai.ChatCompletionToolChoiceOptionAutoAuto)),
		}
	case ai.ToolRequired:
		params.ToolChoice = openai.ChatCompletionToolChoiceOptionUnionParam{
			OfAuto: param.NewOpt(string(openai.ChatCompletionToolChoiceOptionAutoRequired)),
		}
	}
}

// fromCompletion maps an OpenAI chat completion response back into an
// [ai.Message], collecting text and tool calls from the first choice.
func fromCompletion(resp *openai.ChatCompletion) ai.Message {
	out := ai.Message{Role: ai.RoleAssistant}
	if len(resp.Choices) == 0 {
		return out
	}
	msg := resp.Choices[0].Message
	if msg.Content != "" {
		out.Content = append(out.Content, ai.ContentBlock{Kind: ai.BlockText, Text: msg.Content})
	}
	for _, tc := range msg.ToolCalls {
		out.ToolCalls = append(out.ToolCalls, ai.ToolCall{
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: json.RawMessage(tc.Function.Arguments),
		})
	}
	return out
}

// fromEmbeddings maps an OpenAI embeddings response into []ai.Embedding,
// preserving input order and converting the API's float64 vectors to float32.
func fromEmbeddings(resp *openai.CreateEmbeddingResponse) []ai.Embedding {
	out := make([]ai.Embedding, len(resp.Data))
	for _, d := range resp.Data {
		vec := make(ai.Embedding, len(d.Embedding))
		for i, f := range d.Embedding {
			vec[i] = float32(f)
		}
		// The API documents Index as the position in the input list; honor it
		// so order is preserved even if the response is reordered.
		if d.Index >= 0 && int(d.Index) < len(out) {
			out[d.Index] = vec
		}
	}
	return out
}
