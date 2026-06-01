package claude

import (
	"encoding/json"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/expki/go-common/ai"
)

// buildParams maps generic messages and per-turn options into Anthropic
// MessageNewParams: it splits out system turns, places the best-effort
// cache_control breakpoint at the checkpoint boundary, and translates the
// thinking and tool controls.
func (p *chatModel) buildParams(msgs []ai.Message, opts ai.Options) anthropic.MessageNewParams {
	params := anthropic.MessageNewParams{
		Model:     p.model,
		MaxTokens: p.maxTokens,
	}

	anchor, hasAnchor := opts.CacheAnchor()

	var system []anthropic.TextBlockParam
	var conv []anthropic.MessageParam
	for i, m := range msgs {
		// Best-effort prompt caching: mark a cache_control breakpoint on the
		// message at the active checkpoint boundary (§4.7). Anthropic ignores
		// a breakpoint below its minimum prefix, so this is purely a latency
		// optimization and never affects correctness.
		cacheHere := hasAnchor && i == anchor
		if m.Role == ai.RoleSystem {
			system = append(system, systemBlocks(m, cacheHere)...)
			continue
		}
		conv = append(conv, toAnthropicMessage(m, cacheHere))
	}
	params.System = system
	params.Messages = conv

	mapThinking(&params, opts.Thinking)
	mapTools(&params, opts)
	return params
}

// systemBlocks converts a system message into Anthropic system text blocks,
// optionally attaching a cache_control breakpoint to the last block.
func systemBlocks(m ai.Message, cache bool) []anthropic.TextBlockParam {
	var blocks []anthropic.TextBlockParam
	for _, b := range m.Content {
		if b.Kind == ai.BlockText {
			blocks = append(blocks, anthropic.TextBlockParam{Text: b.Text})
		}
	}
	if cache && len(blocks) > 0 {
		blocks[len(blocks)-1].CacheControl = anthropic.NewCacheControlEphemeralParam()
	}
	return blocks
}

// toAnthropicMessage maps one generic non-system message into an Anthropic
// MessageParam, preserving tool calls and tool results.
func toAnthropicMessage(m ai.Message, cache bool) anthropic.MessageParam {
	var blocks []anthropic.ContentBlockParamUnion

	// A signed thinking block must be replayed verbatim, and first, on an
	// assistant turn so a thinking+tools tool-loop is accepted (Anthropic
	// rejects the turn otherwise). Only replay when both the trace and its
	// signature survived; an unsigned trace is dropped rather than risk a
	// rejected request.
	if m.Role == ai.RoleAssistant && m.Thinking != "" && m.ThinkingSignature != "" {
		blocks = append(blocks, anthropic.NewThinkingBlock(m.ThinkingSignature, m.Thinking))
	}

	for _, b := range m.Content {
		switch b.Kind {
		case ai.BlockText:
			if b.Text != "" {
				blocks = append(blocks, anthropic.NewTextBlock(b.Text))
			}
		case ai.BlockToolResult:
			if b.ToolResult != nil {
				blocks = append(blocks, anthropic.NewToolResultBlock(
					b.ToolResult.CallID,
					string(b.ToolResult.Content),
					b.ToolResult.IsError,
				))
			}
		}
	}

	// Assistant tool calls become tool_use blocks.
	for _, tc := range m.ToolCalls {
		var input any = json.RawMessage(tc.Arguments)
		blocks = append(blocks, anthropic.ContentBlockParamUnion{
			OfToolUse: &anthropic.ToolUseBlockParam{
				ID:    tc.ID,
				Name:  tc.Name,
				Input: input,
			},
		})
	}

	if cache && len(blocks) > 0 {
		attachCache(&blocks[len(blocks)-1])
	}

	switch m.Role {
	case ai.RoleAssistant:
		return anthropic.NewAssistantMessage(blocks...)
	default:
		// User and tool-result turns are sent in the user role per the
		// Anthropic convention (tool_result blocks ride on a user turn).
		return anthropic.NewUserMessage(blocks...)
	}
}

// attachCache sets a cache_control breakpoint on a content block, covering the
// variants this adapter produces.
func attachCache(b *anthropic.ContentBlockParamUnion) {
	switch {
	case b.OfText != nil:
		b.OfText.CacheControl = anthropic.NewCacheControlEphemeralParam()
	case b.OfToolResult != nil:
		b.OfToolResult.CacheControl = anthropic.NewCacheControlEphemeralParam()
	case b.OfToolUse != nil:
		b.OfToolUse.CacheControl = anthropic.NewCacheControlEphemeralParam()
	}
}

// mapThinking translates the generic thinking control to Anthropic's adaptive
// thinking config. ThinkingOn requests adaptive thinking, ThinkingOff disables
// it, and ThinkingDefault leaves the field unset (provider default).
func mapThinking(params *anthropic.MessageNewParams, mode ai.ThinkingMode) {
	switch mode {
	case ai.ThinkingOn:
		params.Thinking = anthropic.ThinkingConfigParamUnion{
			OfAdaptive: &anthropic.ThinkingConfigAdaptiveParam{},
		}
	case ai.ThinkingOff:
		params.Thinking = anthropic.ThinkingConfigParamUnion{
			OfDisabled: &anthropic.ThinkingConfigDisabledParam{},
		}
	}
}

// mapTools translates the registered tool descriptors and the generic tool
// mode into Anthropic tool definitions and tool_choice.
func mapTools(params *anthropic.MessageNewParams, opts ai.Options) {
	if opts.Tools == ai.ToolNone || len(opts.ToolDefs) == 0 {
		if opts.Tools == ai.ToolNone {
			params.ToolChoice = anthropic.ToolChoiceUnionParam{
				OfNone: &anthropic.ToolChoiceNoneParam{},
			}
		}
		return
	}

	tools := make([]anthropic.ToolUnionParam, 0, len(opts.ToolDefs))
	for _, t := range opts.ToolDefs {
		var schema map[string]any
		_ = json.Unmarshal(t.Schema, &schema)
		tp := anthropic.ToolParam{
			Name:        t.Name,
			Description: anthropic.String(t.Description),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: schema["properties"],
				Required:   requiredFrom(schema),
			},
		}
		tools = append(tools, anthropic.ToolUnionParam{OfTool: &tp})
	}
	params.Tools = tools

	switch opts.Tools {
	case ai.ToolOptional:
		params.ToolChoice = anthropic.ToolChoiceUnionParam{OfAuto: &anthropic.ToolChoiceAutoParam{}}
	case ai.ToolRequired:
		params.ToolChoice = anthropic.ToolChoiceUnionParam{OfAny: &anthropic.ToolChoiceAnyParam{}}
	}
}

// requiredFrom extracts the "required" array from a reflected JSON schema.
func requiredFrom(schema map[string]any) []string {
	raw, ok := schema["required"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// fromAnthropicMessage maps an Anthropic response Message back into an
// [ai.Message], collecting text, thinking, and tool calls.
func fromAnthropicMessage(resp *anthropic.Message) ai.Message {
	out := ai.Message{Role: ai.RoleAssistant}
	for _, block := range resp.Content {
		switch v := block.AsAny().(type) {
		case anthropic.TextBlock:
			out.Content = append(out.Content, ai.ContentBlock{Kind: ai.BlockText, Text: v.Text})
		case anthropic.ThinkingBlock:
			out.Thinking += v.Thinking
			// Preserve the signature so the trace can be replayed on a later
			// turn (see toAnthropicMessage). The flat message model keeps one
			// signature; adaptive thinking produces a single thinking block.
			if v.Signature != "" {
				out.ThinkingSignature = v.Signature
			}
		case anthropic.ToolUseBlock:
			out.ToolCalls = append(out.ToolCalls, ai.ToolCall{
				ID:        v.ID,
				Name:      v.Name,
				Arguments: json.RawMessage(v.Input),
			})
		}
	}
	return out
}
