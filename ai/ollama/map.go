package ollama

import (
	"encoding/json"

	"github.com/expki/go-common/ai"
	"github.com/ollama/ollama/api"
)

// buildChatRequest maps generic messages and per-turn options into an Ollama
// api.ChatRequest. stream selects streaming vs. single-response mode. The
// checkpoint boundary (opts.CacheAnchor) is intentionally not consulted:
// Ollama reuses its KV cache implicitly, so there is no anchor to place.
func (p *chatModel) buildChatRequest(msgs []ai.Message, opts ai.Options, stream bool) *api.ChatRequest {
	req := &api.ChatRequest{
		Model:     p.model,
		Messages:  toOllamaMessages(msgs),
		Stream:    &stream,
		KeepAlive: p.keepAlive,
		Options:   map[string]any{},
	}

	mapThinking(req, opts.Thinking)
	mapTools(req, opts)
	return req
}

// toOllamaMessages converts the generic history into Ollama messages. Text
// blocks concatenate into the message content; assistant tool calls become
// message tool_calls; tool-result blocks become tool-role messages carrying the
// originating tool name.
func toOllamaMessages(msgs []ai.Message) []api.Message {
	var out []api.Message
	for _, m := range msgs {
		// Tool results are sent as their own tool-role messages, one per
		// result, so they correlate back to the model's tool calls.
		var toolResults []api.Message
		var content string
		for _, b := range m.Content {
			switch b.Kind {
			case ai.BlockText:
				content += b.Text
			case ai.BlockToolResult:
				if b.ToolResult != nil {
					toolResults = append(toolResults, api.Message{
						Role:       string(ai.RoleTool),
						Content:    string(b.ToolResult.Content),
						ToolName:   b.ToolResult.Name,
						ToolCallID: b.ToolResult.CallID,
					})
				}
			}
		}

		if len(toolResults) > 0 {
			out = append(out, toolResults...)
			// A tool-result turn carries no additional assistant/user content.
			continue
		}

		msg := api.Message{
			Role:     string(m.Role),
			Content:  content,
			Thinking: m.Thinking,
		}
		msg.ToolCalls = toOllamaToolCalls(m.ToolCalls)
		out = append(out, msg)
	}
	return out
}

// toOllamaToolCalls maps generic tool calls into Ollama tool calls, decoding
// the raw JSON arguments into the ordered-argument container Ollama expects.
func toOllamaToolCalls(calls []ai.ToolCall) []api.ToolCall {
	if len(calls) == 0 {
		return nil
	}
	out := make([]api.ToolCall, 0, len(calls))
	for _, tc := range calls {
		args := api.NewToolCallFunctionArguments()
		if len(tc.Arguments) > 0 {
			_ = json.Unmarshal(tc.Arguments, &args)
		}
		out = append(out, api.ToolCall{
			ID: tc.ID,
			Function: api.ToolCallFunction{
				Name:      tc.Name,
				Arguments: args,
			},
		})
	}
	return out
}

// mapThinking translates the generic thinking control to Ollama's think
// parameter. ThinkingOn/Off set the boolean; ThinkingDefault leaves it unset so
// the model's own default applies. Non-thinking models silently ignore it.
func mapThinking(req *api.ChatRequest, mode ai.ThinkingMode) {
	switch mode {
	case ai.ThinkingOn:
		req.Think = &api.ThinkValue{Value: true}
	case ai.ThinkingOff:
		req.Think = &api.ThinkValue{Value: false}
	}
}

// mapTools translates the registered tool descriptors and the generic tool
// mode into Ollama tool definitions. Ollama has no tool_choice control, so
// ToolNone simply omits the tools array while ToolOptional and ToolRequired
// both offer the tools; the inability to hard-force is reflected by the
// provider not implementing [ai.ToolForcer].
func mapTools(req *api.ChatRequest, opts ai.Options) {
	if opts.Tools == ai.ToolNone || len(opts.ToolDefs) == 0 {
		return
	}
	tools := make(api.Tools, 0, len(opts.ToolDefs))
	for _, t := range opts.ToolDefs {
		tools = append(tools, toOllamaTool(t))
	}
	req.Tools = tools
}

// toOllamaTool serializes one reflected [ai.Tool] into an Ollama tool
// definition. The reflected JSON schema is unmarshaled into Ollama's parameter
// container so the property order and types carry over intact.
func toOllamaTool(t ai.Tool) api.Tool {
	fn := api.ToolFunction{
		Name:        t.Name,
		Description: t.Description,
	}
	if len(t.Schema) > 0 {
		_ = json.Unmarshal(t.Schema, &fn.Parameters)
	}
	if fn.Parameters.Type == "" {
		fn.Parameters.Type = "object"
	}
	return api.Tool{Type: "function", Function: fn}
}

// fromOllamaMessage maps an Ollama response message back into an [ai.Message],
// collecting text, thinking, and tool calls.
func fromOllamaMessage(m api.Message) ai.Message {
	out := ai.Message{Role: ai.RoleAssistant, Thinking: m.Thinking}
	if m.Content != "" {
		out.Content = append(out.Content, ai.ContentBlock{Kind: ai.BlockText, Text: m.Content})
	}
	out.ToolCalls = fromOllamaToolCalls(m.ToolCalls)
	return out
}

// fromOllamaToolCalls maps Ollama tool calls back into generic tool calls,
// re-encoding the ordered arguments as a raw JSON object.
func fromOllamaToolCalls(calls []api.ToolCall) []ai.ToolCall {
	if len(calls) == 0 {
		return nil
	}
	out := make([]ai.ToolCall, 0, len(calls))
	for _, tc := range calls {
		raw, err := json.Marshal(tc.Function.Arguments)
		if err != nil || len(raw) == 0 {
			raw = json.RawMessage("{}")
		}
		out = append(out, ai.ToolCall{
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: json.RawMessage(raw),
		})
	}
	return out
}
