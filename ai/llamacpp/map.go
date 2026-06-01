package llamacpp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/expki/go-common/ai"
)

// templateMessage is one chat turn in the shape /apply-template and the
// OpenAI-compatible endpoints expect.
type templateMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// applyTemplateRequest renders generic messages through the server's chat
// template (POST /apply-template, ai/llama.cpp.md:655) into a single prompt
// string suitable for /completion.
type applyTemplateRequest struct {
	Messages []templateMessage `json:"messages"`
}

type applyTemplateResponse struct {
	Prompt string `json:"prompt"`
}

// completionRequest is the subset of POST /completion fields this adapter sets
// (ai/llama.cpp.md:412). Fields not set fall back to the server defaults.
type completionRequest struct {
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream,omitempty"`
	Model  string `json:"model,omitempty"`
	// IDSlot is always serialized (no omitempty): slotID deliberately pins a
	// slot in [0, numSlots), and slot 0 is a valid pin for the no-anchor case.
	// With omitempty an id_slot of 0 would be dropped, letting /completion
	// auto-pick a slot while save/restore still targets slot 0 — silently
	// defeating the slot cache for the ~1/8 of keys that hash to 0 (§4.8).
	IDSlot   int `json:"id_slot"`
	NPredict int `json:"n_predict,omitempty"`

	// JSONSchema constrains generation to a JSON object matching this schema,
	// the grammar-based mechanism used to elicit tool calls (there is no native
	// tool_choice on /completion). Set only when a single tool is offered.
	JSONSchema json.RawMessage `json:"json_schema,omitempty"`

	// Reasoning toggles thinking on supporting models; ignored otherwise
	// (silent degrade). ReasoningBudget caps thinking tokens when > 0.
	Reasoning       *bool `json:"reasoning,omitempty"`
	ReasoningBudget *int  `json:"reasoning_budget,omitempty"`
}

// completionResponse is the subset of the /completion result this adapter
// reads (ai/llama.cpp.md:586). In streaming mode each SSE data line decodes
// into this same shape with Content holding the next token chunk and Stop
// marking the terminal frame.
type completionResponse struct {
	Content   string `json:"content"`
	Stop      bool   `json:"stop"`
	Reasoning string `json:"reasoning_content"`
}

// toTemplateMessages flattens generic messages into the chat shape the
// template endpoint expects, concatenating each message's text blocks. Tool
// results are rendered as text so the model sees them in the rebuilt prompt;
// the authoritative tool-loop bookkeeping lives in ai.Conversation.
func toTemplateMessages(msgs []ai.Message) []templateMessage {
	out := make([]templateMessage, 0, len(msgs))
	for _, m := range msgs {
		var b strings.Builder
		for _, blk := range m.Content {
			switch blk.Kind {
			case ai.BlockText:
				b.WriteString(blk.Text)
			case ai.BlockToolResult:
				if blk.ToolResult != nil {
					b.Write(blk.ToolResult.Content)
				}
			}
		}
		out = append(out, templateMessage{Role: string(m.Role), Content: b.String()})
	}
	return out
}

// buildCompletion maps generic messages and per-turn options into a
// completionRequest. It renders the prompt via /apply-template, applies the
// thinking control, attaches a tool grammar when exactly the tool-eliciting
// conditions hold, and pins the id_slot from the checkpoint-boundary slot key
// ([conversationKey], §4.8). The prompt-rendering round-trip is the caller's
// responsibility (it needs the client); buildCompletion only fills the
// non-prompt fields.
func (p *chatModel) buildCompletion(prompt string, opts ai.Options, stream bool) completionRequest {
	req := completionRequest{
		Prompt: prompt,
		Stream: stream,
		Model:  p.model,
		IDSlot: slotID(conversationKey(opts)),
	}

	mapThinking(&req, opts, p.reasoning)
	mapTools(&req, opts)
	return req
}

// mapThinking translates the generic thinking control into the reasoning
// request fields. ThinkingOn forces reasoning on, ThinkingOff forces it off,
// and ThinkingDefault follows the provider's WithReasoning default. On a model
// without reasoning support the server ignores the fields (silent degrade).
func mapThinking(req *completionRequest, opts ai.Options, defaultOn bool) {
	on := defaultOn
	switch opts.Thinking {
	case ai.ThinkingOn:
		on = true
	case ai.ThinkingOff:
		on = false
	}
	req.Reasoning = &on
}

// mapTools attaches a JSON-schema grammar that constrains generation to a tool
// call. llama-server's /completion cannot hard-force a *choice* among tools,
// so this adapter does NOT implement [ai.ToolForcer]; ToolRequired degrades to
// a surfaced caveat (handled by ai.Conversation). A grammar is attached only
// when tools are offered and the turn is not ToolNone; with multiple tools the
// schema admits any of them via oneOf. The model's resulting JSON is parsed
// into a tool call by parseToolCall.
func mapTools(req *completionRequest, opts ai.Options) {
	if opts.Tools == ai.ToolNone || len(opts.ToolDefs) == 0 {
		return
	}
	req.JSONSchema = toolGrammarSchema(opts.ToolDefs)
}

// toolGrammarSchema builds a JSON schema that matches a single tool call:
// {"name": <tool name>, "arguments": <that tool's argument schema>}. With more
// than one tool offered the schema is a oneOf over each tool's call shape.
func toolGrammarSchema(tools []ai.Tool) json.RawMessage {
	one := func(t ai.Tool) map[string]any {
		var argSchema any
		if len(t.Schema) > 0 {
			_ = json.Unmarshal(t.Schema, &argSchema)
		}
		return map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name":      map[string]any{"const": t.Name},
				"arguments": argSchema,
			},
			"required": []string{"name", "arguments"},
		}
	}
	if len(tools) == 1 {
		raw, _ := json.Marshal(one(tools[0]))
		return raw
	}
	variants := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		variants = append(variants, one(t))
	}
	raw, _ := json.Marshal(map[string]any{"oneOf": variants})
	return raw
}

// toolEnvelope is the JSON shape the grammar constrains the model to emit; it
// is parsed back into an [ai.ToolCall].
type toolEnvelope struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// parseToolCall attempts to read a grammar-constrained tool call out of the
// model's text. It returns ok=false when the text is not a tool envelope (a
// plain text answer), in which case the caller treats the content as assistant
// text. The call id is derived deterministically from the name and arguments
// so a streamed and a blocking parse of the same content agree.
func parseToolCall(content string, tools []ai.Tool) (ai.ToolCall, bool) {
	if len(tools) == 0 {
		return ai.ToolCall{}, false
	}
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "{") {
		return ai.ToolCall{}, false
	}
	var env toolEnvelope
	if err := json.Unmarshal([]byte(trimmed), &env); err != nil || env.Name == "" {
		return ai.ToolCall{}, false
	}
	if !knownTool(env.Name, tools) {
		return ai.ToolCall{}, false
	}
	args := env.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	return ai.ToolCall{
		ID:        toolCallID(env.Name, args),
		Name:      env.Name,
		Arguments: args,
	}, true
}

// knownTool reports whether name matches one of the offered tools.
func knownTool(name string, tools []ai.Tool) bool {
	for _, t := range tools {
		if t.Name == name {
			return true
		}
	}
	return false
}

// toolCallID derives a stable call id from the tool name and arguments so that
// blocking and streaming code produce identical ids for identical content.
func toolCallID(name string, args json.RawMessage) string {
	h := sha256.Sum256(append([]byte(name+"\x00"), args...))
	return "call_" + hex.EncodeToString(h[:8])
}

// fromCompletion maps a blocking /completion response into an [ai.Message],
// splitting a grammar-constrained tool call out of the content when present.
func fromCompletion(resp completionResponse, tools []ai.Tool) ai.Message {
	out := ai.Message{Role: ai.RoleAssistant}
	if resp.Reasoning != "" {
		out.Thinking = resp.Reasoning
	}
	if call, ok := parseToolCall(resp.Content, tools); ok {
		out.ToolCalls = append(out.ToolCalls, call)
		return out
	}
	if resp.Content != "" {
		out.Content = append(out.Content, ai.ContentBlock{Kind: ai.BlockText, Text: resp.Content})
	}
	return out
}

// conversationKey returns the deterministic key used to pin a slot ([slotID])
// and name slot-cache files ([slotFilename]). The [ai.ChatModel] interface does
// NOT carry a conversation id, so the key is derived solely from the active
// checkpoint boundary index reported by opts.CacheAnchor() — it is a
// boundary key, not a conversation identity. A consequence is that two
// distinct conversations whose turns sit at the same checkpoint-boundary index
// produce the same key and therefore collide on the same slot; that is
// acceptable because slots are a pure latency optimization and local history is
// authoritative, so a collision is only a cache miss, never wrong content
// (§4.8). Absent an anchor the key is empty, which pins slot 0.
func conversationKey(opts ai.Options) string {
	if idx, ok := opts.CacheAnchor(); ok {
		return "anchor" + strconv.Itoa(idx)
	}
	return ""
}
