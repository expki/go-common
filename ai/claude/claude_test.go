package claude

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/expki/go-common/ai"
)

// capturedRequest records the JSON body the SDK sent so tests can assert the
// generic→native mapping.
type capturedRequest struct {
	body map[string]any
}

// newTestProvider stands up an httptest.Server returning respBody for any
// /v1/messages call and wires a provider at it. The returned *capturedRequest
// holds the last decoded request body.
func newTestProvider(t *testing.T, respBody string, opts ...Option) (ai.ChatModel, *capturedRequest) {
	t.Helper()
	cap := &capturedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &cap.body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)

	all := append([]Option{WithBaseURL(srv.URL), WithHTTPClient(srv.Client())}, opts...)
	return NewChat("test-key", all...), cap
}

const textResponse = `{
  "id": "msg_1",
  "type": "message",
  "role": "assistant",
  "model": "claude-opus-4-8",
  "content": [{"type": "text", "text": "hello from claude"}],
  "stop_reason": "end_turn",
  "usage": {"input_tokens": 10, "output_tokens": 5}
}`

func TestChat_TextRoundTrip(t *testing.T) {
	p, _ := newTestProvider(t, textResponse)
	msg, err := p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if msg.Role != ai.RoleAssistant || msg.Text() != "hello from claude" {
		t.Errorf("got %+v", msg)
	}
}

func TestChat_ModelAndMaxTokens(t *testing.T) {
	p, cap := newTestProvider(t, textResponse, WithModel("claude-sonnet-4-6"), WithMaxTokens(1234))
	if _, err := p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{}); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if cap.body["model"] != "claude-sonnet-4-6" {
		t.Errorf("model = %v", cap.body["model"])
	}
	if cap.body["max_tokens"].(float64) != 1234 {
		t.Errorf("max_tokens = %v", cap.body["max_tokens"])
	}
}

func TestMap_ThinkingOn(t *testing.T) {
	p, cap := newTestProvider(t, textResponse)
	_, _ = p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{Thinking: ai.ThinkingOn})
	thinking, ok := cap.body["thinking"].(map[string]any)
	if !ok || thinking["type"] != "adaptive" {
		t.Errorf("thinking = %v, want adaptive", cap.body["thinking"])
	}
}

func TestMap_ThinkingOff(t *testing.T) {
	p, cap := newTestProvider(t, textResponse)
	_, _ = p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{Thinking: ai.ThinkingOff})
	thinking, ok := cap.body["thinking"].(map[string]any)
	if !ok || thinking["type"] != "disabled" {
		t.Errorf("thinking = %v, want disabled", cap.body["thinking"])
	}
}

func TestMap_ThinkingDefaultOmitted(t *testing.T) {
	p, cap := newTestProvider(t, textResponse)
	_, _ = p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{Thinking: ai.ThinkingDefault})
	if _, present := cap.body["thinking"]; present {
		t.Errorf("thinking should be omitted by default, got %v", cap.body["thinking"])
	}
}

// TestMap_ThinkingSignatureReplayedFirst verifies a signed reasoning trace is
// re-emitted as the first block of the assistant turn, which Anthropic requires
// for a thinking+tools tool-loop to be accepted.
func TestMap_ThinkingSignatureReplayedFirst(t *testing.T) {
	m := ai.Message{
		Role:              ai.RoleAssistant,
		Thinking:          "let me think",
		ThinkingSignature: "sig-abc",
		Content:           []ai.ContentBlock{{Kind: ai.BlockText, Text: "the answer"}},
	}
	got := toAnthropicMessage(m, false)
	if len(got.Content) == 0 {
		t.Fatal("no content blocks produced")
	}
	first := got.Content[0]
	if first.OfThinking == nil {
		t.Fatalf("first block is not a thinking block: %+v", first)
	}
	if first.OfThinking.Signature != "sig-abc" || first.OfThinking.Thinking != "let me think" {
		t.Errorf("thinking block = %+v, want signature/thinking preserved", first.OfThinking)
	}
}

// TestMap_ThinkingUnsignedNotReplayed verifies a reasoning trace with no
// signature is dropped rather than replayed (an unsigned thinking block would
// be rejected by the API).
func TestMap_ThinkingUnsignedNotReplayed(t *testing.T) {
	m := ai.Message{
		Role:     ai.RoleAssistant,
		Thinking: "unsigned reasoning",
		Content:  []ai.ContentBlock{{Kind: ai.BlockText, Text: "answer"}},
	}
	got := toAnthropicMessage(m, false)
	if len(got.Content) > 0 && got.Content[0].OfThinking != nil {
		t.Error("unsigned thinking must not be replayed as a thinking block")
	}
}

// TestMap_ThinkingSignatureCaptured verifies the signature on a response
// thinking block is preserved onto the generic message for later replay.
func TestMap_ThinkingSignatureCaptured(t *testing.T) {
	var resp anthropic.Message
	const raw = `{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-6",` +
		`"content":[{"type":"thinking","thinking":"deep thought","signature":"sig-xyz"},` +
		`{"type":"text","text":"hello"}],"stop_reason":"end_turn"}`
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out := fromAnthropicMessage(&resp)
	if out.Thinking != "deep thought" {
		t.Errorf("thinking = %q", out.Thinking)
	}
	if out.ThinkingSignature != "sig-xyz" {
		t.Errorf("signature = %q, want sig-xyz", out.ThinkingSignature)
	}
}

func TestMap_ToolChoice(t *testing.T) {
	tool, err := ai.ReflectTool(sampleTool, "a sample tool")
	if err != nil {
		t.Fatalf("ReflectTool: %v", err)
	}
	tests := []struct {
		name     string
		mode     ai.ToolMode
		wantType string
		wantTool bool
	}{
		{"optional", ai.ToolOptional, "auto", true},
		{"required", ai.ToolRequired, "any", true},
		{"none", ai.ToolNone, "none", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, cap := newTestProvider(t, textResponse)
			_, _ = p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{
				Tools:    tt.mode,
				ToolDefs: []ai.Tool{tool},
			})
			tc, _ := cap.body["tool_choice"].(map[string]any)
			if tc == nil || tc["type"] != tt.wantType {
				t.Errorf("tool_choice = %v, want type %q", cap.body["tool_choice"], tt.wantType)
			}
			_, hasTools := cap.body["tools"]
			if hasTools != tt.wantTool {
				t.Errorf("tools present = %v, want %v", hasTools, tt.wantTool)
			}
		})
	}
}

func TestMap_ToolSchemaSerialized(t *testing.T) {
	tool, _ := ai.ReflectTool(sampleTool, "a sample tool")
	p, cap := newTestProvider(t, textResponse)
	_, _ = p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{
		Tools:    ai.ToolOptional,
		ToolDefs: []ai.Tool{tool},
	})
	tools, ok := cap.body["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("tools = %v", cap.body["tools"])
	}
	first := tools[0].(map[string]any)
	if first["name"] != "sampletool" {
		t.Errorf("tool name = %v", first["name"])
	}
	if first["description"] != "a sample tool" {
		t.Errorf("tool description = %v", first["description"])
	}
	schema, _ := first["input_schema"].(map[string]any)
	props, _ := schema["properties"].(map[string]any)
	if _, ok := props["query"]; !ok {
		t.Errorf("input_schema properties = %v", schema["properties"])
	}
}

func TestMap_CacheAnchorReadViaAccessor(t *testing.T) {
	// With no anchor (a plain Options{}), map.go must read opts.CacheAnchor()
	// and place no cache_control breakpoint.
	p, cap := newTestProvider(t, textResponse)
	_, _ = p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{})
	if hasCacheControl(cap.body) {
		t.Errorf("did not expect cache_control with no anchor: %v", cap.body["messages"])
	}

	// With an anchor set by a real Conversation (CacheAnchor has no setter), a
	// checkpoint boundary places exactly one cache_control breakpoint. This
	// proves the mapping reads the anchor via opts.CacheAnchor(), not a field.
	convProvider, convCap := newTestProvider(t, textResponse)
	conv, err := ai.NewConversation(convProvider, ai.OpenMemoryStore())
	if err != nil {
		t.Fatalf("NewConversation: %v", err)
	}
	cap = convCap
	if _, err := conv.Send(context.Background(), "first"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := conv.Checkpoint("cp"); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	// Anchor now at message index 2 (len after first turn). The next turn
	// carries a cache_control breakpoint on the message at that boundary.
	if _, err := conv.Send(context.Background(), "second"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !hasCacheControl(cap.body) {
		t.Errorf("expected cache_control once an anchor is set: %v", cap.body["messages"])
	}
}

func TestProvider_CapabilityProbes(t *testing.T) {
	p := NewChat("k")
	f, ok := p.(ai.ToolForcer)
	if !ok || !f.CanForceTools() {
		t.Errorf("Claude should force tools: ok=%v", ok)
	}
	fam, ok := p.(ai.FamilyProvider)
	if !ok || fam.Family() != "claude" {
		t.Errorf("family = %v (ok=%v)", fam, ok)
	}
}

func TestStream_TextAndToolCall(t *testing.T) {
	p, _ := newTestProvider(t, "", withSSE(sseSequence))
	s := p.Stream(context.Background(), []ai.Message{ai.UserText("weather?")}, ai.Options{})

	var text string
	var sawToolCall bool
	for ev := range s.All() {
		switch ev.Kind {
		case ai.EventText:
			text += ev.Text
		case ai.EventToolCall:
			sawToolCall = true
			if ev.ToolCall.Name != "get_weather" {
				t.Errorf("tool name = %q", ev.ToolCall.Name)
			}
			if !strings.Contains(string(ev.ToolCall.Arguments), "Paris") {
				t.Errorf("tool args = %s", ev.ToolCall.Arguments)
			}
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Err: %v", err)
	}
	if text != "Let me check." {
		t.Errorf("text = %q", text)
	}
	if !sawToolCall {
		t.Error("expected a tool call event")
	}
}

// --- helpers ---

type sampleArgs struct {
	Query string `json:"query" desc:"the search query"`
}

func sampleTool(in sampleArgs) string { return in.Query }

// hasCacheControl reports whether any message content block in the request
// body carries a cache_control breakpoint.
func hasCacheControl(body map[string]any) bool {
	msgs, _ := body["messages"].([]any)
	for _, m := range msgs {
		mm, _ := m.(map[string]any)
		content, _ := mm["content"].([]any)
		for _, c := range content {
			cc, _ := c.(map[string]any)
			if _, ok := cc["cache_control"]; ok {
				return true
			}
		}
	}
	return false
}

// withSSE returns an Option that swaps in an HTTP client whose responses are
// the given Server-Sent Events payload, for streaming tests.
func withSSE(payload string) Option {
	return func(o *options) {
		o.http = &http.Client{Transport: sseTransport{payload: payload}}
	}
}

type sseTransport struct{ payload string }

func (t sseTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(t.payload)),
		Request:    r,
	}
	return resp, nil
}

// sseSequence is a minimal Anthropic streaming sequence: a text delta then a
// completed tool_use block.
const sseSequence = `event: message_start
data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4-8","content":[],"stop_reason":null,"usage":{"input_tokens":1,"output_tokens":1}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me check."}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"get_weather","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"city\": \"Paris\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":1}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":10}}

event: message_stop
data: {"type":"message_stop"}

`
