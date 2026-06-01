package ollama

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/expki/go-common/ai"
)

// capture records the decoded JSON request body and the path the SDK hit so
// tests can assert the generic to native mapping.
type capture struct {
	path string
	body map[string]any
}

// newTestServer stands up an httptest.Server that records the request and
// returns respBody for any call, returning its base URL, its client, and the
// capture.
func newTestServer(t *testing.T, respBody string) (string, *http.Client, *capture) {
	t.Helper()
	cap := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &cap.body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, srv.Client(), cap
}

// newTestProvider wires a chat model at a recording test server.
func newTestProvider(t *testing.T, respBody string, opts ...Option) (ai.ChatModel, *capture) {
	t.Helper()
	url, client, cap := newTestServer(t, respBody)
	all := append([]Option{WithHTTPClient(client)}, opts...)
	return NewChat(url, all...), cap
}

// newTestEmbedder wires an embedder at a recording test server.
func newTestEmbedder(t *testing.T, respBody string, opts ...Option) (ai.Embedder, *capture) {
	t.Helper()
	url, client, cap := newTestServer(t, respBody)
	all := append([]Option{WithHTTPClient(client)}, opts...)
	return NewEmbed(url, all...), cap
}

// textResponse is a single-line (newline-delimited) Ollama chat response.
// /api/chat is read with a line scanner, so fixtures must be one JSON object
// per line, not pretty-printed across lines.
const textResponse = `{"model":"llama3.2","created_at":"2023-12-12T14:13:43.416799Z","message":{"role":"assistant","content":"hello from ollama"},"done":true}`

func TestChat_TextRoundTrip(t *testing.T) {
	p, cap := newTestProvider(t, textResponse)
	msg, err := p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if msg.Role != ai.RoleAssistant || msg.Text() != "hello from ollama" {
		t.Errorf("got %+v", msg)
	}
	if cap.path != "/api/chat" {
		t.Errorf("path = %q, want /api/chat", cap.path)
	}
	if cap.body["stream"] != false {
		t.Errorf("stream = %v, want false for Chat", cap.body["stream"])
	}
}

func TestChat_ModelAndKeepAlive(t *testing.T) {
	p, cap := newTestProvider(t, textResponse, WithModel("qwen2.5:7b"))
	if _, err := p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{}); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if cap.body["model"] != "qwen2.5:7b" {
		t.Errorf("model = %v", cap.body["model"])
	}
}

func TestMap_Messages_TextRolesPreserved(t *testing.T) {
	p, cap := newTestProvider(t, textResponse)
	msgs := []ai.Message{
		{Role: ai.RoleSystem, Content: []ai.ContentBlock{{Kind: ai.BlockText, Text: "be terse"}}},
		ai.UserText("why is the sky blue?"),
	}
	if _, err := p.Chat(context.Background(), msgs, ai.Options{}); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	out, _ := cap.body["messages"].([]any)
	if len(out) != 2 {
		t.Fatalf("messages = %v", cap.body["messages"])
	}
	first := out[0].(map[string]any)
	if first["role"] != "system" || first["content"] != "be terse" {
		t.Errorf("system message = %v", first)
	}
}

func TestMap_ToolResultBecomesToolRoleMessage(t *testing.T) {
	p, cap := newTestProvider(t, textResponse)
	msgs := []ai.Message{
		ai.UserText("weather?"),
		{
			Role: ai.RoleAssistant,
			ToolCalls: []ai.ToolCall{
				{ID: "call_1", Name: "get_weather", Arguments: json.RawMessage(`{"city":"Paris"}`)},
			},
		},
		{
			Role: ai.RoleTool,
			Content: []ai.ContentBlock{{
				Kind:       ai.BlockToolResult,
				ToolResult: &ai.ToolResult{CallID: "call_1", Name: "get_weather", Content: json.RawMessage(`"11C"`)},
			}},
		},
	}
	if _, err := p.Chat(context.Background(), msgs, ai.Options{}); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	out, _ := cap.body["messages"].([]any)
	if len(out) != 3 {
		t.Fatalf("messages = %v", cap.body["messages"])
	}
	// Assistant tool call preserved.
	asst := out[1].(map[string]any)
	calls, _ := asst["tool_calls"].([]any)
	if len(calls) != 1 {
		t.Fatalf("assistant tool_calls = %v", asst)
	}
	fn := calls[0].(map[string]any)["function"].(map[string]any)
	if fn["name"] != "get_weather" {
		t.Errorf("tool call name = %v", fn["name"])
	}
	// Tool result became a tool-role message carrying the tool name.
	tool := out[2].(map[string]any)
	if tool["role"] != "tool" || tool["tool_name"] != "get_weather" {
		t.Errorf("tool message = %v", tool)
	}
}

func TestMap_Thinking(t *testing.T) {
	tests := []struct {
		name    string
		mode    ai.ThinkingMode
		want    any
		present bool
	}{
		{"on", ai.ThinkingOn, true, true},
		{"off", ai.ThinkingOff, false, true},
		{"default", ai.ThinkingDefault, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, cap := newTestProvider(t, textResponse)
			_, _ = p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{Thinking: tt.mode})
			got, present := cap.body["think"]
			if present != tt.present {
				t.Fatalf("think present = %v, want %v (body think=%v)", present, tt.present, got)
			}
			if present && got != tt.want {
				t.Errorf("think = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMap_ToolMode(t *testing.T) {
	tool, err := ai.ReflectTool(sampleTool, "a sample tool")
	if err != nil {
		t.Fatalf("ReflectTool: %v", err)
	}
	tests := []struct {
		name     string
		mode     ai.ToolMode
		wantTool bool
	}{
		{"optional offers tools", ai.ToolOptional, true},
		{"required offers tools", ai.ToolRequired, true},
		{"none omits tools", ai.ToolNone, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, cap := newTestProvider(t, textResponse)
			_, _ = p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{
				Tools:    tt.mode,
				ToolDefs: []ai.Tool{tool},
			})
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
	if first["type"] != "function" {
		t.Errorf("tool type = %v", first["type"])
	}
	fn, _ := first["function"].(map[string]any)
	if fn["name"] != "sampletool" {
		t.Errorf("tool name = %v", fn["name"])
	}
	if fn["description"] != "a sample tool" {
		t.Errorf("tool description = %v", fn["description"])
	}
	params, _ := fn["parameters"].(map[string]any)
	if params["type"] != "object" {
		t.Errorf("parameters type = %v", params["type"])
	}
	props, _ := params["properties"].(map[string]any)
	if _, ok := props["query"]; !ok {
		t.Errorf("parameters properties = %v", params["properties"])
	}
}

func TestChat_ToolCallParsedBack(t *testing.T) {
	const resp = `{"model":"llama3.2","message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"get_weather","arguments":{"city":"Tokyo"}}}]},"done":true,"done_reason":"stop"}`
	p, _ := newTestProvider(t, resp)
	msg, err := p.Chat(context.Background(), []ai.Message{ai.UserText("weather?")}, ai.Options{})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if len(msg.ToolCalls) != 1 {
		t.Fatalf("tool calls = %+v", msg.ToolCalls)
	}
	tc := msg.ToolCalls[0]
	if tc.Name != "get_weather" {
		t.Errorf("tool name = %q", tc.Name)
	}
	if !strings.Contains(string(tc.Arguments), "Tokyo") {
		t.Errorf("tool args = %s", tc.Arguments)
	}
}

func TestEmbed_RoundTrip(t *testing.T) {
	const resp = `{"model":"all-minilm","embeddings":[[0.1,0.2,0.3],[0.4,0.5,0.6]]}`
	e, cap := newTestEmbedder(t, resp, WithModel("all-minilm"))
	got, err := e.Embed(context.Background(), []string{"a", "b"})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if cap.path != "/api/embed" {
		t.Errorf("path = %q, want /api/embed", cap.path)
	}
	if cap.body["model"] != "all-minilm" {
		t.Errorf("embed model = %v", cap.body["model"])
	}
	if len(got) != 2 || len(got[0]) != 3 || got[0][0] != 0.1 {
		t.Errorf("embeddings = %v", got)
	}
}

// TestEmbed_EmptyInputNoCall verifies empty input short-circuits to a non-nil
// zero-length slice without hitting the server (parity with the other adapters).
func TestEmbed_EmptyInputNoCall(t *testing.T) {
	e, cap := newTestEmbedder(t, `{"model":"all-minilm","embeddings":[]}`)
	got, err := e.Embed(context.Background(), nil)
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("Embed = %v, want non-nil empty", got)
	}
	if cap.path != "" {
		t.Errorf("server was hit at %q; empty input must not make a request", cap.path)
	}
}

func TestEmbed_EmptyResultNonNil(t *testing.T) {
	const resp = `{"model":"all-minilm","embeddings":[]}`
	e, _ := newTestEmbedder(t, resp)
	got, err := e.Embed(context.Background(), []string{"a"})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("Embed = %v, want non-nil empty", got)
	}
}

func TestProvider_Capabilities(t *testing.T) {
	p := NewChat("http://localhost:11434")
	// Ollama cannot hard-force a tool call, so it must NOT implement ToolForcer.
	if _, ok := p.(ai.ToolForcer); ok {
		t.Error("Ollama should not implement ai.ToolForcer (cannot hard-force tools)")
	}
	fam, ok := p.(ai.FamilyProvider)
	if !ok || fam.Family() != "ollama" {
		t.Errorf("family = %v (ok=%v)", fam, ok)
	}
}

func TestStream_TextThinkingAndToolCall(t *testing.T) {
	// A streamed sequence of newline-delimited JSON chunks: a thinking delta, a
	// text delta, a chunk carrying a tool call, then the terminal done chunk.
	const chunks = `{"model":"llama3.2","message":{"role":"assistant","thinking":"hmm "}}
{"model":"llama3.2","message":{"role":"assistant","content":"Let me check."}}
{"model":"llama3.2","message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"get_weather","arguments":{"city":"Paris"}}}]}}
{"model":"llama3.2","message":{"role":"assistant","content":""},"done":true,"done_reason":"stop"}
`
	p, _ := newTestProvider(t, chunks)
	s := p.Stream(context.Background(), []ai.Message{ai.UserText("weather?")}, ai.Options{})

	var text, thinking string
	var sawToolCall bool
	for ev := range s.All() {
		switch ev.Kind {
		case ai.EventText:
			text += ev.Text
		case ai.EventThinking:
			thinking += ev.Thinking
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
	if thinking != "hmm " {
		t.Errorf("thinking = %q", thinking)
	}
	if !sawToolCall {
		t.Error("expected a tool call event")
	}
}

func TestStream_EarlyBreakNoLeak(t *testing.T) {
	const chunks = `{"model":"llama3.2","message":{"role":"assistant","content":"one"}}
{"model":"llama3.2","message":{"role":"assistant","content":"two"}}
{"model":"llama3.2","message":{"role":"assistant","content":"three"}}
{"model":"llama3.2","message":{"role":"assistant","content":""},"done":true}
`
	p, _ := newTestProvider(t, chunks)
	s := p.Stream(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{})

	// Break after the first event; the producer goroutine must be torn down
	// deterministically (the range loop's cleanup cancels and drains it).
	for range s.All() {
		break
	}
}

// --- helpers ---

type sampleArgs struct {
	Query string `json:"query" desc:"the search query"`
}

func sampleTool(in sampleArgs) string { return in.Query }
