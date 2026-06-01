package openai

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

// capturedRequest records the JSON body the SDK sent so tests can assert the
// generic→native mapping.
type capturedRequest struct {
	body map[string]any
}

// newTestProvider stands up an httptest.Server returning respBody for any
// /chat/completions call and wires a provider at it. The returned
// *capturedRequest holds the last decoded request body.
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
  "id": "chatcmpl_1",
  "object": "chat.completion",
  "created": 1,
  "model": "gpt-4o",
  "choices": [
    {
      "index": 0,
      "finish_reason": "stop",
      "logprobs": null,
      "message": {"role": "assistant", "content": "hello from openai", "refusal": null}
    }
  ]
}`

const toolCallResponse = `{
  "id": "chatcmpl_2",
  "object": "chat.completion",
  "created": 1,
  "model": "gpt-4o",
  "choices": [
    {
      "index": 0,
      "finish_reason": "tool_calls",
      "logprobs": null,
      "message": {
        "role": "assistant",
        "content": "",
        "refusal": null,
        "tool_calls": [
          {"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\": \"Paris\"}"}}
        ]
      }
    }
  ]
}`

func TestChat_TextRoundTrip(t *testing.T) {
	p, _ := newTestProvider(t, textResponse)
	msg, err := p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if msg.Role != ai.RoleAssistant || msg.Text() != "hello from openai" {
		t.Errorf("got %+v", msg)
	}
}

func TestChat_Model(t *testing.T) {
	p, cap := newTestProvider(t, textResponse, WithModel("o3"))
	if _, err := p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{}); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if cap.body["model"] != "o3" {
		t.Errorf("model = %v", cap.body["model"])
	}
}

func TestChat_ToolCallParsed(t *testing.T) {
	p, _ := newTestProvider(t, toolCallResponse)
	msg, err := p.Chat(context.Background(), []ai.Message{ai.UserText("weather?")}, ai.Options{})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if len(msg.ToolCalls) != 1 {
		t.Fatalf("tool calls = %+v", msg.ToolCalls)
	}
	tc := msg.ToolCalls[0]
	if tc.ID != "call_1" || tc.Name != "get_weather" {
		t.Errorf("tool call = %+v", tc)
	}
	if !strings.Contains(string(tc.Arguments), "Paris") {
		t.Errorf("arguments = %s", tc.Arguments)
	}
}

func TestMap_ThinkingOn(t *testing.T) {
	p, cap := newTestProvider(t, textResponse, WithModel("o3"))
	_, _ = p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{Thinking: ai.ThinkingOn})
	if cap.body["reasoning_effort"] != "high" {
		t.Errorf("reasoning_effort = %v, want high", cap.body["reasoning_effort"])
	}
}

func TestMap_ThinkingOff(t *testing.T) {
	p, cap := newTestProvider(t, textResponse, WithModel("o3"))
	_, _ = p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{Thinking: ai.ThinkingOff})
	if cap.body["reasoning_effort"] != "low" {
		t.Errorf("reasoning_effort = %v, want low", cap.body["reasoning_effort"])
	}
}

// TestMap_ThinkingOnNonReasoningModelOmitted guards the silent-degradation
// contract: on a non-reasoning model (the default gpt-4o) the reasoning_effort
// field must NOT be sent even for ThinkingOn, because the real API rejects it
// with a 400 there rather than ignoring it.
func TestMap_ThinkingOnNonReasoningModelOmitted(t *testing.T) {
	for _, mode := range []ai.ThinkingMode{ai.ThinkingOn, ai.ThinkingOff} {
		p, cap := newTestProvider(t, textResponse) // default model: gpt-4o
		_, _ = p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{Thinking: mode})
		if v, present := cap.body["reasoning_effort"]; present {
			t.Errorf("mode %v: reasoning_effort must be omitted on a non-reasoning model, got %v", mode, v)
		}
	}
}

func TestMap_ThinkingDefaultOmitted(t *testing.T) {
	p, cap := newTestProvider(t, textResponse)
	_, _ = p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{Thinking: ai.ThinkingDefault})
	if _, present := cap.body["reasoning_effort"]; present {
		t.Errorf("reasoning_effort should be omitted by default, got %v", cap.body["reasoning_effort"])
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
		want     string
		wantTool bool
	}{
		{"optional", ai.ToolOptional, "auto", true},
		{"required", ai.ToolRequired, "required", true},
		{"none", ai.ToolNone, "none", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, cap := newTestProvider(t, textResponse)
			_, _ = p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{
				Tools:    tt.mode,
				ToolDefs: []ai.Tool{tool},
			})
			if cap.body["tool_choice"] != tt.want {
				t.Errorf("tool_choice = %v, want %q", cap.body["tool_choice"], tt.want)
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
	props, _ := params["properties"].(map[string]any)
	if _, ok := props["query"]; !ok {
		t.Errorf("parameters properties = %v", params["properties"])
	}
}

func TestMap_SystemAndAssistantRoles(t *testing.T) {
	p, cap := newTestProvider(t, textResponse)
	msgs := []ai.Message{
		{Role: ai.RoleSystem, Content: []ai.ContentBlock{{Kind: ai.BlockText, Text: "be brief"}}},
		ai.UserText("hi"),
		ai.AssistantText("hello"),
		ai.UserText("again"),
	}
	_, _ = p.Chat(context.Background(), msgs, ai.Options{})
	got, _ := cap.body["messages"].([]any)
	if len(got) != 4 {
		t.Fatalf("messages = %v", cap.body["messages"])
	}
	roles := make([]string, len(got))
	for i, m := range got {
		roles[i], _ = m.(map[string]any)["role"].(string)
	}
	want := []string{"system", "user", "assistant", "user"}
	for i := range want {
		if roles[i] != want[i] {
			t.Errorf("role[%d] = %q, want %q (all: %v)", i, roles[i], want[i], roles)
		}
	}
}

func TestMap_ToolResultRoundTrips(t *testing.T) {
	p, cap := newTestProvider(t, textResponse)
	msgs := []ai.Message{
		ai.UserText("weather?"),
		{Role: ai.RoleAssistant, ToolCalls: []ai.ToolCall{
			{ID: "call_1", Name: "get_weather", Arguments: json.RawMessage(`{"city":"Paris"}`)},
		}},
		{Role: ai.RoleTool, Content: []ai.ContentBlock{
			{Kind: ai.BlockToolResult, ToolResult: &ai.ToolResult{CallID: "call_1", Name: "get_weather", Content: json.RawMessage(`"sunny"`)}},
		}},
	}
	_, _ = p.Chat(context.Background(), msgs, ai.Options{})
	got, _ := cap.body["messages"].([]any)
	if len(got) != 3 {
		t.Fatalf("messages = %v", cap.body["messages"])
	}
	// assistant turn carries tool_calls
	asst, _ := got[1].(map[string]any)
	tcs, _ := asst["tool_calls"].([]any)
	if len(tcs) != 1 {
		t.Fatalf("assistant tool_calls = %v", asst["tool_calls"])
	}
	// tool turn maps to a tool message keyed by the call id
	tool, _ := got[2].(map[string]any)
	if tool["role"] != "tool" || tool["tool_call_id"] != "call_1" {
		t.Errorf("tool message = %v", tool)
	}
}

func TestEmbed_RoundTrip(t *testing.T) {
	const embedResp = `{
      "object": "list",
      "model": "text-embedding-3-small",
      "data": [
        {"object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3]},
        {"object": "embedding", "index": 1, "embedding": [0.4, 0.5, 0.6]}
      ],
      "usage": {"prompt_tokens": 2, "total_tokens": 2}
    }`
	var cap capturedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &cap.body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, embedResp)
	}))
	t.Cleanup(srv.Close)
	e := NewEmbed("k", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithModel("text-embedding-3-large"))

	got, err := e.Embed(context.Background(), []string{"a", "b"})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if len(got) != 2 || len(got[0]) != 3 || got[1][0] != 0.4 {
		t.Errorf("Embed = %v", got)
	}
	if cap.body["model"] != "text-embedding-3-large" {
		t.Errorf("embed model = %v", cap.body["model"])
	}
}

func TestEmbed_EmptyInput(t *testing.T) {
	e := NewEmbed("k")
	got, err := e.Embed(context.Background(), nil)
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("Embed = %v, want non-nil empty", got)
	}
}

func TestProvider_CapabilityProbes(t *testing.T) {
	p := NewChat("k")
	f, ok := p.(ai.ToolForcer)
	if !ok || !f.CanForceTools() {
		t.Errorf("OpenAI should force tools: ok=%v", ok)
	}
	fam, ok := p.(ai.FamilyProvider)
	if !ok || fam.Family() != "openai" {
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

// sseSequence is a minimal OpenAI chat completion stream: a text delta then a
// tool call delivered across an id/name chunk and an arguments chunk.
const sseSequence = `data: {"id":"chatcmpl_1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":"Let me check."},"finish_reason":null}]}

data: {"id":"chatcmpl_1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]},"finish_reason":null}]}

data: {"id":"chatcmpl_1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\": \"Paris\"}"}}]},"finish_reason":null}]}

data: {"id":"chatcmpl_1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}

data: [DONE]

`
