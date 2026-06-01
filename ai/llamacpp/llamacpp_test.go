package llamacpp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/expki/go-common/ai"
)

// recordedCall captures one inbound HTTP request so tests can assert the
// generic→native mapping and endpoint shapes.
type recordedCall struct {
	method string
	path   string // URL path only
	rawURL string // path + query (for /slots action assertions)
	body   map[string]any
}

// mockServer is a programmable llama-server stand-in. It records every request
// and dispatches a handler per URL path; unregistered paths return 200 with an
// empty JSON object.
type mockServer struct {
	mu        sync.Mutex
	calls     []recordedCall
	handlers  map[string]http.HandlerFunc
	failSlots bool
	server    *httptest.Server
}

func newMockServer(t *testing.T) *mockServer {
	t.Helper()
	m := &mockServer{handlers: map[string]http.HandlerFunc{}}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)

		m.mu.Lock()
		m.calls = append(m.calls, recordedCall{
			method: r.Method,
			path:   r.URL.Path,
			rawURL: r.URL.RequestURI(),
			body:   body,
		})
		h := m.handlers[r.URL.Path]
		failSlots := m.failSlots
		m.mu.Unlock()

		if h != nil {
			h(w, r)
			return
		}
		// Slot endpoints carry the id in the path (/slots/{id}) so they cannot
		// be matched by exact path. When failSlots is set they return 500 so
		// tests can prove every slot failure is swallowed by the provider.
		if strings.HasPrefix(r.URL.Path, "/slots/") && failSlots {
			http.Error(w, "slots disabled", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{}")
	}))
	t.Cleanup(m.server.Close)
	return m
}

// on registers a handler for an exact URL path.
func (m *mockServer) on(path string, h http.HandlerFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[path] = h
}

// callsFor returns every recorded call whose path matches.
func (m *mockServer) callsFor(path string) []recordedCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []recordedCall
	for _, c := range m.calls {
		if c.path == path {
			out = append(out, c)
		}
	}
	return out
}

// slotCalls returns every recorded call to a /slots/{id} path-param endpoint.
func (m *mockServer) slotCalls() []recordedCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []recordedCall
	for _, c := range m.calls {
		if strings.HasPrefix(c.path, "/slots/") {
			out = append(out, c)
		}
	}
	return out
}

// jsonHandler writes a fixed JSON body with 200.
func jsonHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}
}

// templateHandler answers /apply-template with a fixed rendered prompt.
func templateHandler(prompt string) http.HandlerFunc {
	return jsonHandler(`{"prompt":` + jsonString(prompt) + `}`)
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func newProvider(m *mockServer, opts ...Option) ai.ChatModel {
	all := append([]Option{WithHTTPClient(m.server.Client())}, opts...)
	return NewChat(m.server.URL, all...)
}

func newEmbedder(m *mockServer, opts ...Option) ai.Embedder {
	all := append([]Option{WithHTTPClient(m.server.Client())}, opts...)
	return NewEmbed(m.server.URL, all...)
}

func TestChat_TextRoundTrip(t *testing.T) {
	m := newMockServer(t)
	m.on("/apply-template", templateHandler("USER: hi\nASSISTANT:"))
	m.on("/completion", jsonHandler(`{"content":"hello from llama","stop":true}`))

	p := newProvider(m)
	msg, err := p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if msg.Role != ai.RoleAssistant || msg.Text() != "hello from llama" {
		t.Errorf("got %+v", msg)
	}

	// The rendered prompt must be forwarded to /completion verbatim.
	comp := m.callsFor("/completion")
	if len(comp) != 1 {
		t.Fatalf("want 1 /completion call, got %d", len(comp))
	}
	if comp[0].body["prompt"] != "USER: hi\nASSISTANT:" {
		t.Errorf("prompt = %v", comp[0].body["prompt"])
	}
}

func TestMap_ThinkingControl(t *testing.T) {
	tests := []struct {
		name      string
		mode      ai.ThinkingMode
		defaultOn bool
		want      bool
	}{
		{"on", ai.ThinkingOn, false, true},
		{"off", ai.ThinkingOff, true, false},
		{"default-follows-provider-on", ai.ThinkingDefault, true, true},
		{"default-follows-provider-off", ai.ThinkingDefault, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMockServer(t)
			m.on("/apply-template", templateHandler("p"))
			m.on("/completion", jsonHandler(`{"content":"x","stop":true}`))

			var opts []Option
			if tt.defaultOn {
				opts = append(opts, WithReasoning(true))
			}
			p := newProvider(m, opts...)
			_, _ = p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{Thinking: tt.mode})

			comp := m.callsFor("/completion")
			got, ok := comp[0].body["reasoning"].(bool)
			if !ok || got != tt.want {
				t.Errorf("reasoning = %v (ok=%v), want %v", comp[0].body["reasoning"], ok, tt.want)
			}
		})
	}
}

// TestMap_IDSlotAlwaysSerialized verifies the pinned id_slot is sent even when
// it is 0. With omitempty a 0 slot would be dropped, letting /completion
// auto-pick a slot while save/restore targets slot 0 — silently defeating the
// slot cache for keys that hash to slot 0 (§4.8).
func TestMap_IDSlotAlwaysSerialized(t *testing.T) {
	raw, err := json.Marshal(completionRequest{Prompt: "hi", IDSlot: 0})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"id_slot":0`) {
		t.Errorf("id_slot not serialized when 0: %s", raw)
	}
}

func TestMap_ToolGrammarAttached(t *testing.T) {
	tool, err := ai.ReflectTool(sampleTool, "a sample tool")
	if err != nil {
		t.Fatalf("ReflectTool: %v", err)
	}
	tests := []struct {
		name       string
		mode       ai.ToolMode
		wantSchema bool
	}{
		{"optional", ai.ToolOptional, true},
		{"required", ai.ToolRequired, true},
		{"none", ai.ToolNone, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMockServer(t)
			m.on("/apply-template", templateHandler("p"))
			m.on("/completion", jsonHandler(`{"content":"x","stop":true}`))

			p := newProvider(m)
			_, _ = p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{
				Tools:    tt.mode,
				ToolDefs: []ai.Tool{tool},
			})
			comp := m.callsFor("/completion")
			_, hasSchema := comp[0].body["json_schema"]
			if hasSchema != tt.wantSchema {
				t.Errorf("json_schema present = %v, want %v", hasSchema, tt.wantSchema)
			}
		})
	}
}

func TestChat_ParsesToolCall(t *testing.T) {
	tool, _ := ai.ReflectTool(sampleTool, "a sample tool")
	m := newMockServer(t)
	m.on("/apply-template", templateHandler("p"))
	// The grammar constrains the model to a {name, arguments} envelope.
	m.on("/completion", jsonHandler(`{"content":"{\"name\":\"sampletool\",\"arguments\":{\"query\":\"weather\"}}","stop":true}`))

	p := newProvider(m)
	msg, err := p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{
		Tools:    ai.ToolOptional,
		ToolDefs: []ai.Tool{tool},
	})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if len(msg.ToolCalls) != 1 {
		t.Fatalf("want 1 tool call, got %d (%+v)", len(msg.ToolCalls), msg)
	}
	tc := msg.ToolCalls[0]
	if tc.Name != "sampletool" {
		t.Errorf("tool name = %q", tc.Name)
	}
	if !strings.Contains(string(tc.Arguments), "weather") {
		t.Errorf("tool args = %s", tc.Arguments)
	}
	if tc.ID == "" {
		t.Error("tool call id should be populated")
	}
}

func TestChat_PlainTextNotMistakenForToolCall(t *testing.T) {
	tool, _ := ai.ReflectTool(sampleTool, "a sample tool")
	m := newMockServer(t)
	m.on("/apply-template", templateHandler("p"))
	m.on("/completion", jsonHandler(`{"content":"just a normal answer","stop":true}`))

	p := newProvider(m)
	msg, _ := p.Chat(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{
		Tools:    ai.ToolOptional,
		ToolDefs: []ai.Tool{tool},
	})
	if len(msg.ToolCalls) != 0 {
		t.Errorf("expected no tool call, got %+v", msg.ToolCalls)
	}
	if msg.Text() != "just a normal answer" {
		t.Errorf("text = %q", msg.Text())
	}
}

func TestProvider_DoesNotForceTools(t *testing.T) {
	// llama.cpp cannot hard-force a tool choice, so the provider must NOT
	// implement ai.ToolForcer (ToolRequired degrades to a surfaced caveat).
	p := NewChat("http://localhost:8080")
	if _, ok := p.(ai.ToolForcer); ok {
		t.Error("llamacpp provider should not implement ai.ToolForcer")
	}
	fam, ok := p.(ai.FamilyProvider)
	if !ok || fam.Family() != "llamacpp" {
		t.Errorf("family = %v (ok=%v)", fam, ok)
	}
}

func TestEmbed_Vectors(t *testing.T) {
	m := newMockServer(t)
	// Native /embedding returns an array of objects with nested per-token rows;
	// for pooled models that is a single row (the sentence vector).
	m.on("/embedding", jsonHandler(`{"index":0,"embedding":[[0.1,0.2,0.3]]}`))

	e := newEmbedder(m)
	got, err := e.Embed(context.Background(), []string{"hello"})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if len(got) != 1 || len(got[0]) != 3 || got[0][0] != 0.1 {
		t.Errorf("Embed = %v", got)
	}
}

func TestEmbed_FlatVectorShape(t *testing.T) {
	m := newMockServer(t)
	m.on("/embedding", jsonHandler(`{"index":0,"embedding":[0.5,0.6]}`))

	e := newEmbedder(m)
	got, err := e.Embed(context.Background(), []string{"hello"})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if len(got) != 1 || len(got[0]) != 2 || got[0][1] != 0.6 {
		t.Errorf("Embed = %v", got)
	}
}

func TestEmbed_EmptyInputs(t *testing.T) {
	m := newMockServer(t)
	e := newEmbedder(m)
	got, err := e.Embed(context.Background(), nil)
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("Embed = %v, want non-nil empty", got)
	}
}

func TestStream_TextAndToolCall(t *testing.T) {
	tool, _ := ai.ReflectTool(sampleTool, "a sample tool")
	tests := []struct {
		name         string
		sse          string
		tools        []ai.Tool
		wantText     string
		wantToolCall bool
	}{
		{
			name:     "plain text streamed",
			sse:      "data: {\"content\":\"Hel\"}\n\ndata: {\"content\":\"lo\"}\n\ndata: {\"content\":\"\",\"stop\":true}\n\n",
			tools:    nil,
			wantText: "Hello",
		},
		{
			name:         "tool call buffered and parsed",
			sse:          "data: {\"content\":\"{\\\"name\\\":\\\"samp\"}\n\ndata: {\"content\":\"letool\\\",\\\"arguments\\\":{\\\"query\\\":\\\"x\\\"}}\"}\n\ndata: {\"content\":\"\",\"stop\":true}\n\n",
			tools:        []ai.Tool{tool},
			wantToolCall: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMockServer(t)
			m.on("/apply-template", templateHandler("p"))
			m.on("/completion", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, tt.sse)
			})

			p := newProvider(m)
			s := p.Stream(context.Background(), []ai.Message{ai.UserText("hi")}, ai.Options{
				Tools:    ai.ToolOptional,
				ToolDefs: tt.tools,
			})

			var text string
			var sawTool bool
			for ev := range s.All() {
				switch ev.Kind {
				case ai.EventText:
					text += ev.Text
				case ai.EventToolCall:
					sawTool = true
					if ev.ToolCall.Name != "sampletool" {
						t.Errorf("tool name = %q", ev.ToolCall.Name)
					}
				}
			}
			if err := s.Err(); err != nil {
				t.Fatalf("Err: %v", err)
			}
			if tt.wantText != "" && text != tt.wantText {
				t.Errorf("text = %q, want %q", text, tt.wantText)
			}
			if sawTool != tt.wantToolCall {
				t.Errorf("sawToolCall = %v, want %v", sawTool, tt.wantToolCall)
			}
		})
	}
}

func TestSlots_PathParamEndpointPinnedSlotAndSwallowedFailure(t *testing.T) {
	// With a configured slot-save-path and a Conversation-set anchor, a turn
	// must hit the path-param slot endpoint /slots/{id}?action=… with the
	// pinned id_slot. Every slot call here returns 500, proving the failure is
	// swallowed and the chat still succeeds (slots are pure latency, §4.8).
	m := newMockServer(t)
	m.failSlots = true
	m.on("/apply-template", templateHandler("p"))
	m.on("/completion", jsonHandler(`{"content":"ok","stop":true}`))

	// A real Conversation sets the anchor; CacheAnchor has no app-settable
	// setter, so this is the only way an anchor reaches the provider.
	provider := NewChat(m.server.URL, WithHTTPClient(m.server.Client()), WithSlotSavePath("/tmp/slots"))
	conv, err := ai.NewConversation(provider, ai.OpenMemoryStore(), ai.WithID("conv-xyz"))
	if err != nil {
		t.Fatalf("NewConversation: %v", err)
	}
	if _, err := conv.Send(context.Background(), "first"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := conv.Checkpoint("cp"); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	// This send carries the checkpoint anchor, so slot save/restore fire even
	// though the server fails them.
	if _, err := conv.Send(context.Background(), "second"); err != nil {
		t.Fatalf("Send must succeed despite failing slots: %v", err)
	}

	slotCalls := m.slotCalls()
	if len(slotCalls) == 0 {
		t.Fatal("expected at least one /slots call once an anchor is set")
	}
	for _, c := range slotCalls {
		if !strings.HasPrefix(c.path, "/slots/") {
			t.Errorf("slot path %q is not the path-param form /slots/{id}", c.path)
		}
		if !strings.Contains(c.rawURL, "action=") {
			t.Errorf("slot URL %q missing action query", c.rawURL)
		}
	}
}

func TestSlots_SkippedWithoutSlotSavePath(t *testing.T) {
	// With no --slot-save-path configured, no slot endpoint is ever touched.
	m := newMockServer(t)
	m.on("/apply-template", templateHandler("p"))
	m.on("/completion", jsonHandler(`{"content":"ok","stop":true}`))

	provider := NewChat(m.server.URL, WithHTTPClient(m.server.Client()))
	conv, _ := ai.NewConversation(provider, ai.OpenMemoryStore(), ai.WithID("conv-1"))
	_, _ = conv.Send(context.Background(), "first")
	_ = conv.Checkpoint("cp")
	_, _ = conv.Send(context.Background(), "second")

	if got := m.slotCalls(); len(got) != 0 {
		t.Errorf("expected no slot calls without WithSlotSavePath, got %d", len(got))
	}
}

func TestSlots_LocalHistoryAuthoritative(t *testing.T) {
	// Even when slot restore "succeeds" with arbitrary server-side state, the
	// content the provider sends to /completion is always the prompt rendered
	// from the LOCAL messages it was handed — slots only warm the KV cache and
	// never supply restore content (§4.8).
	m := newMockServer(t)
	m.on("/apply-template", templateHandler("RENDERED-FROM-LOCAL-HISTORY"))
	m.on("/completion", jsonHandler(`{"content":"ok","stop":true}`))
	// A restore that returns a bogus slot must not influence the prompt.
	m.on("/slots/0", jsonHandler(`{"id_slot":0,"filename":"x","n_restored":999}`))

	provider := NewChat(m.server.URL, WithHTTPClient(m.server.Client()), WithSlotSavePath("/tmp/slots"))
	conv, _ := ai.NewConversation(provider, ai.OpenMemoryStore(), ai.WithID("conv-auth"))
	if _, err := conv.Send(context.Background(), "first"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	comp := m.callsFor("/completion")
	if len(comp) == 0 {
		t.Fatal("no /completion call recorded")
	}
	if comp[0].body["prompt"] != "RENDERED-FROM-LOCAL-HISTORY" {
		t.Errorf("prompt = %v, want it rendered from local history", comp[0].body["prompt"])
	}
}

// --- helpers ---

type sampleArgs struct {
	Query string `json:"query" desc:"the search query"`
}

func sampleTool(in sampleArgs) string { return in.Query }
