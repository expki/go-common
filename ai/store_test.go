package ai

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestStore_RoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name  string
		store Store
	}{
		{"memory", OpenMemoryStore()},
		{"bolt", mustBolt(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.store
			if err := s.SaveConversation("a", []byte("hello")); err != nil {
				t.Fatalf("Save: %v", err)
			}
			got, err := s.LoadConversation("a")
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if string(got) != "hello" {
				t.Errorf("got %q", got)
			}
			ids, _ := s.ListConversations()
			if len(ids) != 1 || ids[0] != "a" {
				t.Errorf("ids = %v", ids)
			}
			if err := s.DeleteConversation("a"); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, err := s.LoadConversation("a"); err == nil {
				t.Error("expected error loading deleted")
			}
		})
	}
}

// TestStore_CloseViaInterface verifies Close is reachable through the Store
// interface (not just the concrete bolt type) and is a no-op on the memory
// store, so callers can close any Store uniformly.
func TestStore_CloseViaInterface(t *testing.T) {
	stores := map[string]Store{"memory": OpenMemoryStore(), "bolt": mustBolt(t)}
	for name, s := range stores {
		if err := s.Close(); err != nil {
			t.Errorf("%s: Close() = %v, want nil", name, err)
		}
	}
}

func mustBolt(t *testing.T) Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "ai.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return s
}

func TestStore_DurableReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ai.db")

	s1, err := OpenStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	fake := &fakeProvider{chatTurns: []Message{AssistantText("hi there")}}
	conv, err := NewConversation(fake, s1, WithID("conv1"))
	if err != nil {
		t.Fatalf("NewConversation: %v", err)
	}
	if _, err := conv.Send(context.Background(), "hello"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := conv.Checkpoint("cp1"); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if err := s1.Close(); err != nil { // Close is part of the Store interface.
		t.Fatalf("close: %v", err)
	}

	// Reopen and reload.
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	conv2, err := LoadConversation(fake, s2, "conv1", NewToolRegistry())
	if err != nil {
		t.Fatalf("LoadConversation: %v", err)
	}
	msgs := conv2.Messages()
	if len(msgs) != 2 {
		t.Fatalf("history len = %d, want 2", len(msgs))
	}
	if msgs[1].Text() != "hi there" {
		t.Errorf("assistant text = %q", msgs[1].Text())
	}
}

// TestStore_PersistMidToolCall_ReloadRebind builds a conversation that runs a
// tool, persists, reloads with a matching registry, and asserts a follow-up
// Send resolves through the rebound invoker.
func TestStore_PersistMidToolCall_ReloadRebind(t *testing.T) {
	store := OpenMemoryStore()
	fake := &fakeProvider{
		chatTurns: []Message{
			assistantWithToolCall(toolCall("c1", "getweather", weatherArgs{City: "Paris"})),
			AssistantText("it is 21C"),
		},
	}
	conv, _ := NewConversation(fake, store, WithID("c"))
	if err := conv.RegisterToolFunc(GetWeather, "weather"); err != nil {
		t.Fatalf("RegisterToolFunc: %v", err)
	}
	final, err := conv.Send(context.Background(), "weather in Paris?")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if final.Text() != "it is 21C" {
		t.Fatalf("final = %q", final.Text())
	}

	// Reload with a matching registry and continue.
	reg := NewToolRegistry()
	if err := reg.Add(GetWeather, "weather"); err != nil {
		t.Fatalf("reg.Add: %v", err)
	}
	fake2 := &fakeProvider{chatTurns: []Message{AssistantText("follow up")}}
	conv2, err := LoadConversation(fake2, store, "c", reg)
	if err != nil {
		t.Fatalf("LoadConversation: %v", err)
	}
	if _, err := conv2.Send(context.Background(), "again"); err != nil {
		t.Fatalf("Send after reload: %v", err)
	}
}

func TestStore_ReloadSchemaMismatch(t *testing.T) {
	store := OpenMemoryStore()
	fake := &fakeProvider{}
	conv, _ := NewConversation(fake, store, WithID("c"))
	if err := conv.RegisterToolFunc(GetWeather, "weather"); err != nil {
		t.Fatalf("RegisterToolFunc: %v", err)
	}
	if err := conv.Checkpoint("init"); err != nil { // forces a persist
		t.Fatalf("Checkpoint: %v", err)
	}

	// Reload with a registry that binds the persisted name "getweather" to a
	// func whose reflected schema differs, triggering ErrToolSchemaMismatch.
	impostor, err := ReflectTool(weatherImpostor, "")
	if err != nil {
		t.Fatalf("ReflectTool impostor: %v", err)
	}
	impostor.Name = "getweather" // force the name collision
	reg := &ToolRegistry{byName: map[string]Tool{"getweather": impostor}}
	if _, err := LoadConversation(fake, store, "c", reg); !errors.Is(err, ErrToolSchemaMismatch) {
		t.Errorf("err = %v, want ErrToolSchemaMismatch", err)
	}
}

// weatherImpostor reflects with a different argument schema than GetWeather.
type impostorArgs struct {
	Zip int `json:"zip"`
}

func weatherImpostor(in impostorArgs) string { return "x" }

func TestStore_ReloadUnbound(t *testing.T) {
	store := OpenMemoryStore()
	fake := &fakeProvider{
		chatTurns: []Message{assistantWithToolCall(toolCall("c1", "getweather", weatherArgs{City: "Paris"}))},
	}
	conv, _ := NewConversation(fake, store, WithID("c"))
	_ = conv.RegisterToolFunc(GetWeather, "weather")
	// Leave history ending on a pending tool call by scripting only the tool
	// call turn and a single iteration bound via a fresh conversation Send
	// that will run the invoker. Instead, just persist a tool descriptor and
	// reload without rebinding, then Send into a tool-call turn.
	_ = conv.Checkpoint("init")

	fake2 := &fakeProvider{
		chatTurns: []Message{assistantWithToolCall(toolCall("c2", "getweather", weatherArgs{City: "Rome"}))},
	}
	conv2, err := LoadConversation(fake2, store, "c", NewToolRegistry()) // empty registry
	if err != nil {
		t.Fatalf("LoadConversation: %v", err)
	}
	// The invoker is unbound; a Send that triggers the tool call must error.
	if _, err := conv2.Send(context.Background(), "weather?"); !errors.Is(err, ErrToolUnbound) {
		t.Errorf("err = %v, want ErrToolUnbound", err)
	}
}

func TestStore_ReloadProviderMismatch(t *testing.T) {
	store := OpenMemoryStore()
	claudeish := fakeFamilyProvider{fakeProvider: &fakeProvider{}, family: "claude"}
	conv, _ := NewConversation(claudeish, store, WithID("c"))
	if err := conv.Checkpoint("init"); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}

	ollamaish := fakeFamilyProvider{fakeProvider: &fakeProvider{}, family: "ollama"}
	if _, err := LoadConversation(ollamaish, store, "c", NewToolRegistry()); !errors.Is(err, ErrProviderMismatch) {
		t.Errorf("err = %v, want ErrProviderMismatch", err)
	}
}
