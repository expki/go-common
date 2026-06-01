//go:build integration

package openai

import (
	"context"
	"os"
	"testing"

	"github.com/expki/go-common/ai"
)

// integrationKey returns a live OpenAI key from AI_TEST_OPENAI_KEY, skipping
// the test when it is unset so the default suite stays hermetic.
func integrationKey(t *testing.T) string {
	t.Helper()
	key := os.Getenv("AI_TEST_OPENAI_KEY")
	if key == "" {
		t.Skip("AI_TEST_OPENAI_KEY not set; skipping live OpenAI integration test")
	}
	return key
}

// integrationProvider constructs a live chat model from AI_TEST_OPENAI_KEY.
func integrationProvider(t *testing.T, opts ...Option) ai.ChatModel {
	return NewChat(integrationKey(t), opts...)
}

func TestIntegration_Chat(t *testing.T) {
	p := integrationProvider(t)
	msg, err := p.Chat(context.Background(),
		[]ai.Message{ai.UserText("Reply with the single word: pong")}, ai.Options{})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if msg.Text() == "" {
		t.Errorf("empty reply: %+v", msg)
	}
}

func TestIntegration_Stream(t *testing.T) {
	p := integrationProvider(t)
	s := p.Stream(context.Background(),
		[]ai.Message{ai.UserText("Count: 1 2 3")}, ai.Options{})
	var text string
	for ev := range s.All() {
		if ev.Kind == ai.EventText {
			text += ev.Text
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Err: %v", err)
	}
	if text == "" {
		t.Error("expected streamed text")
	}
}

func TestIntegration_Embed(t *testing.T) {
	e := NewEmbed(integrationKey(t), WithModel("text-embedding-3-small"))
	got, err := e.Embed(context.Background(), []string{"hello", "world"})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if len(got) != 2 || len(got[0]) == 0 {
		t.Errorf("Embed = %d vectors", len(got))
	}
}

func TestIntegration_ThinkingAndTools(t *testing.T) {
	p := integrationProvider(t, WithModel("o3"))
	tool, err := ai.ReflectTool(sampleTool, "echoes the query back")
	if err != nil {
		t.Fatalf("ReflectTool: %v", err)
	}
	msg, err := p.Chat(context.Background(),
		[]ai.Message{ai.UserText("Call sampletool with query=ping")},
		ai.Options{Thinking: ai.ThinkingOn, Tools: ai.ToolRequired, ToolDefs: []ai.Tool{tool}})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if len(msg.ToolCalls) == 0 {
		t.Errorf("expected a forced tool call, got %+v", msg)
	}
}
