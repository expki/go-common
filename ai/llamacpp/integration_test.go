//go:build integration

package llamacpp_test

import (
	"context"
	"os"
	"testing"

	"github.com/expki/go-common/ai"
	"github.com/expki/go-common/ai/llamacpp"
)

// liveURL reads the llama-server base URL for live integration tests and skips
// the test when it is unset, keeping the default `go test` run hermetic.
func liveURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("AI_TEST_LLAMACPP_URL")
	if url == "" {
		t.Skip("AI_TEST_LLAMACPP_URL not set; skipping live llama.cpp integration test")
	}
	return url
}

func TestLive_Chat(t *testing.T) {
	p := llamacpp.NewChat(liveURL(t))
	msg, err := p.Chat(context.Background(), []ai.Message{ai.UserText("Say hello in one word.")}, ai.Options{})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if msg.Text() == "" && len(msg.ToolCalls) == 0 {
		t.Errorf("expected non-empty completion, got %+v", msg)
	}
}

func TestLive_Stream(t *testing.T) {
	p := llamacpp.NewChat(liveURL(t))
	s := p.Stream(context.Background(), []ai.Message{ai.UserText("Count to three.")}, ai.Options{})
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

func TestLive_Embed(t *testing.T) {
	e := llamacpp.NewEmbed(liveURL(t))
	got, err := e.Embed(context.Background(), []string{"hello world"})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if len(got) != 1 || len(got[0]) == 0 {
		t.Errorf("Embed = %v, want one non-empty vector", got)
	}
}
