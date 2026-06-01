//go:build integration

package ollama

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/expki/go-common/ai"
)

// liveURL reads the Ollama server URL from AI_TEST_OLLAMA_URL and skips the
// test when unset, keeping the default `go test` run hermetic.
func liveURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("AI_TEST_OLLAMA_URL")
	if url == "" {
		t.Skip("AI_TEST_OLLAMA_URL not set; skipping live Ollama integration test")
	}
	return url
}

// liveModel returns the chat model to exercise, defaulting to llama3.2.
func liveModel() string {
	if m := os.Getenv("AI_TEST_OLLAMA_MODEL"); m != "" {
		return m
	}
	return "llama3.2"
}

func TestIntegration_Chat(t *testing.T) {
	p := NewChat(liveURL(t), WithModel(liveModel()))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	msg, err := p.Chat(ctx, []ai.Message{ai.UserText("Reply with the single word: pong")}, ai.Options{})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if strings.TrimSpace(msg.Text()) == "" {
		t.Errorf("empty chat response: %+v", msg)
	}
}

func TestIntegration_Stream(t *testing.T) {
	p := NewChat(liveURL(t), WithModel(liveModel()))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	s := p.Stream(ctx, []ai.Message{ai.UserText("Count from 1 to 3.")}, ai.Options{})
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
		t.Error("empty streamed response")
	}
}

func TestIntegration_Embed(t *testing.T) {
	model := os.Getenv("AI_TEST_OLLAMA_EMBED_MODEL")
	if model == "" {
		model = "all-minilm"
	}
	e := NewEmbed(liveURL(t), WithModel(model))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	got, err := e.Embed(ctx, []string{"hello", "world"})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if len(got) != 2 || len(got[0]) == 0 {
		t.Errorf("embeddings = %d vectors, first len %d", len(got), func() int {
			if len(got) > 0 {
				return len(got[0])
			}
			return 0
		}())
	}
}
