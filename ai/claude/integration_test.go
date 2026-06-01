//go:build integration

package claude_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/expki/go-common/ai"
	"github.com/expki/go-common/ai/claude"
)

// requireKey skips the test unless a live Anthropic key is configured.
func requireKey(t *testing.T) string {
	t.Helper()
	key := os.Getenv("AI_TEST_ANTHROPIC_KEY")
	if key == "" {
		t.Skip("AI_TEST_ANTHROPIC_KEY not set; skipping live Claude integration test")
	}
	return key
}

func TestIntegration_Chat(t *testing.T) {
	p := claude.NewChat(requireKey(t), claude.WithMaxTokens(256))
	conv, err := ai.NewConversation(p, ai.OpenMemoryStore())
	if err != nil {
		t.Fatalf("NewConversation: %v", err)
	}
	msg, err := conv.Send(context.Background(), "Reply with exactly the word: pong")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(strings.ToLower(msg.Text()), "pong") {
		t.Errorf("reply did not contain pong: %q", msg.Text())
	}
}

func TestIntegration_Stream(t *testing.T) {
	p := claude.NewChat(requireKey(t), claude.WithMaxTokens(256))
	conv, err := ai.NewConversation(p, ai.OpenMemoryStore())
	if err != nil {
		t.Fatalf("NewConversation: %v", err)
	}
	s := conv.Stream(context.Background(), "Count: one two three")
	var text string
	for ev := range s.All() {
		if ev.Kind == ai.EventText {
			text += ev.Text
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("stream Err: %v", err)
	}
	if text == "" {
		t.Error("expected streamed text")
	}
}

func TestIntegration_Thinking(t *testing.T) {
	p := claude.NewChat(requireKey(t), claude.WithMaxTokens(2048))
	conv, err := ai.NewConversation(p, ai.OpenMemoryStore())
	if err != nil {
		t.Fatalf("NewConversation: %v", err)
	}
	msg, err := conv.Send(context.Background(),
		"How many r's are in strawberry? Reason carefully.", ai.Thinking(ai.ThinkingOn))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if msg.Text() == "" {
		t.Error("expected an answer")
	}
}

func TestIntegration_Tools(t *testing.T) {
	p := claude.NewChat(requireKey(t), claude.WithMaxTokens(1024))
	conv, err := ai.NewConversation(p, ai.OpenMemoryStore())
	if err != nil {
		t.Fatalf("NewConversation: %v", err)
	}
	if err := conv.RegisterToolFunc(addNumbers, "Add two integers and return the sum"); err != nil {
		t.Fatalf("RegisterToolFunc: %v", err)
	}
	msg, err := conv.Send(context.Background(),
		"Use the addnumbers tool to add 2 and 3, then tell me the result.",
		ai.Tools(ai.ToolRequired))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(msg.Text(), "5") {
		t.Errorf("expected the tool-augmented answer to mention 5: %q", msg.Text())
	}
}

type addArgs struct {
	A int `json:"a"`
	B int `json:"b"`
}

func addNumbers(in addArgs) int { return in.A + in.B }
