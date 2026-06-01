# ai

One interface for four LLM backends. You write your app against `ai` once; the only line that names a backend is the constructor. Swap `claude.NewChat` for `openai.NewChat`, `ollama.NewChat`, or `llamacpp.NewChat` and everything else — chat, streaming, the automatic tool loop, checkpoints, the durable store — runs unchanged.

```go
chat := claude.NewChat(apiKey)                // or openai.NewChat / ollama.NewChat / llamacpp.NewChat
conv, _ := ai.NewConversation(chat, ai.OpenMemoryStore())
msg, _ := conv.Send(ctx, "Summarize this in one line: ...")
fmt.Println(msg.Text())
```

- `ai.NewConversation(chatModel, store, opts...)` starts a stateful dialogue.
- `conv.Send` / `conv.Stream` run one turn — including a bounded, automatic tool loop.
- `conv.RegisterToolFunc` turns a Go function into a tool (schema derived by reflection).
- `conv.Checkpoint` / `conv.Restore` rewind history; the store makes it survive a restart.
- Embeddings are a separate capability: construct an `ai.Embedder` with a provider's `NewEmbed` and call `emb.Embed(ctx, inputs)`.

The `ai` package itself imports no SDK. Each provider subpackage is a thin adapter that translates the generic verbs into native calls; the hard parts — the tool loop, checkpoint/restore, bbolt persistence — live in `ai` and every backend inherits them.

## Install

```sh
go get github.com/expki/go-common/ai
```

The store is bbolt, pulled through a `replace` directive. Go only honors `replace` from the main module, so repeat it in your own `go.mod` or the build won't compile:

```
replace go.etcd.io/bbolt => github.com/expki/bbolt v1.5.0-rc.0.0.20260531215528-dccadea585ba
```

The provider SDKs (`anthropic-sdk-go`, `openai-go`, `ollama/api`) come in transitively; `llamacpp` is a plain HTTP client with no SDK.

## Providers

Each `NewChat` returns an `ai.ChatModel`. From there your code is identical.

```go
chat := claude.NewChat(anthropicKey,
    claude.WithModel("claude-opus-4-8"),
    claude.WithMaxTokens(16000))

chat := openai.NewChat(openaiKey,
    openai.WithModel("gpt-4o"))

chat := ollama.NewChat("http://localhost:11434",
    ollama.WithModel("llama3.2"))

chat := llamacpp.NewChat("http://localhost:8080",
    llamacpp.WithSlotSavePath("/var/lib/llama/slots"))
```

`claude.NewChat` and `openai.NewChat` take an API key; `ollama.NewChat` and `llamacpp.NewChat` take a base URL. Every provider also accepts `WithHTTPClient` for tests and proxies.

## Embeddings

Embeddings are a distinct capability, constructed separately from chat with each provider's `NewEmbed`, returning an `ai.Embedder`. `WithModel` selects the embedding model (each provider has a sensible default).

```go
emb := openai.NewEmbed(openaiKey, openai.WithModel("text-embedding-3-small"))
vecs, _ := emb.Embed(ctx, []string{"hello", "world"})

emb := ollama.NewEmbed("http://localhost:11434", ollama.WithModel("nomic-embed-text"))
emb := llamacpp.NewEmbed("http://localhost:8080")
```

Claude has **no** native embeddings endpoint, so the `claude` package exposes no `NewEmbed`. To embed alongside Claude chat, construct a separate embedder from another provider:

```go
chat := claude.NewChat(anthropicKey)
emb := openai.NewEmbed(openaiKey, openai.WithModel("text-embedding-3-small"))
vecs, _ := emb.Embed(ctx, []string{"hello", "world"})
```

## Controls

Two per-prompt controls, passed to `Send`/`Stream`. Each maps to the backend's native mechanism and degrades silently where the backend can't honor it.

```go
conv.Send(ctx, "think hard about this", ai.Thinking(ai.ThinkingOn))   // ThinkingOn / ThinkingOff / ThinkingDefault
conv.Send(ctx, "look it up", ai.Tools(ai.ToolRequired))               // ToolNone / ToolOptional / ToolRequired
```

`ToolRequired` is the one control that does **not** silently lie: a backend that can't force a tool call completes the turn with a `ai.ToolRequiredNotHonored` caveat on the message rather than pretending it forced one. Claude and OpenAI force tools; Ollama and llama.cpp surface the caveat.

## Tools

Register a Go function and the loop calls it for you — decodes the arguments, runs the function, feeds the result back, repeats until the model stops (bounded by `WithMaxToolIterations`, default 8).

```go
type weatherArgs struct {
    City string `json:"city" desc:"the city to look up"`
}
func getWeather(ctx context.Context, in weatherArgs) (string, error) { /* ... */ }

conv.RegisterToolFunc(getWeather, "Get the current weather for a city")
conv.Send(ctx, "What's the weather in Paris?")   // the loop calls getWeather automatically
```

The JSON schema is derived from the argument struct (`json` tags for names, `desc` tags for descriptions, `omitempty` marks a field optional).

## Streaming

`conv.Stream` returns a single stream that spans the whole tool loop — text, thinking, and one `EventToolCall` per tool turn, ending in one `EventDone`.

```go
s := conv.Stream(ctx, "Walk me through it")
for ev := range s.All() {
    switch ev.Kind {
    case ai.EventText:
        fmt.Print(ev.Text)
    case ai.EventToolCall:
        fmt.Printf("\n[calling %s]\n", ev.ToolCall.Name)
    }
}
if err := s.Err(); err != nil { /* handle */ }
```

Breaking out of the range early tears the stream down cleanly; cancellation flows through the `ctx` you passed in.

## Checkpoints and persistence

`Checkpoint` names the current end of history; `Restore` rewinds to it and branches (checkpoints made after that point are dropped). Checkpoint/rewind is a **hard local contract** — it operates only on the conversation's own history and is bit-correct on every provider. Provider-side caching (Claude `cache_control`, llama.cpp KV slots, Ollama KV reuse, OpenAI prefix cache) is anchored to the active checkpoint but is strictly **best-effort**: a cache miss only costs latency, never correctness.

```go
store, _ := ai.OpenStore("/data/chats.db")          // durable bbolt; OpenMemoryStore() for tests
conv, _ := ai.NewConversation(chat, store, ai.WithID("chat-42"))

conv.Send(ctx, "first question")
conv.Checkpoint("after-intro")
conv.Send(ctx, "follow-up")
conv.Restore("after-intro")                          // history rewinds; "follow-up" is gone
```

Reload across a restart with `LoadConversation`. Tool functions aren't serializable, so only `{name, schema, description}` persist — rebind the Go functions by name through a `ToolRegistry`:

```go
reg := ai.NewToolRegistry()
reg.Add(getWeather, "Get the current weather for a city")
conv, err := ai.LoadConversation(chat, store, "chat-42", reg)
```

A reload against a different provider family returns `ai.ErrProviderMismatch`; a tool whose reflected schema changed since it was saved returns `ai.ErrToolSchemaMismatch`.

## A single Conversation is not concurrent

One `Conversation` runs one span at a time. A second concurrent `Send`/`Stream`, or a `Restore` during a live span, returns `ai.ErrSpanInFlight` rather than interleaving. `Messages()` and `Checkpoint()` stay responsive mid-span (the internal lock is never held across a provider round-trip). Distinct conversations are independent.

## Testing

The default test suite is hermetic — `ai` runs against a fake provider, and each adapter runs against mocked HTTP, so no network or credentials are needed.

```sh
go test ./ai/...
go test -race -run 'Conversation|Tool|Store|Stream|Concurrent' ./ai/...
```

Live tests live behind a build tag and skip unless their endpoint env var is set:

```sh
AI_TEST_ANTHROPIC_KEY=...  \
AI_TEST_OPENAI_KEY=...      \
AI_TEST_OLLAMA_URL=http://localhost:11434 \
AI_TEST_LLAMACPP_URL=http://localhost:8080 \
go test -tags=integration ./ai/...
```

## Building

```sh
go build ./ai/...
```
