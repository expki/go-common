package llamacpp

import "net/http"

// Option configures a llama.cpp [ai.ChatModel] or [ai.Embedder] at
// construction. Pass options to [NewChat] or [NewEmbed].
type Option func(*options)

type options struct {
	model        string
	slotSavePath string
	reasoning    bool
	apiKey       string
	http         *http.Client
}

// WithModel sets the model alias sent on each request's "model" field. A
// single-model llama-server ignores it; it matters only when the server runs
// the multi-model router (see ai/llama.cpp.md). The default is unset, which
// lets the server choose its loaded model.
func WithModel(model string) Option {
	return func(o *options) { o.model = model }
}

// WithSlotSavePath records the server's --slot-save-path directory so that this
// adapter can name deterministic slot-cache files when saving and restoring KV
// slots (see [ai.Conversation] checkpoints). Slot save/restore is a PURE
// latency optimization: when this is unset, slot operations are skipped
// entirely and correctness is unaffected because local history is always
// authoritative.
func WithSlotSavePath(path string) Option {
	return func(o *options) { o.slotSavePath = path }
}

// WithReasoning enables reasoning (thinking) by default for turns that leave
// the thinking mode at [ai.ThinkingDefault]. A per-turn [ai.Thinking] control
// still overrides it. On a model that does not support reasoning the request
// fields are simply ignored by the server (silent degrade).
func WithReasoning(on bool) Option {
	return func(o *options) { o.reasoning = on }
}

// WithHTTPClient injects a custom *http.Client, used to point unit tests at an
// httptest.Server. When nil, [http.DefaultClient] is used.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) { o.http = c }
}

// WithAPIKey sets a bearer token sent as the Authorization header on every
// request, for a llama-server started with --api-key. The default is unset (no
// Authorization header).
func WithAPIKey(key string) Option {
	return func(o *options) { o.apiKey = key }
}

func resolve(opts []Option) options {
	o := options{}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
