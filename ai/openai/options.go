package openai

import (
	"net/http"

	"github.com/openai/openai-go/shared"
)

// Option configures an OpenAI [ai.ChatModel] or [ai.Embedder] at construction.
// Pass options to [NewChat] or [NewEmbed].
type Option func(*options)

type options struct {
	model   shared.ChatModel
	baseURL string
	apiKey  string
	http    *http.Client
}

// defaultModel is the chat model used by [NewChat] when [WithModel] is not set;
// it is a capable general-purpose model.
const defaultModel shared.ChatModel = shared.ChatModelGPT4o

// defaultEmbedModel is the embeddings model used by [NewEmbed] when [WithModel]
// is not set.
const defaultEmbedModel shared.ChatModel = "text-embedding-3-small"

// WithModel sets the OpenAI model id. For [NewChat] it is the chat model (for
// example "gpt-4o", "o3", or "gpt-4o-mini"); for [NewEmbed] it is the
// embeddings model (for example "text-embedding-3-small" or
// "text-embedding-3-large"). Each constructor applies its own default when this
// is unset.
func WithModel(model string) Option {
	return func(o *options) {
		if model != "" {
			o.model = shared.ChatModel(model)
		}
	}
}

// WithBaseURL overrides the OpenAI API base URL, for proxies, compatible
// endpoints, or test servers (used together with [WithHTTPClient] in tests).
func WithBaseURL(url string) Option {
	return func(o *options) { o.baseURL = url }
}

// WithHTTPClient injects a custom *http.Client, used to point unit tests at an
// httptest.Server. When nil the SDK default client is used.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) { o.http = c }
}

// resolve applies opts over an apiKey-seeded zero options value. The model
// field is left unset so each constructor ([NewChat], [NewEmbed]) can apply its
// own default.
func resolve(apiKey string, opts []Option) options {
	o := options{apiKey: apiKey}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
