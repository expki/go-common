package ollama

import (
	"net/http"
	"time"
)

// Option configures an Ollama [ai.ChatModel] or [ai.Embedder] at construction.
// Pass options to [NewChat] or [NewEmbed].
type Option func(*options)

type options struct {
	model     string
	keepAlive *time.Duration
	http      *http.Client
}

// defaultModel is the chat model used by [NewChat] when [WithModel] is not
// supplied. It is a widely available tool-capable Ollama model.
const defaultModel = "llama3.2"

// defaultEmbedModel is the embeddings model used by [NewEmbed] when [WithModel]
// is not supplied.
const defaultEmbedModel = "all-minilm"

// WithModel sets the Ollama model name. For [NewChat] it is the chat model (for
// example "llama3.2" or "qwen2.5:7b"); for [NewEmbed] it is the embeddings
// model (for example "all-minilm" or "nomic-embed-text"). Each constructor
// applies its own default when this is unset.
func WithModel(model string) Option {
	return func(o *options) {
		if model != "" {
			o.model = model
		}
	}
}

// WithKeepAlive sets how long the model stays loaded in memory following a
// request, mapping to Ollama's keep_alive parameter. The zero value leaves the
// field unset so the server applies its own default (5m). A negative duration
// keeps the model loaded indefinitely, matching Ollama's convention.
func WithKeepAlive(d time.Duration) Option {
	return func(o *options) {
		dd := d
		o.keepAlive = &dd
	}
}

// WithHTTPClient injects a custom *http.Client, used to point unit tests at an
// httptest.Server. When nil the http.DefaultClient is used.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) { o.http = c }
}

// resolve applies opts over a zero options value. The model field is left
// unset so each constructor ([NewChat], [NewEmbed]) can apply its own default.
func resolve(opts []Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if o.http == nil {
		o.http = http.DefaultClient
	}
	return o
}
