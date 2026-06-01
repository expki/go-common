package claude

import (
	"net/http"

	"github.com/anthropics/anthropic-sdk-go"
)

// Option configures a Claude [ai.ChatModel] at construction. Pass options to
// [NewChat].
type Option func(*options)

type options struct {
	model     anthropic.Model
	maxTokens int64
	baseURL   string
	apiKey    string
	http      *http.Client
}

// defaultModel is the model used when none is supplied; it is the most capable
// Claude model.
const defaultModel = anthropic.ModelClaudeOpus4_8

// defaultMaxTokens is the response cap used when [WithMaxTokens] is not set.
const defaultMaxTokens int64 = 16000

// WithModel sets the Anthropic model id (for example anthropic.ModelClaudeOpus4_8
// or a bare string). The default is the most capable Opus model.
func WithModel(model string) Option {
	return func(o *options) { o.model = anthropic.Model(model) }
}

// WithMaxTokens sets the maximum number of tokens to generate per turn. The
// default is 16000.
func WithMaxTokens(n int64) Option {
	return func(o *options) {
		if n > 0 {
			o.maxTokens = n
		}
	}
}

// WithBaseURL overrides the Anthropic API base URL, for proxies or test
// servers (used together with [WithHTTPClient] in tests).
func WithBaseURL(url string) Option {
	return func(o *options) { o.baseURL = url }
}

// WithHTTPClient injects a custom *http.Client, used to point unit tests at an
// httptest.Server. When nil the SDK default client is used.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) { o.http = c }
}

func resolve(apiKey string, opts []Option) options {
	o := options{
		model:     defaultModel,
		maxTokens: defaultMaxTokens,
		apiKey:    apiKey,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
