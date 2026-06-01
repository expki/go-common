package llamacpp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// client is the low-level transport to a single llama-server. It is a thin
// wrapper over net/http that knows the base URL, the optional bearer token, and
// the handful of llama-server endpoints this adapter uses: /completion (chat,
// blocking or SSE), /apply-template (render chat messages into a prompt),
// /embedding, and the /slots/{id} cache operations. It carries no generic-AI
// concepts; mapping lives in map.go and slots.go.
type client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// newClient builds a client for baseURL. A trailing slash on baseURL is
// trimmed so endpoint paths join cleanly. When httpc is nil the
// [http.DefaultClient] is used.
func newClient(baseURL, apiKey string, httpc *http.Client) *client {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    httpc,
	}
}

// newRequest builds a POST request to path with a JSON body, attaching the
// Content-Type and (when configured) Authorization headers.
func (c *client) newRequest(ctx context.Context, path string, body any) (*http.Request, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	return req, nil
}

// postJSON sends body to path and decodes a JSON response into out. A non-2xx
// status is returned as an error carrying the response body for diagnostics.
func (c *client) postJSON(ctx context.Context, path string, body, out any) error {
	req, err := c.newRequest(ctx, path, body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c.statusError(path, resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// postStream sends body with "stream":true semantics already set by the caller
// and returns the live response for SSE consumption. The caller owns closing
// the response body. A non-2xx status is drained, closed, and returned as an
// error.
func (c *client) postStream(ctx context.Context, path string, body any) (*http.Response, error) {
	req, err := c.newRequest(ctx, path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := c.statusError(path, resp)
		resp.Body.Close()
		return nil, err
	}
	return resp, nil
}

// statusError reads the response body (best effort) and formats a non-2xx
// status into an error. It does not close the body; callers manage that.
func (c *client) statusError(path string, resp *http.Response) error {
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("llamacpp: %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(snippet)))
}
