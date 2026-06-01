package ai

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"sync"
)

// Conversation owns the running history and named checkpoints for one
// dialogue, drives the automatic tool-execution loop, and persists itself to a
// [Store]. It is created with [NewConversation] or rehydrated with
// [LoadConversation].
//
// A single Conversation instance is NOT safe for concurrent mutation: an
// internal mutex guards short in-memory edits and an inFlight flag gives
// span exclusivity, so a second concurrent [Conversation.Send] or
// [Conversation.Stream], or a mutator such as [Conversation.Restore] during a
// live span, returns [ErrSpanInFlight] rather than interleaving. The mutex is
// never held across a provider round-trip, so [Conversation.Messages] and
// [Conversation.Checkpoint] still return promptly while a tool-loop is in
// flight. Distinct Conversations are independent and may run in parallel.
type Conversation struct {
	id           string
	family       string
	provider     ChatModel
	store        Store
	maxToolIters int

	mu          sync.Mutex
	msgs        []Message
	checkpoints map[string]int  // name -> message count at checkpoint
	tools       map[string]Tool // name -> bound tool
	toolOrder   []string        // registration order, for stable ToolDefs
	inFlight    bool
}

// FamilyProvider is an optional interface a [ChatModel] may implement to
// declare its provider family (for example "claude"). The family is recorded
// when a conversation is persisted and validated on reload to prevent
// reusing a persisted conversation across incompatible backends
// ([ErrProviderMismatch]). A chat model that does not implement it is recorded
// under the empty family, which matches any chat model on reload.
type FamilyProvider interface {
	// Family returns the stable provider-family identifier.
	Family() string
}

func familyOf(p ChatModel) string {
	if fp, ok := p.(FamilyProvider); ok {
		return fp.Family()
	}
	return ""
}

// NewConversation starts a fresh conversation backed by p and persisted to
// store. Pass [WithID] to choose the persistence key, [WithMaxToolIterations]
// to bound the tool-loop, otherwise a random id and [DefaultMaxToolIterations]
// are used.
func NewConversation(p ChatModel, store Store, opts ...ConvOption) (*Conversation, error) {
	if p == nil {
		return nil, fmt.Errorf("ai: NewConversation requires a chat model")
	}
	if store == nil {
		return nil, fmt.Errorf("ai: NewConversation requires a store")
	}
	o := resolveConvOptions(opts)
	id := o.id
	if id == "" {
		id = randomID()
	}
	c := &Conversation{
		id:           id,
		family:       familyOf(p),
		provider:     p,
		store:        store,
		maxToolIters: o.maxToolIters,
		checkpoints:  map[string]int{},
		tools:        map[string]Tool{},
	}
	return c, nil
}

// persistedConversation is the on-disk shape of a conversation. Tool invokers
// (Go funcs) are not serializable, so only the descriptor fields survive; they
// are re-bound on load via a [ToolRegistry].
type persistedConversation struct {
	ID          string          `json:"id"`
	Family      string          `json:"family"`
	Messages    []Message       `json:"messages"`
	Checkpoints map[string]int  `json:"checkpoints"`
	Tools       []persistedTool `json:"tools"`
}

type persistedTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
}

// LoadConversation rehydrates a conversation persisted under id. Tool invokers
// are not persisted, so the caller supplies reg (a [ToolRegistry]) to re-bind
// each persisted tool's Go func by name; an unmatched name leaves the tool
// unbound until [Conversation.RegisterToolFunc] supplies it. A re-bound func
// whose reflected schema differs from the persisted schema returns
// [ErrToolSchemaMismatch]; reloading against a provider of a different family
// returns [ErrProviderMismatch].
func LoadConversation(p ChatModel, store Store, id string, reg *ToolRegistry) (*Conversation, error) {
	if p == nil || store == nil {
		return nil, fmt.Errorf("ai: LoadConversation requires a chat model and store")
	}
	data, err := store.LoadConversation(id)
	if err != nil {
		return nil, err
	}
	var pc persistedConversation
	if err := json.Unmarshal(data, &pc); err != nil {
		return nil, fmt.Errorf("ai: decoding conversation %q: %w", id, err)
	}
	if fam := familyOf(p); pc.Family != "" && fam != "" && pc.Family != fam {
		return nil, fmt.Errorf("%w: stored %q, provider %q", ErrProviderMismatch, pc.Family, fam)
	}

	c := &Conversation{
		id:           pc.ID,
		family:       pc.Family,
		provider:     p,
		store:        store,
		maxToolIters: DefaultMaxToolIterations,
		// Copy the decoded structures rather than alias them, matching the
		// defensive copying done by persist/Messages so the live conversation
		// never shares backing storage with the decode buffer.
		msgs:        append([]Message(nil), pc.Messages...),
		checkpoints: map[string]int{},
		tools:       map[string]Tool{},
	}
	maps.Copy(c.checkpoints, pc.Checkpoints)
	for _, pt := range pc.Tools {
		c.toolOrder = append(c.toolOrder, pt.Name)
		tool, err := reg.bind(pt.Name, pt.Schema)
		if err != nil {
			if err == ErrToolUnbound {
				// Leave a descriptor-only (unbound) tool; it errors only if
				// the loop actually needs to invoke it.
				c.tools[pt.Name] = Tool{Name: pt.Name, Description: pt.Description, Schema: pt.Schema}
				continue
			}
			return nil, err // ErrToolSchemaMismatch
		}
		c.tools[pt.Name] = tool
	}
	return c, nil
}

// ID returns the conversation's persistence key.
func (c *Conversation) ID() string { return c.id }

// Messages returns a copy of the current history. It acquires the internal
// lock only briefly and returns promptly even while a Send or Stream tool-loop
// is in flight (the lock is never held across a provider round-trip).
func (c *Conversation) Messages() []Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Message, len(c.msgs))
	copy(out, c.msgs)
	return out
}

// RegisterToolFunc reflects fn into a tool descriptor, binds its invoker, and
// registers it on the conversation. If a descriptor with the same name already
// exists (for example a placeholder created by [LoadConversation] before
// re-binding), the freshly reflected schema must match the existing one or
// [ErrToolSchemaMismatch] is returned. It returns [ErrSpanInFlight] if a span
// is currently active.
func (c *Conversation) RegisterToolFunc(fn any, desc string) error {
	tool, err := ReflectTool(fn, desc)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inFlight {
		return ErrSpanInFlight
	}
	if existing, ok := c.tools[tool.Name]; ok {
		if !schemaEqual(existing.Schema, tool.Schema) {
			return ErrToolSchemaMismatch
		}
	} else {
		c.toolOrder = append(c.toolOrder, tool.Name)
	}
	c.tools[tool.Name] = tool
	return nil
}

// toolDefs returns the registered tool descriptors in registration order.
// Callers must hold c.mu.
func (c *Conversation) toolDefs() []Tool {
	defs := make([]Tool, 0, len(c.toolOrder))
	for _, name := range c.toolOrder {
		defs = append(defs, c.tools[name])
	}
	return defs
}

// Checkpoint records the current end of history under name. A later
// [Conversation.Restore] truncates history back to this point. It returns
// [ErrSpanInFlight] if a span is in flight, and persists the conversation.
func (c *Conversation) Checkpoint(name string) error {
	c.mu.Lock()
	if c.inFlight {
		c.mu.Unlock()
		return ErrSpanInFlight
	}
	c.checkpoints[name] = len(c.msgs)
	c.mu.Unlock()
	return c.persist()
}

// Restore truncates history back to the point recorded by Checkpoint(name) and
// branches from there: any checkpoint recorded after that point is orphaned
// (removed from the live set, and dropped from the store on the next persist).
// A name always refers to a point on the current linear history. It returns
// [ErrSpanInFlight] if a span is in flight.
func (c *Conversation) Restore(name string) error {
	c.mu.Lock()
	if c.inFlight {
		c.mu.Unlock()
		return ErrSpanInFlight
	}
	at, ok := c.checkpoints[name]
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("ai: unknown checkpoint %q", name)
	}
	c.msgs = c.msgs[:at]
	for n, idx := range c.checkpoints {
		if idx > at {
			delete(c.checkpoints, n)
		}
	}
	c.mu.Unlock()
	return c.persist()
}

// persist serializes the current state to the store. It snapshots under the
// lock then writes outside it.
func (c *Conversation) persist() error {
	c.mu.Lock()
	pc := persistedConversation{
		ID:          c.id,
		Family:      c.family,
		Messages:    append([]Message(nil), c.msgs...),
		Checkpoints: map[string]int{},
		Tools:       make([]persistedTool, 0, len(c.toolOrder)),
	}
	maps.Copy(pc.Checkpoints, c.checkpoints)
	for _, name := range c.toolOrder {
		t := c.tools[name]
		pc.Tools = append(pc.Tools, persistedTool{Name: t.Name, Description: t.Description, Schema: t.Schema})
	}
	c.mu.Unlock()

	data, err := json.Marshal(pc)
	if err != nil {
		return fmt.Errorf("ai: encoding conversation: %w", err)
	}
	return c.store.SaveConversation(c.id, data)
}

// beginSpan marks a span in flight, returning [ErrSpanInFlight] if one already
// is. endSpan clears it.
func (c *Conversation) beginSpan() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inFlight {
		return ErrSpanInFlight
	}
	c.inFlight = true
	return nil
}

func (c *Conversation) endSpan() {
	c.mu.Lock()
	c.inFlight = false
	c.mu.Unlock()
}

func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Send appends a user turn carrying text, runs the synchronous auto tool-loop,
// and returns the final assistant message. The loop invokes the provider,
// executes any requested tool calls against their bound Go funcs, appends the
// results, and re-invokes until a turn requests no tool or the
// [WithMaxToolIterations] bound is hit. When [ToolRequired] was requested but
// the provider cannot force a tool call and none was produced, the returned
// message carries a [ToolRequiredNotHonored] caveat (it never errors for that
// reason). A second concurrent span returns [ErrSpanInFlight].
func (c *Conversation) Send(ctx context.Context, text string, opts ...PromptOption) (Message, error) {
	if err := c.beginSpan(); err != nil {
		return Message{}, err
	}
	defer c.endSpan()

	o := c.buildOptions(opts)
	c.appendUser(text)

	forceable := c.canForceTools()
	var last Message
	for iters := 0; iters < c.maxToolIters; iters++ {
		// Honor cancellation between tool turns, mirroring the streaming path; a
		// provider or invoker that ignores ctx must not buy extra turns.
		if err := ctx.Err(); err != nil {
			return Message{}, err
		}
		msg, err := c.provider.Chat(ctx, c.snapshot(), o)
		if err != nil {
			return Message{}, err
		}
		c.appendMessage(msg)
		last = msg
		if len(msg.ToolCalls) == 0 {
			if o.Tools == ToolRequired && !forceable {
				last = c.addCaveat(ToolRequiredNotHonored)
			}
			if err := c.persist(); err != nil {
				return Message{}, err
			}
			return last, nil
		}
		results, err := c.runToolCalls(ctx, msg.ToolCalls)
		if err != nil {
			return Message{}, err
		}
		c.appendMessage(results)
	}
	// Iteration bound hit: surface the last assistant message without error.
	if err := c.persist(); err != nil {
		return Message{}, err
	}
	return last, nil
}

// buildOptions resolves PromptOptions and populates the unexported cacheAnchor
// from the active checkpoint boundary (the highest checkpoint index <= current
// history length). Callers must NOT hold c.mu.
func (c *Conversation) buildOptions(opts []PromptOption) Options {
	var o Options
	for _, opt := range opts {
		opt(&o)
	}
	c.mu.Lock()
	o.ToolDefs = c.toolDefs()
	anchor := -1
	for _, idx := range c.checkpoints {
		if idx <= len(c.msgs) && idx > anchor {
			anchor = idx
		}
	}
	c.mu.Unlock()
	o.setCacheAnchor(anchor)
	return o
}

// canForceTools performs the single ToolForcer assertion site for a span.
func (c *Conversation) canForceTools() bool {
	if f, ok := c.provider.(ToolForcer); ok {
		return f.CanForceTools()
	}
	return false
}

func (c *Conversation) appendUser(text string) {
	c.mu.Lock()
	c.msgs = append(c.msgs, UserText(text))
	c.mu.Unlock()
}

func (c *Conversation) appendMessage(m Message) {
	c.mu.Lock()
	c.msgs = append(c.msgs, m)
	c.mu.Unlock()
}

// addCaveat appends a caveat to the last message in history and returns the
// updated copy.
func (c *Conversation) addCaveat(caveat string) Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.msgs) == 0 {
		return Message{}
	}
	i := len(c.msgs) - 1
	c.msgs[i].Caveats = append(c.msgs[i].Caveats, caveat)
	return c.msgs[i]
}

func (c *Conversation) snapshot() []Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Message, len(c.msgs))
	copy(out, c.msgs)
	return out
}

// runToolCalls executes each requested call against its bound invoker and
// returns a single RoleTool message carrying the results. An unbound invoker
// is [ErrToolUnbound]; an invoker that itself errors is reported back to the
// model as an error tool-result rather than failing the span.
func (c *Conversation) runToolCalls(ctx context.Context, calls []ToolCall) (Message, error) {
	msg := Message{Role: RoleTool}
	for _, call := range calls {
		if err := ctx.Err(); err != nil {
			return Message{}, err
		}
		c.mu.Lock()
		tool, ok := c.tools[call.Name]
		c.mu.Unlock()
		if !ok || !tool.Bound() {
			return Message{}, fmt.Errorf("%w: %q", ErrToolUnbound, call.Name)
		}
		out, err := tool.Invoke(ctx, call.Arguments)
		res := ToolResult{CallID: call.ID, Name: call.Name}
		if err != nil {
			res.IsError = true
			res.Content = mustJSON(err.Error())
		} else {
			res.Content = out
		}
		msg.Content = append(msg.Content, ContentBlock{Kind: BlockToolResult, ToolResult: &res})
	}
	return msg, nil
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`"<unencodable error>"`)
	}
	return b
}
