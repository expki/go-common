package ai

import "encoding/json"

// Role identifies who produced a [Message].
type Role string

const (
	// RoleSystem carries instructions that frame the whole dialogue.
	RoleSystem Role = "system"
	// RoleUser is a turn produced by the application or end user.
	RoleUser Role = "user"
	// RoleAssistant is a turn produced by the model.
	RoleAssistant Role = "assistant"
	// RoleTool carries the result of a tool invocation back to the model.
	RoleTool Role = "tool"
)

// BlockKind discriminates the variants of a [ContentBlock].
type BlockKind int

const (
	// BlockText is a plain-text fragment carried in [ContentBlock.Text].
	BlockText BlockKind = iota
	// BlockToolResult is the output of a tool call carried in
	// [ContentBlock.ToolResult].
	BlockToolResult
)

// ContentBlock is one fragment of a [Message]. A message's content is an
// ordered list of blocks so that text and tool results can interleave in a
// single turn the way provider APIs expect.
type ContentBlock struct {
	// Kind discriminates which payload field is populated.
	Kind BlockKind
	// Text holds the fragment when Kind is [BlockText].
	Text string
	// ToolResult holds the output when Kind is [BlockToolResult].
	ToolResult *ToolResult
}

// ToolCall is a request from the model to invoke a registered tool. The
// tool-loop in [Conversation] decodes Arguments, invokes the bound Go func,
// and feeds the result back as a [ToolResult].
type ToolCall struct {
	// ID uniquely identifies this call within a turn so its result can be
	// correlated back to it.
	ID string
	// Name is the reflected tool name (see [ReflectTool]).
	Name string
	// Arguments is the raw JSON object the model produced for the call.
	Arguments json.RawMessage
}

// ToolResult is the output of a single [ToolCall], appended to history and
// sent back to the model on the next turn.
type ToolResult struct {
	// CallID matches the [ToolCall.ID] this result answers.
	CallID string
	// Name is the tool that produced the result.
	Name string
	// Content is the tool's output, JSON-encoded.
	Content json.RawMessage
	// IsError reports whether the tool invocation failed; the content then
	// describes the error.
	IsError bool
}

// Message is one turn of conversation history. It is the unit both the
// [Provider] interface and the bbolt store operate on.
type Message struct {
	// Role identifies who produced the turn.
	Role Role
	// Content is the ordered list of text and tool-result fragments.
	Content []ContentBlock
	// ToolCalls is the set of tool invocations the model requested on this
	// turn; empty on turns that requested none.
	ToolCalls []ToolCall
	// Thinking holds the model's reasoning trace when a thinking mode was
	// active and the provider surfaced it; empty otherwise.
	Thinking string
	// ThinkingSignature holds a provider-issued signature over the reasoning
	// trace, when the provider produces one (Anthropic extended thinking). It
	// must be replayed verbatim on later turns so a thinking+tools tool-loop is
	// accepted; providers that do not sign reasoning leave it empty.
	ThinkingSignature string
	// Caveats carries non-fatal advisories about the turn, such as
	// [ToolRequiredNotHonored]. It is persisted with the message but does not
	// participate in provider-family validation.
	Caveats []string
}

// Text returns the concatenation of every [BlockText] fragment in the
// message, the common case for reading an assistant reply.
func (m Message) Text() string {
	var s string
	for _, b := range m.Content {
		if b.Kind == BlockText {
			s += b.Text
		}
	}
	return s
}

// UserText builds a user [Message] carrying a single text block.
func UserText(text string) Message {
	return Message{Role: RoleUser, Content: []ContentBlock{{Kind: BlockText, Text: text}}}
}

// AssistantText builds an assistant [Message] carrying a single text block.
func AssistantText(text string) Message {
	return Message{Role: RoleAssistant, Content: []ContentBlock{{Kind: BlockText, Text: text}}}
}
