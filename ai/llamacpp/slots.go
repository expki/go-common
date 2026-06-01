package llamacpp

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/url"
)

// slotAction is one of the three KV-cache slot verbs llama-server exposes on
// POST /slots/{id_slot}?action=… (ai/llama.cpp.md:1071,1091,1111).
type slotAction string

const (
	slotSave    slotAction = "save"
	slotRestore slotAction = "restore"
	slotErase   slotAction = "erase"
)

// numSlots is the assumed slot count used to map a slot key onto a pinned
// id_slot by hash. It does not need to match the server's actual --parallel
// count: an over- or under-estimate only changes which slots collide, and a
// collision is a CACHE MISS, never wrong content (§4.8). A modest default
// spreads distinct slot keys across the common case of a few parallel slots.
const numSlots = 8

// slotID pins a deterministic id_slot for a slot key by hashing it into
// [0, numSlots). The key comes from [conversationKey] and is derived from the
// active checkpoint boundary (opts.CacheAnchor), NOT from a conversation id —
// the ChatModel interface does not carry one. Slots are shared and ephemeral on
// the server, so two distinct conversations whose turns share the same
// checkpoint-boundary index hash to the same key and thus the same slot; per
// §4.8 that collision merely evicts the other conversation's warm KV (a cache
// miss on its next turn) and never yields wrong restore content, because local
// history is authoritative. An empty key (no anchor, e.g. a direct Provider
// call) pins slot 0.
func slotID(key string) int {
	if key == "" {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() % numSlots)
}

// slotFilename builds a deterministic slot-cache file name from the slot key
// and the active checkpoint boundary (the message index read from
// [ai.Options.CacheAnchor]). The key itself is boundary-derived (see
// [conversationKey]), not a conversation id. A branchy restore to a different
// boundary selects a different file, so caching tracks the live branch (§4.7);
// two conversations sharing a boundary index produce the same file name, which
// is an accepted cache collision (§4.8), never wrong content. The name is
// sanitized so it is a safe single path component under --slot-save-path.
func slotFilename(key string, boundary int) string {
	return fmt.Sprintf("aicache_%s_%d.bin", sanitize(key), boundary)
}

// sanitize replaces any byte outside [A-Za-z0-9_-] with '_' so the result is a
// safe single filename component regardless of the key's contents.
func sanitize(s string) string {
	if s == "" {
		return "anon"
	}
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			out[i] = c
		default:
			out[i] = '_'
		}
	}
	return string(out)
}

// slotRequest is the JSON body for save/restore (erase needs none of these).
type slotRequest struct {
	Filename string `json:"filename,omitempty"`
}

// doSlot performs one best-effort slot operation against the path-param
// endpoint POST /slots/{id}?action=… (ai/llama.cpp.md:1071). It is a PURE
// latency optimization: every failure mode — slots disabled, --slot-save-path
// unset on the server, a non-2xx response, a slot reassigned to another
// request — is SWALLOWED and returns nil. A stale or colliding slot is just a
// cache miss on the next /completion, never wrong content, because the local
// conversation history is always authoritative (§4.8). When slotSavePath is
// empty the operation is skipped entirely.
func (p *chatModel) doSlot(ctx context.Context, action slotAction, id int, filename string) {
	if p.slotSavePath == "" {
		return
	}
	path := fmt.Sprintf("/slots/%d?action=%s", id, url.QueryEscape(string(action)))
	var body any
	if action != slotErase {
		body = slotRequest{Filename: filename}
	} else {
		body = struct{}{}
	}
	// Errors are intentionally ignored: slots never affect correctness.
	_ = p.client.postJSON(ctx, path, body, nil)
}
