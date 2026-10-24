package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/vigneshwarancs/airlock/internal/jsonwalk"
	"github.com/vigneshwarancs/airlock/internal/rewrite"
	"github.com/vigneshwarancs/airlock/internal/vault"
)

// streamTextKeys are the JSON keys that carry incrementally streamed prose.
// Only these feed the stateful rehydrator, because only these can be split
// across events. Everything else arrives whole.
var streamTextKeys = map[string]bool{
	"text":              true,
	"partial_json":      true,
	"thinking":          true,
	"content":           true,
	"reasoning":         true,
	"reasoning_content": true,
}

// terminalTypes are Anthropic event types after which no further text can
// arrive in the current block.
var terminalTypes = map[string]bool{
	"content_block_stop": true,
	"message_delta":      true,
	"message_stop":       true,
	"error":              true,
}

// sseMeta is the subset of an event we need for ordering decisions.
type sseMeta struct {
	Type    string      `json:"type"`
	Index   *int        `json:"index"`
	ID      string      `json:"id"`
	Model   string      `json:"model"`
	Created json.Number `json:"created"`
	Choices []struct {
		Index        int     `json:"index"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

func (m sseMeta) terminal() bool {
	if terminalTypes[m.Type] {
		return true
	}
	for _, c := range m.Choices {
		if c.FinishReason != nil {
			return true
		}
	}
	return false
}

// streamResponse relays an SSE stream, rehydrating placeholders as it goes.
//
// Two ordering problems are handled here. First, a placeholder can straddle
// events, so the rehydrator holds the ambiguous tail. Second, those held
// bytes must be emitted before the stream's terminal events — otherwise the
// text would arrive after the client has already closed the content block.
// To do that we buffer each "event:" line until its "data:" line arrives, so
// a synthetic delta can be injected cleanly in front of the pair.
func (s *Server) streamResponse(w http.ResponseWriter, body io.Reader, v *vault.Vault, provider string) (int64, []string, error) {
	h := rewrite.NewRehydrator(v)
	flusher, _ := w.(http.Flusher)
	br := bufio.NewReaderSize(body, 64*1024)

	var written int64
	var pendingEvent string
	st := &streamState{provider: provider}

	emit := func(s string) error {
		n, err := io.WriteString(w, s)
		written += int64(n)
		return err
	}

	// flushHeld emits anything the rehydrator is holding as its own event,
	// ahead of whatever triggered the flush.
	flushHeld := func() error {
		tail := h.Flush()
		if tail == "" {
			return nil
		}
		return emit(st.syntheticDelta(tail))
	}

	var relayErr error
	for {
		line, readErr := br.ReadString('\n')

		if line != "" {
			trimmed := strings.TrimRight(line, "\r\n")

			switch {
			case strings.HasPrefix(trimmed, "event:"):
				// Hold until the matching data line so we can inject before it.
				pendingEvent = line

			case strings.HasPrefix(trimmed, "data:"):
				payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
				out, terminal := s.rewriteEvent(payload, h, st)
				if terminal {
					if err := flushHeld(); err != nil {
						relayErr = err
					}
				}
				if pendingEvent != "" {
					if err := emit(pendingEvent); err != nil {
						relayErr = err
					}
					pendingEvent = ""
				}
				if err := emit("data: " + out + "\n"); err != nil {
					relayErr = err
				}

			default:
				// Blank separators, comments, id: and retry: lines.
				if pendingEvent != "" {
					if err := emit(pendingEvent); err != nil {
						relayErr = err
					}
					pendingEvent = ""
				}
				if err := emit(line); err != nil {
					relayErr = err
				}
			}

			if flusher != nil {
				flusher.Flush()
			}
		}

		if readErr != nil {
			if readErr != io.EOF && relayErr == nil {
				relayErr = readErr
			}
			break
		}
		if relayErr != nil {
			break
		}
	}

	// The upstream ended; emit whatever is still held plus any orphaned
	// event line, so no bytes are silently dropped.
	if err := flushHeld(); err != nil && relayErr == nil {
		relayErr = err
	}
	if pendingEvent != "" {
		if err := emit(pendingEvent); err != nil && relayErr == nil {
			relayErr = err
		}
	}
	if flusher != nil {
		flusher.Flush()
	}
	return written, h.Unknown(), relayErr
}

// rewriteEvent rehydrates one SSE data payload and reports whether it is a
// terminal event. Non-JSON payloads ([DONE], keepalives) pass through, but
// still count as terminal so held bytes are not stranded.
func (s *Server) rewriteEvent(payload string, h *rewrite.Rehydrator, st *streamState) (string, bool) {
	// The [DONE] sentinel starts with '[' and so looks structurally like
	// JSON. Checking it explicitly matters: it must count as terminal, or
	// held bytes would be emitted after the client has stopped reading.
	if payload == "" || payload == "[DONE]" || !looksLikeJSON([]byte(payload)) {
		return payload, true
	}

	var meta sseMeta
	if err := json.Unmarshal([]byte(payload), &meta); err != nil {
		// Not an event we can model. Forward it verbatim, and treat it as
		// terminal so nothing stays stranded behind it.
		return payload, true
	}
	st.observe(meta)

	out, err := jsonwalk.MapStrings([]byte(payload), func(key, val string) string {
		if streamTextKeys[key] {
			return h.Feed(val)
		}
		return h.Once(val)
	})
	if err != nil {
		// Unparseable payload: forward verbatim rather than corrupt the
		// stream. It cannot contain a rehydratable value we care about.
		return payload, meta.terminal()
	}
	return string(out), meta.terminal()
}

// streamState remembers just enough of the stream envelope to synthesize a
// well-formed delta event in the provider's own dialect.
type streamState struct {
	provider  string
	lastIndex int
	id        string
	model     string
	created   json.Number
}

func (st *streamState) observe(m sseMeta) {
	if m.Index != nil {
		st.lastIndex = *m.Index
	} else if len(m.Choices) > 0 {
		st.lastIndex = m.Choices[0].Index
	}
	if m.ID != "" {
		st.id = m.ID
	}
	if m.Model != "" {
		st.model = m.Model
	}
	if m.Created != "" {
		st.created = m.Created
	}
}

// syntheticDelta wraps leftover text in a complete SSE event. Leftover only
// occurs when a stream ends mid-placeholder, so this is a rare path — but
// dropping the bytes would silently truncate the model's answer.
func (st *streamState) syntheticDelta(text string) string {
	if st.provider == "openai" {
		created := st.created
		if created == "" {
			created = "0"
		}
		chunk := map[string]any{
			"id":      st.id,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   st.model,
			"choices": []any{map[string]any{
				"index":         st.lastIndex,
				"delta":         map[string]any{"content": text},
				"finish_reason": nil,
			}},
		}
		return "data: " + mustJSON(chunk) + "\n\n"
	}
	chunk := map[string]any{
		"type":  "content_block_delta",
		"index": st.lastIndex,
		"delta": map[string]any{"type": "text_delta", "text": text},
	}
	return "event: content_block_delta\ndata: " + mustJSON(chunk) + "\n\n"
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf(`{"type":"error","error":{"message":%q}}`, err.Error())
	}
	return string(b)
}
