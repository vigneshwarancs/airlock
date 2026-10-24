// Package rewrite restores real values in model output, including across
// streaming chunk boundaries.
//
// This is the hardest part of the proxy. Providers stream token by token, so
// a placeholder like [[AL:PERSON_1]] routinely arrives split as "[[AL:PER"
// then "SON_1]]". The rehydrator holds back exactly the bytes it cannot yet
// prove are safe to emit — never more than one placeholder's width — so added
// latency is bounded rather than amortized.
package rewrite

import (
	"sort"
	"strings"

	"github.com/vigneshwarancs/airlock/internal/vault"
)

// Resolver maps a full placeholder to its original value.
type Resolver interface {
	Resolve(placeholder string) (string, bool)
}

// Rehydrator is stateful across Feed calls and is not safe for concurrent
// use. Use one per response stream.
type Rehydrator struct {
	res     Resolver
	hold    string
	unknown map[string]int
}

func NewRehydrator(res Resolver) *Rehydrator {
	return &Rehydrator{res: res, unknown: make(map[string]int)}
}

// Feed consumes the next chunk and returns the text that is safe to emit now.
// It may return "" if the entire chunk is an ambiguous placeholder prefix.
func (h *Rehydrator) Feed(s string) string {
	if s == "" && h.hold == "" {
		return ""
	}
	out, hold := h.rewrite(h.hold+s, true)
	h.hold = hold
	return out
}

// Flush emits any held bytes. Call it once the stream is complete. Whatever
// is left is by definition an incomplete placeholder, so it is emitted
// verbatim — it can never contain a real value.
func (h *Rehydrator) Flush() string {
	if h.hold == "" {
		return ""
	}
	out, _ := h.rewrite(h.hold, false)
	h.hold = ""
	return out
}

// Once rewrites a complete, self-contained string without touching the
// streaming hold state, while still recording unknown placeholders. Use it
// for fields that arrive whole inside a streamed event (tool names, error
// messages) rather than token by token.
func (h *Rehydrator) Once(s string) string {
	out, _ := h.rewrite(s, false)
	return out
}

// Pending reports whether bytes are currently held back.
func (h *Rehydrator) Pending() bool { return h.hold != "" }

// Unknown lists placeholders the model emitted that were never minted, in
// sorted order. A non-empty result means the model invented a placeholder,
// which policy treats as a violation rather than as text.
func (h *Rehydrator) Unknown() []string {
	if len(h.unknown) == 0 {
		return nil
	}
	out := make([]string, 0, len(h.unknown))
	for k := range h.unknown {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (h *Rehydrator) rewrite(buf string, allowHold bool) (out, hold string) {
	var b strings.Builder
	b.Grow(len(buf))

	i := 0
	for i < len(buf) {
		j := strings.Index(buf[i:], vault.Open)
		if j < 0 {
			// No opener in the remainder, but the tail may be the start of
			// one that continues in the next chunk.
			if allowHold {
				k := partialOpenSuffix(buf, i)
				b.WriteString(buf[i:k])
				return b.String(), buf[k:]
			}
			b.WriteString(buf[i:])
			return b.String(), ""
		}

		start := i + j
		b.WriteString(buf[i:start])
		nameStart := start + len(vault.Open)

		e := strings.Index(buf[nameStart:], vault.Close)
		if e < 0 {
			// Opener with no closer. Hold only while a placeholder is still
			// possible; past that width it is ordinary text.
			if allowHold && len(buf)-start <= vault.MaxPlaceholderLen {
				return b.String(), buf[start:]
			}
			b.WriteString(vault.Open)
			i = nameStart
			continue
		}

		name := buf[nameStart : nameStart+e]
		if !validName(name) {
			b.WriteString(vault.Open)
			i = nameStart
			continue
		}

		end := nameStart + e + len(vault.Close)
		ph := buf[start:end]
		if val, ok := h.res.Resolve(ph); ok {
			b.WriteString(val)
		} else {
			h.unknown[ph]++
			b.WriteString(ph) // carries no secret; surfaced via Unknown()
		}
		i = end
	}
	return b.String(), ""
}

// partialOpenSuffix returns the index where a trailing partial opener begins,
// or len(buf) if the tail cannot start one.
func partialOpenSuffix(buf string, from int) int {
	max := len(vault.Open) - 1
	if n := len(buf) - from; n < max {
		max = n
	}
	for n := max; n > 0; n-- {
		if strings.HasPrefix(vault.Open, buf[len(buf)-n:]) {
			return len(buf) - n
		}
	}
	return len(buf)
}

func validName(s string) bool {
	if s == "" || len(s) > vault.MaxPlaceholderLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			continue
		}
		return false
	}
	return true
}

// All rehydrates a complete string in one shot, for non-streaming responses.
func All(res Resolver, s string) (string, []string) {
	h := NewRehydrator(res)
	out := h.Feed(s) + h.Flush()
	return out, h.Unknown()
}
