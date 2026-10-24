// Package vault holds the mapping between real values and the placeholders
// that stand in for them upstream.
//
// The vault is in-memory and scoped to a single request. That is not a
// limitation — it is what makes cross-turn consistency free. Agents resend
// the whole conversation each turn, and Airlock rehydrates every response, so
// the same value reappears in the same order on the next request and is
// assigned the same placeholder. No persistence means no plaintext at rest.
package vault

import (
	"fmt"
	"sync"
)

const (
	// Open and Close are ASCII on purpose. encoding/json leaves them alone,
	// and they survive the round trip through providers that re-encode
	// non-ASCII as \uXXXX escapes.
	Open  = "[[AL:"
	Close = "]]"

	// MaxPlaceholderLen bounds how many bytes the streaming rehydrator will
	// hold back while waiting for a closing marker.
	MaxPlaceholderLen = 64

	// RedactedName is the sentinel for irreversible redaction.
	RedactedName = "REDACTED"
)

// Redacted is the placeholder emitted for the "redact" action.
var Redacted = Open + RedactedName + Close

// Vault is safe for concurrent use.
type Vault struct {
	mu     sync.Mutex
	fwd    map[string]string // kind\x00value -> placeholder
	rev    map[string]string // placeholder -> value
	counts map[string]int    // kind -> highest assigned ordinal
}

func New() *Vault {
	v := &Vault{
		fwd:    make(map[string]string),
		rev:    make(map[string]string),
		counts: make(map[string]int),
	}
	// Redaction is one-way: resolving the sentinel yields a visible marker
	// rather than tripping the unknown-placeholder check.
	v.rev[Redacted] = "[redacted]"
	return v
}

// Tokenize returns a stable placeholder for value. Calling it twice with the
// same kind and value returns the same placeholder.
//
// Keys are the exact bytes of value, never a normalized form. Two spellings
// of the same name get two placeholders, and both restore losslessly — which
// is the correct trade when the alternative is handing back the wrong string.
func (v *Vault) Tokenize(kind, value string) string {
	v.mu.Lock()
	defer v.mu.Unlock()

	key := kind + "\x00" + value
	if ph, ok := v.fwd[key]; ok {
		return ph
	}
	v.counts[kind]++
	ph := fmt.Sprintf("%s%s_%d%s", Open, kind, v.counts[kind], Close)
	v.fwd[key] = ph
	v.rev[ph] = value
	return ph
}

// Resolve maps a full placeholder back to its original value.
func (v *Vault) Resolve(placeholder string) (string, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	val, ok := v.rev[placeholder]
	return val, ok
}

// Len reports how many distinct values were tokenized.
func (v *Vault) Len() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.fwd)
}

// Summary counts placeholders per kind, for the ledger. Values never leave
// the vault, so only the counts are reportable.
func (v *Vault) Summary() map[string]int {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make(map[string]int, len(v.counts))
	for k, n := range v.counts {
		out[k] = n
	}
	return out
}
