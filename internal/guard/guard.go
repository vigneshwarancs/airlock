// Package guard applies policy to an outbound request: scan, decide, rewrite.
package guard

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vigneshwarancs/airlock/internal/detect"
	"github.com/vigneshwarancs/airlock/internal/jsonwalk"
	"github.com/vigneshwarancs/airlock/internal/policy"
	"github.com/vigneshwarancs/airlock/internal/vault"
)

// Guard is immutable and safe for concurrent use. Per-request state lives in
// the vault that callers pass in.
type Guard struct {
	pol *policy.Policy
	sc  *detect.Scanner
}

func New(p *policy.Policy) (*Guard, error) {
	sc, err := p.Scanner()
	if err != nil {
		return nil, err
	}
	return &Guard{pol: p, sc: sc}, nil
}

// Report summarizes what a scan found. It deliberately carries counts and
// kinds but never values — it is what gets written to the ledger.
type Report struct {
	Tokenized map[string]int `json:"tokenized,omitempty"`
	Redacted  map[string]int `json:"redacted,omitempty"`
	Blocked   map[string]int `json:"blocked,omitempty"`
	Allowed   map[string]int `json:"allowed,omitempty"`
}

func newReport() *Report {
	return &Report{
		Tokenized: map[string]int{},
		Redacted:  map[string]int{},
		Blocked:   map[string]int{},
		Allowed:   map[string]int{},
	}
}

// IsBlocked reports whether any detection triggered the block action.
func (r *Report) IsBlocked() bool { return len(r.Blocked) > 0 }

// BlockedKinds lists blocked detector kinds in stable order, for the error
// message returned to the agent.
func (r *Report) BlockedKinds() []string {
	out := make([]string, 0, len(r.Blocked))
	for k := range r.Blocked {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Total counts every detection, regardless of action.
func (r *Report) Total() int {
	n := 0
	for _, m := range []map[string]int{r.Tokenized, r.Redacted, r.Blocked, r.Allowed} {
		for _, c := range m {
			n += c
		}
	}
	return n
}

// Map renders the report as action -> kind -> count, the shape the ledger
// records. Empty actions are omitted.
func (r *Report) Map() map[string]map[string]int {
	out := map[string]map[string]int{}
	for action, m := range map[string]map[string]int{
		"tokenize": r.Tokenized,
		"redact":   r.Redacted,
		"block":    r.Blocked,
		"allow":    r.Allowed,
	} {
		if len(m) > 0 {
			out[action] = m
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// prune drops empty action buckets so the ledger and JSON output stay terse.
func (r *Report) prune() {
	if len(r.Tokenized) == 0 {
		r.Tokenized = nil
	}
	if len(r.Redacted) == 0 {
		r.Redacted = nil
	}
	if len(r.Blocked) == 0 {
		r.Blocked = nil
	}
	if len(r.Allowed) == 0 {
		r.Allowed = nil
	}
}

// SanitizeDocument rewrites every string leaf of a JSON request body
// according to policy, recording what it did.
//
// The body is still rewritten when something is blocked, because the caller
// decides what to do with a blocked report — but a blocked request must never
// be forwarded.
func (g *Guard) SanitizeDocument(raw []byte, v *vault.Vault) ([]byte, *Report, error) {
	rep := newReport()
	out, err := jsonwalk.MapStrings(raw, func(_, s string) string {
		return g.sanitizeString(s, v, rep)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("scan request body: %w", err)
	}
	rep.prune()
	return out, rep, nil
}

// SanitizeText rewrites a single string. Exposed for `airlock scan` and tests.
func (g *Guard) SanitizeText(s string, v *vault.Vault) (string, *Report) {
	rep := newReport()
	out := g.sanitizeString(s, v, rep)
	rep.prune()
	return out, rep
}

// sanitizeString replaces matches right-to-left so that earlier byte offsets
// stay valid as the string is rewritten.
func (g *Guard) sanitizeString(s string, v *vault.Vault, rep *Report) string {
	matches := g.sc.Scan(s)
	if len(matches) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16*len(matches))

	prev := 0
	for _, m := range matches {
		kind := string(m.Kind)
		action := g.pol.ActionFor(m.Kind)

		b.WriteString(s[prev:m.Start])
		switch action {
		case policy.Tokenize:
			rep.Tokenized[kind]++
			b.WriteString(v.Tokenize(kind, m.Value))
		case policy.Redact:
			rep.Redacted[kind]++
			b.WriteString(vault.Redacted)
		case policy.Block:
			// Still removed from the body: if a fail-open operator forwards
			// anyway, the value must not ride along.
			rep.Blocked[kind]++
			b.WriteString(vault.Redacted)
		case policy.Allow:
			rep.Allowed[kind]++
			b.WriteString(m.Value)
		}
		prev = m.End
	}
	b.WriteString(s[prev:])
	return b.String()
}
