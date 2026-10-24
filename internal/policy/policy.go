// Package policy loads and evaluates the YAML rules that define the data
// boundary. The policy file is meant to live in version control: it is the
// reviewable artifact that says what may leave the machine.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/vigneshwarancs/airlock/internal/detect"
)

// Action is what happens when a detector fires.
type Action string

const (
	// Tokenize swaps the value for a reversible placeholder. Default.
	Tokenize Action = "tokenize"
	// Redact replaces the value irreversibly. Use when the model has no
	// legitimate need for the value, not even a stand-in identity.
	Redact Action = "redact"
	// Block refuses the request outright.
	Block Action = "block"
	// Allow forwards the value untouched.
	Allow Action = "allow"
)

func (a Action) valid() bool {
	switch a {
	case Tokenize, Redact, Block, Allow:
		return true
	}
	return false
}

// Policy is the parsed airlock.yaml.
type Policy struct {
	Version  int               `yaml:"version"`
	Listen   string            `yaml:"listen"`
	Upstream map[string]string `yaml:"upstream"`

	// Pointer-typed booleans distinguish "omitted" from "explicitly false",
	// so `enabled: false` in a file is never overwritten by a default.
	Defaults struct {
		OnDetect           Action `yaml:"on_detect"`
		Fail               string `yaml:"fail"`
		StrictPlaceholders *bool  `yaml:"strict_placeholders"`
	} `yaml:"defaults"`

	Detectors struct {
		Builtin []string `yaml:"builtin"`
		Entropy struct {
			Enabled bool    `yaml:"enabled"`
			MinBits float64 `yaml:"min_bits"`
			MinLen  int     `yaml:"min_len"`
		} `yaml:"entropy"`
		Custom []CustomDetector `yaml:"custom"`
	} `yaml:"detectors"`

	// Actions overrides Defaults.OnDetect for a specific detector kind.
	Actions map[string]Action `yaml:"actions"`

	Ledger struct {
		Enabled        *bool  `yaml:"enabled"`
		Path           string `yaml:"path"`
		RedactPayloads bool   `yaml:"redact_payloads"`
	} `yaml:"ledger"`
}

// CustomDetector is a user-supplied regex, with an optional action override.
type CustomDetector struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"`
	Action  Action `yaml:"action"`
}

// Default returns the policy `airlock init` writes: every checksum-validated
// and prefix-anchored detector on, tokenizing by default, credentials blocked
// outright, failing closed.
func Default() *Policy {
	p := &Policy{
		Version: 1,
		Listen:  "127.0.0.1:4455",
		Upstream: map[string]string{
			"anthropic": "https://api.anthropic.com",
			"openai":    "https://api.openai.com",
		},
		Actions: map[string]Action{
			string(detect.PrivateKey):  Block,
			string(detect.AWSKey):      Block,
			string(detect.GitHubToken): Block,
			string(detect.SlackToken):  Block,
			string(detect.APIKey):      Block,
		},
	}
	p.Defaults.OnDetect = Tokenize
	p.Defaults.Fail = "closed"
	p.Defaults.StrictPlaceholders = boolPtr(true)

	for _, k := range detect.DefaultKinds {
		p.Detectors.Builtin = append(p.Detectors.Builtin, string(k))
	}
	p.Detectors.Entropy.MinBits = 4.2
	p.Detectors.Entropy.MinLen = 24

	p.Ledger.Enabled = boolPtr(true)
	p.Ledger.Path = "~/.airlock/ledger.jsonl"
	p.Ledger.RedactPayloads = true
	return p
}

// Load reads and validates a policy file.
//
// Parsing starts from the zero value rather than from Default() so that the
// file owns what it declares: `upstream: {}` means no upstreams, not the
// built-in ones, and a policy listing three detectors does not silently
// inherit eleven. Only fields the file omits entirely fall back to defaults.
func Load(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}

	p := &Policy{}
	if err := yaml.Unmarshal(raw, p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	p.applyDefaults()

	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// applyDefaults fills in only the fields the policy file left unset.
func (p *Policy) applyDefaults() {
	d := Default()
	if p.Version == 0 {
		p.Version = d.Version
	}
	if p.Listen == "" {
		p.Listen = d.Listen
	}
	if p.Upstream == nil {
		p.Upstream = d.Upstream
	}
	if p.Defaults.OnDetect == "" {
		p.Defaults.OnDetect = d.Defaults.OnDetect
	}
	if p.Defaults.Fail == "" {
		p.Defaults.Fail = d.Defaults.Fail
	}
	if p.Defaults.StrictPlaceholders == nil {
		p.Defaults.StrictPlaceholders = d.Defaults.StrictPlaceholders
	}
	if p.Detectors.Entropy.MinBits == 0 {
		p.Detectors.Entropy.MinBits = d.Detectors.Entropy.MinBits
	}
	if p.Detectors.Entropy.MinLen == 0 {
		p.Detectors.Entropy.MinLen = d.Detectors.Entropy.MinLen
	}
	if p.Ledger.Enabled == nil {
		p.Ledger.Enabled = d.Ledger.Enabled
	}
	if p.Ledger.Path == "" {
		p.Ledger.Path = d.Ledger.Path
	}
}

// Validate rejects a policy rather than guessing. A security policy that
// silently falls back to a default is worse than one that refuses to start.
func (p *Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version %d (expected 1)", p.Version)
	}
	if !p.Defaults.OnDetect.valid() {
		return fmt.Errorf("defaults.on_detect %q must be one of tokenize, redact, block, allow", p.Defaults.OnDetect)
	}
	switch p.Defaults.Fail {
	case "closed", "open":
	default:
		return fmt.Errorf("defaults.fail %q must be \"closed\" or \"open\"", p.Defaults.Fail)
	}
	for kind, a := range p.Actions {
		if !a.valid() {
			return fmt.Errorf("actions.%s: invalid action %q", kind, a)
		}
	}
	for _, c := range p.Detectors.Custom {
		if c.Name == "" || c.Pattern == "" {
			return fmt.Errorf("custom detector needs both name and pattern")
		}
		if c.Action != "" && !c.Action.valid() {
			return fmt.Errorf("custom detector %q: invalid action %q", c.Name, c.Action)
		}
	}
	if len(p.Upstream) == 0 {
		return fmt.Errorf("at least one upstream must be configured")
	}
	// Surface unknown detector names here, at startup, rather than at the
	// first request.
	if _, err := p.Scanner(); err != nil {
		return err
	}
	return nil
}

// Scanner compiles the policy's detector set.
func (p *Policy) Scanner() (*detect.Scanner, error) {
	kinds := make([]detect.Kind, 0, len(p.Detectors.Builtin))
	for _, k := range p.Detectors.Builtin {
		kinds = append(kinds, detect.Kind(strings.ToUpper(strings.TrimSpace(k))))
	}
	custom := make([]detect.Custom, 0, len(p.Detectors.Custom))
	for _, c := range p.Detectors.Custom {
		custom = append(custom, detect.Custom{Name: c.Name, Pattern: c.Pattern})
	}
	var ent *detect.EntropyDetector
	if p.Detectors.Entropy.Enabled {
		ent = &detect.EntropyDetector{
			MinBits: p.Detectors.Entropy.MinBits,
			MinLen:  p.Detectors.Entropy.MinLen,
		}
	}
	return detect.NewScanner(kinds, custom, ent)
}

// ActionFor resolves the action for a detected kind, honouring per-kind
// overrides and custom-detector actions before the default.
func (p *Policy) ActionFor(kind detect.Kind) Action {
	if a, ok := p.Actions[string(kind)]; ok && a.valid() {
		return a
	}
	for _, c := range p.Detectors.Custom {
		if c.Action != "" && detect.Kind(normalize(c.Name)) == kind {
			return c.Action
		}
	}
	return p.Defaults.OnDetect
}

// FailClosed reports whether a detector or upstream error should block the
// request instead of forwarding it.
func (p *Policy) FailClosed() bool { return p.Defaults.Fail != "open" }

// StrictPlaceholders reports whether a placeholder the model invented should
// be treated as a violation. Defaults to true when unset.
func (p *Policy) StrictPlaceholders() bool {
	return p.Defaults.StrictPlaceholders == nil || *p.Defaults.StrictPlaceholders
}

// LedgerEnabled defaults to true when unset.
func (p *Policy) LedgerEnabled() bool {
	return p.Ledger.Enabled == nil || *p.Ledger.Enabled
}

func boolPtr(b bool) *bool { return &b }

// LedgerPath returns the ledger path with ~ expanded.
func (p *Policy) LedgerPath() string { return ExpandHome(p.Ledger.Path) }

// UpstreamFor returns the base URL for a provider name.
func (p *Policy) UpstreamFor(provider string) (string, bool) {
	u, ok := p.Upstream[provider]
	return u, ok
}

// Marshal renders the policy as YAML, for `airlock init`.
func (p *Policy) Marshal() ([]byte, error) { return yaml.Marshal(p) }

// ExpandHome replaces a leading ~ with the user's home directory.
func ExpandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(path, "~"), "/"))
	}
	return path
}

func normalize(s string) string {
	s = strings.ToUpper(s)
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteByte(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
