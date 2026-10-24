package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigneshwarancs/airlock/internal/detect"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "airlock.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestShippedTemplateLoads is the release gate: `airlock init` writes
// DefaultYAML, so a template that does not validate ships a broken binary.
func TestShippedTemplateLoads(t *testing.T) {
	pol, err := Load(write(t, DefaultYAML))
	if err != nil {
		t.Fatalf("the shipped default policy does not load: %v", err)
	}
	if pol.Defaults.OnDetect != Tokenize {
		t.Errorf("default on_detect = %q, want tokenize", pol.Defaults.OnDetect)
	}
	if !pol.FailClosed() {
		t.Error("the shipped default must fail closed")
	}
	if _, err := pol.Scanner(); err != nil {
		t.Errorf("the shipped detector set does not compile: %v", err)
	}
	if len(pol.Detectors.Builtin) == 0 {
		t.Error("the shipped default enables no detectors")
	}
	if pol.Detectors.Entropy.Enabled {
		t.Error("entropy must stay opt-in by default")
	}
}

func TestShippedTemplateBlocksCredentials(t *testing.T) {
	pol, err := Load(write(t, DefaultYAML))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []detect.Kind{
		detect.PrivateKey, detect.AWSKey, detect.GitHubToken, detect.SlackToken, detect.APIKey,
	} {
		if got := pol.ActionFor(kind); got != Block {
			t.Errorf("ActionFor(%s) = %q, want block", kind, got)
		}
	}
	if got := pol.ActionFor(detect.Email); got != Tokenize {
		t.Errorf("ActionFor(EMAIL) = %q, want tokenize", got)
	}
}

func TestCustomDetectorActionApplies(t *testing.T) {
	pol, err := Load(write(t, DefaultYAML))
	if err != nil {
		t.Fatal(err)
	}
	// The template defines employee_id, which normalizes to EMPLOYEE_ID.
	if got := pol.ActionFor(detect.Kind("EMPLOYEE_ID")); got != Tokenize {
		t.Errorf("ActionFor(EMPLOYEE_ID) = %q, want tokenize", got)
	}
}

func TestExplicitActionOutranksDefault(t *testing.T) {
	pol, err := Load(write(t, `
version: 1
upstream: {anthropic: https://api.anthropic.com}
defaults: {on_detect: redact, fail: closed}
detectors:
  builtin: [EMAIL, CARD]
actions:
  CARD: block
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := pol.ActionFor(detect.CreditCard); got != Block {
		t.Errorf("ActionFor(CARD) = %q, want block", got)
	}
	if got := pol.ActionFor(detect.Email); got != Redact {
		t.Errorf("ActionFor(EMAIL) = %q, want the default redact", got)
	}
}

// TestFileOwnsDetectorList makes sure a short policy does not silently
// inherit the builtin defaults — the file must mean exactly what it says.
func TestFileOwnsDetectorList(t *testing.T) {
	pol, err := Load(write(t, `
version: 1
upstream: {anthropic: https://api.anthropic.com}
defaults: {on_detect: tokenize, fail: closed}
detectors:
  builtin: [EMAIL]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.Detectors.Builtin) != 1 || pol.Detectors.Builtin[0] != "EMAIL" {
		t.Errorf("builtin = %v, want exactly [EMAIL]", pol.Detectors.Builtin)
	}
	if len(pol.Actions) != 0 {
		t.Errorf("actions = %v, want none inherited", pol.Actions)
	}
}

func TestInvalidPoliciesAreRejected(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unsupported version",
			body: "version: 99\nupstream: {anthropic: x}\ndefaults: {on_detect: tokenize, fail: closed}\n",
			want: "version",
		},
		{
			name: "bad default action",
			body: "version: 1\nupstream: {anthropic: x}\ndefaults: {on_detect: shred, fail: closed}\n",
			want: "on_detect",
		},
		{
			name: "bad fail mode",
			body: "version: 1\nupstream: {anthropic: x}\ndefaults: {on_detect: tokenize, fail: maybe}\n",
			want: "fail",
		},
		{
			name: "unknown detector",
			body: "version: 1\nupstream: {anthropic: x}\ndefaults: {on_detect: tokenize, fail: closed}\ndetectors:\n  builtin: [NOPE]\n",
			want: "unknown detector",
		},
		{
			name: "bad per-kind action",
			body: "version: 1\nupstream: {anthropic: x}\ndefaults: {on_detect: tokenize, fail: closed}\nactions:\n  EMAIL: incinerate\n",
			want: "invalid action",
		},
		{
			name: "custom detector missing pattern",
			body: "version: 1\nupstream: {anthropic: x}\ndefaults: {on_detect: tokenize, fail: closed}\ndetectors:\n  custom:\n    - name: foo\n",
			want: "name and pattern",
		},
		{
			name: "uncompilable custom pattern",
			body: "version: 1\nupstream: {anthropic: x}\ndefaults: {on_detect: tokenize, fail: closed}\ndetectors:\n  custom:\n    - {name: foo, pattern: \"([\"}\n",
			want: "custom detector",
		},
		{
			name: "no upstream",
			body: "version: 1\nupstream: {}\ndefaults: {on_detect: tokenize, fail: closed}\n",
			want: "upstream",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(write(t, tc.body))
			if err == nil {
				t.Fatal("expected the policy to be rejected")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadMissingFileIsNotExist(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("expected an error for a missing policy file")
	}
	if !os.IsNotExist(unwrap(err)) {
		t.Errorf("error should wrap fs.ErrNotExist so the CLI can suggest `airlock init`, got %v", err)
	}
}

func unwrap(err error) error {
	type unwrapper interface{ Unwrap() error }
	for {
		u, ok := err.(unwrapper)
		if !ok {
			return err
		}
		err = u.Unwrap()
	}
}

func TestFailOpenIsHonoured(t *testing.T) {
	pol, err := Load(write(t, `
version: 1
upstream: {anthropic: x}
defaults: {on_detect: tokenize, fail: open}
`))
	if err != nil {
		t.Fatal(err)
	}
	if pol.FailClosed() {
		t.Error("fail: open should disable fail-closed behaviour")
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory in this environment")
	}
	if got := ExpandHome("~/.airlock/ledger.jsonl"); got != filepath.Join(home, ".airlock/ledger.jsonl") {
		t.Errorf("ExpandHome = %q", got)
	}
	if got := ExpandHome("/absolute/path"); got != "/absolute/path" {
		t.Errorf("absolute paths must be untouched, got %q", got)
	}
	if got := ExpandHome("relative/path"); got != "relative/path" {
		t.Errorf("relative paths must be untouched, got %q", got)
	}
	// A path that merely contains ~ must not be expanded.
	if got := ExpandHome("/tmp/~backup"); got != "/tmp/~backup" {
		t.Errorf("mid-path tilde was expanded, got %q", got)
	}
}

func TestUpstreamLookup(t *testing.T) {
	pol := Default()
	if u, ok := pol.UpstreamFor("anthropic"); !ok || u == "" {
		t.Error("anthropic upstream should be configured by default")
	}
	if _, ok := pol.UpstreamFor("nonexistent"); ok {
		t.Error("UpstreamFor should report unknown providers as missing")
	}
}

func TestDefaultPolicyValidates(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("Default() must be valid: %v", err)
	}
}
