package guard

import (
	"strings"
	"testing"

	"github.com/vigneshwarancs/airlock/internal/detect"
	"github.com/vigneshwarancs/airlock/internal/policy"
	"github.com/vigneshwarancs/airlock/internal/rewrite"
	"github.com/vigneshwarancs/airlock/internal/vault"
)

const pemKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9OiJjRazXBZ1BjP5CE/Wm/Rr500P
-----END RSA PRIVATE KEY-----`

func guardWith(t *testing.T, mutate func(*policy.Policy)) *Guard {
	t.Helper()
	pol := policy.Default()
	if mutate != nil {
		mutate(pol)
	}
	g, err := New(pol)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func TestTokenizeThenRehydrateIsLossless(t *testing.T) {
	g := guardWith(t, nil)
	v := vault.New()

	in := "Email priya.r@acme.co and card 4111 1111 1111 1111 for order AC-88412."
	out, rep := g.SanitizeText(in, v)

	if strings.Contains(out, "priya.r@acme.co") {
		t.Error("email survived into the sanitized text")
	}
	if strings.Contains(out, "4111 1111 1111 1111") {
		t.Error("card survived into the sanitized text")
	}
	if rep.Tokenized["EMAIL"] != 1 || rep.Tokenized["CARD"] != 1 {
		t.Errorf("report = %+v, want one EMAIL and one CARD tokenized", rep.Tokenized)
	}
	// The non-sensitive parts must be untouched.
	if !strings.Contains(out, "for order AC-88412.") {
		t.Errorf("surrounding text was altered: %q", out)
	}

	back, unknown := rewrite.All(v, out)
	if back != in {
		t.Errorf("round trip changed the text:\n got %q\nwant %q", back, in)
	}
	if len(unknown) != 0 {
		t.Errorf("unexpected unknown placeholders: %v", unknown)
	}
}

// TestManyMatchesKeepOffsetsValid exercises the right-to-left replacement:
// rewriting left to right would invalidate every later offset.
func TestManyMatchesKeepOffsetsValid(t *testing.T) {
	g := guardWith(t, nil)
	v := vault.New()

	in := "a@x.com, b@y.com, c@z.com, d@w.com, e@v.com"
	out, rep := g.SanitizeText(in, v)

	if rep.Tokenized["EMAIL"] != 5 {
		t.Fatalf("tokenized %d emails, want 5 (report %+v)", rep.Tokenized["EMAIL"], rep.Tokenized)
	}
	for _, want := range []string{"EMAIL_1", "EMAIL_2", "EMAIL_3", "EMAIL_4", "EMAIL_5"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing placeholder %s in %q", want, out)
		}
	}
	if back, _ := rewrite.All(v, out); back != in {
		t.Errorf("round trip failed:\n got %q\nwant %q", back, in)
	}
}

func TestRepeatedValueReusesOnePlaceholder(t *testing.T) {
	g := guardWith(t, nil)
	v := vault.New()

	in := "Contact priya@acme.co. Reply to priya@acme.co. CC priya@acme.co."
	out, _ := g.SanitizeText(in, v)

	if strings.Contains(out, "EMAIL_2") {
		t.Errorf("the same address got multiple placeholders: %q", out)
	}
	if n := strings.Count(out, "[[AL:EMAIL_1]]"); n != 3 {
		t.Errorf("found %d occurrences of EMAIL_1, want 3", n)
	}
	if back, _ := rewrite.All(v, out); back != in {
		t.Error("round trip failed for a repeated value")
	}
}

func TestBlockedCredentialIsReportedAndRemoved(t *testing.T) {
	g := guardWith(t, nil)
	v := vault.New()

	in := "deploy key:\n" + pemKey + "\nuse it"
	out, rep := g.SanitizeText(in, v)

	if !rep.IsBlocked() {
		t.Fatal("a private key must trigger the block action")
	}
	if got := rep.BlockedKinds(); len(got) != 1 || got[0] != "PRIVATE_KEY" {
		t.Errorf("BlockedKinds() = %v, want [PRIVATE_KEY]", got)
	}
	// Even on the blocked path the value must be stripped, in case a
	// fail-open operator forwards the body anyway.
	if strings.Contains(out, "MIIEowIBAAKCAQEA") {
		t.Error("the key body survived into the sanitized text")
	}
}

func TestRedactIsIrreversible(t *testing.T) {
	g := guardWith(t, func(p *policy.Policy) {
		p.Actions[string(detect.Email)] = policy.Redact
	})
	v := vault.New()

	out, rep := g.SanitizeText("mail priya@acme.co now", v)
	if rep.Redacted["EMAIL"] != 1 {
		t.Fatalf("report = %+v, want one redacted EMAIL", rep)
	}
	if !strings.Contains(out, vault.Redacted) {
		t.Errorf("expected the redaction sentinel in %q", out)
	}

	back, unknown := rewrite.All(v, out)
	if strings.Contains(back, "priya@acme.co") {
		t.Error("a redacted value came back — redaction must be one-way")
	}
	if !strings.Contains(back, "[redacted]") {
		t.Errorf("expected a visible redaction marker, got %q", back)
	}
	if len(unknown) != 0 {
		t.Errorf("the sentinel must not count as unknown: %v", unknown)
	}
}

func TestAllowPassesValueThrough(t *testing.T) {
	g := guardWith(t, func(p *policy.Policy) {
		p.Actions[string(detect.Email)] = policy.Allow
	})
	v := vault.New()

	in := "mail priya@acme.co now"
	out, rep := g.SanitizeText(in, v)
	if out != in {
		t.Errorf("allow must not alter the text, got %q", out)
	}
	if rep.Allowed["EMAIL"] != 1 {
		t.Errorf("report = %+v, want one allowed EMAIL", rep)
	}
	if v.Len() != 0 {
		t.Error("allow must not mint a placeholder")
	}
}

func TestCleanTextIsUntouchedAndReportsNothing(t *testing.T) {
	g := guardWith(t, nil)
	v := vault.New()

	in := "Refactor the retry loop in internal/proxy/stream.go to use a bounded buffer."
	out, rep := g.SanitizeText(in, v)
	if out != in {
		t.Errorf("clean text was modified: %q", out)
	}
	if rep.Total() != 0 {
		t.Errorf("report = %+v, want nothing detected", rep)
	}
	if rep.Map() != nil {
		t.Errorf("Map() = %v, want nil for an empty report", rep.Map())
	}
}

func TestSanitizeDocumentWalksNestedToolArguments(t *testing.T) {
	g := guardWith(t, nil)
	v := vault.New()

	raw := []byte(`{
      "model":"claude-opus-5",
      "messages":[{"role":"user","content":[
        {"type":"tool_result","content":"customer priya@acme.co"},
        {"type":"text","text":"and card 4111111111111111"}
      ]}]
    }`)

	out, rep, err := g.SanitizeDocument(raw, v)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "priya@acme.co") {
		t.Error("email inside a tool_result was not sanitized")
	}
	if strings.Contains(string(out), "4111111111111111") {
		t.Error("card inside a text block was not sanitized")
	}
	if !strings.Contains(string(out), `"model":"claude-opus-5"`) {
		t.Error("the model field must be preserved exactly")
	}
	if rep.Tokenized["EMAIL"] != 1 || rep.Tokenized["CARD"] != 1 {
		t.Errorf("report = %+v", rep.Tokenized)
	}
}

func TestSanitizeDocumentRejectsMalformedJSON(t *testing.T) {
	g := guardWith(t, nil)
	if _, _, err := g.SanitizeDocument([]byte(`{"broken":`), vault.New()); err == nil {
		t.Error("expected an error for malformed JSON so the caller can fail closed")
	}
}

func TestReportMapGroupsByAction(t *testing.T) {
	g := guardWith(t, func(p *policy.Policy) {
		p.Actions[string(detect.CreditCard)] = policy.Redact
	})
	v := vault.New()

	_, rep := g.SanitizeText("priya@acme.co and 4111111111111111 and "+pemKey, v)
	m := rep.Map()

	if m["tokenize"]["EMAIL"] != 1 {
		t.Errorf("tokenize bucket = %v", m["tokenize"])
	}
	if m["redact"]["CARD"] != 1 {
		t.Errorf("redact bucket = %v", m["redact"])
	}
	if m["block"]["PRIVATE_KEY"] != 1 {
		t.Errorf("block bucket = %v", m["block"])
	}
	if rep.Total() != 3 {
		t.Errorf("Total() = %d, want 3", rep.Total())
	}
}

func TestCustomDetectorFromPolicyIsApplied(t *testing.T) {
	g := guardWith(t, func(p *policy.Policy) {
		p.Detectors.Custom = []policy.CustomDetector{
			{Name: "employee_id", Pattern: `EMP-[0-9]{6}`, Action: policy.Tokenize},
		}
	})
	v := vault.New()

	out, rep := g.SanitizeText("assigned to EMP-004213 today", v)
	if strings.Contains(out, "EMP-004213") {
		t.Errorf("custom detector did not fire: %q", out)
	}
	if rep.Tokenized["EMPLOYEE_ID"] != 1 {
		t.Errorf("report = %+v, want one EMPLOYEE_ID", rep.Tokenized)
	}
	if back, _ := rewrite.All(v, out); !strings.Contains(back, "EMP-004213") {
		t.Error("custom detector value did not round trip")
	}
}

func TestNewRejectsInvalidPolicy(t *testing.T) {
	pol := policy.Default()
	pol.Detectors.Builtin = []string{"NOT_REAL"}
	if _, err := New(pol); err == nil {
		t.Error("New must reject a policy whose detectors do not compile")
	}
}
