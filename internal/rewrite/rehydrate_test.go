package rewrite

import (
	"strings"
	"testing"

	"github.com/vigneshwarancs/airlock/internal/vault"
)

// fixture returns a vault with two known placeholders plus the tokenized and
// expected-plaintext forms of a sentence that uses one of them twice.
func fixture(t *testing.T) (*vault.Vault, string, string) {
	t.Helper()
	v := vault.New()
	person := v.Tokenize("PERSON", "Priya Raghavan")
	email := v.Tokenize("EMAIL", "priya.r@acme.co")

	tokenized := "Hi " + person + ", we emailed " + email + ". Regards to " + person + "!"
	plain := "Hi Priya Raghavan, we emailed priya.r@acme.co. Regards to Priya Raghavan!"
	return v, tokenized, plain
}

func TestRehydrateWholeString(t *testing.T) {
	v, tokenized, plain := fixture(t)
	got, unknown := All(v, tokenized)
	if got != plain {
		t.Errorf("got %q, want %q", got, plain)
	}
	if len(unknown) != 0 {
		t.Errorf("unexpected unknown placeholders: %v", unknown)
	}
}

// TestRehydrateAcrossEverySplitPoint is the core guarantee: no matter where
// the provider happens to break the stream, the client sees identical text.
func TestRehydrateAcrossEverySplitPoint(t *testing.T) {
	v, tokenized, plain := fixture(t)

	for i := 0; i <= len(tokenized); i++ {
		h := NewRehydrator(v)
		got := h.Feed(tokenized[:i]) + h.Feed(tokenized[i:]) + h.Flush()
		if got != plain {
			t.Fatalf("split at %d: got %q, want %q", i, got, plain)
		}
		if len(h.Unknown()) != 0 {
			t.Fatalf("split at %d: unexpected unknowns %v", i, h.Unknown())
		}
	}
}

// TestRehydrateByteByByte is the worst case a token-streaming provider can
// produce: every byte arrives in its own event.
func TestRehydrateByteByByte(t *testing.T) {
	v, tokenized, plain := fixture(t)

	h := NewRehydrator(v)
	var sb strings.Builder
	for i := 0; i < len(tokenized); i++ {
		sb.WriteString(h.Feed(tokenized[i : i+1]))
	}
	sb.WriteString(h.Flush())

	if got := sb.String(); got != plain {
		t.Errorf("got %q, want %q", got, plain)
	}
}

func TestRehydrateAtEveryFixedChunkSize(t *testing.T) {
	v, tokenized, plain := fixture(t)

	for _, size := range []int{1, 2, 3, 4, 5, 7, 11, 13, 64} {
		h := NewRehydrator(v)
		var sb strings.Builder
		for i := 0; i < len(tokenized); i += size {
			end := i + size
			if end > len(tokenized) {
				end = len(tokenized)
			}
			sb.WriteString(h.Feed(tokenized[i:end]))
		}
		sb.WriteString(h.Flush())
		if got := sb.String(); got != plain {
			t.Errorf("chunk size %d: got %q, want %q", size, got, plain)
		}
	}
}

// TestHoldIsBounded guarantees the latency claim: the rehydrator never
// withholds more than one placeholder's width.
func TestHoldIsBounded(t *testing.T) {
	v := vault.New()
	v.Tokenize("PERSON", "Priya")

	h := NewRehydrator(v)
	long := strings.Repeat("ordinary prose ", 100)
	out := h.Feed(long)
	if h.Pending() {
		t.Error("rehydrator is holding bytes for text containing no opener")
	}
	if out != long {
		t.Error("plain text was altered")
	}

	// A partial opener is held, but only the partial opener.
	out = h.Feed("tail text [[AL")
	if !h.Pending() {
		t.Error("expected the partial opener to be held")
	}
	if out != "tail text " {
		t.Errorf("got %q, want everything before the partial opener", out)
	}
	if got := h.Flush(); got != "[[AL" {
		t.Errorf("Flush() = %q, want the held partial opener verbatim", got)
	}
}

func TestUnknownPlaceholderIsReportedAndLeftLiteral(t *testing.T) {
	v := vault.New()
	v.Tokenize("PERSON", "Priya")

	h := NewRehydrator(v)
	// PERSON_7 was never minted — the model invented it.
	got := h.Feed("Hello [[AL:PERSON_7]] and [[AL:PERSON_1]]") + h.Flush()

	if !strings.Contains(got, "[[AL:PERSON_7]]") {
		t.Errorf("unknown placeholder should pass through literally, got %q", got)
	}
	if !strings.Contains(got, "Priya") {
		t.Errorf("known placeholder should still resolve, got %q", got)
	}
	unknown := h.Unknown()
	if len(unknown) != 1 || unknown[0] != "[[AL:PERSON_7]]" {
		t.Errorf("Unknown() = %v, want exactly [[AL:PERSON_7]]", unknown)
	}
}

func TestRedactionSentinelResolves(t *testing.T) {
	v := vault.New()
	got, unknown := All(v, "value was "+vault.Redacted+" here")
	if got != "value was [redacted] here" {
		t.Errorf("got %q", got)
	}
	if len(unknown) != 0 {
		t.Errorf("the redaction sentinel must not count as unknown, got %v", unknown)
	}
}

func TestLiteralTextThatResemblesPlaceholders(t *testing.T) {
	v := vault.New()
	v.Tokenize("PERSON", "Priya")

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lowercase name is not a placeholder", "[[AL:person_1]]", "[[AL:person_1]]"},
		{"spaces in name", "[[AL:NOT A NAME]]", "[[AL:NOT A NAME]]"},
		{"empty name", "[[AL:]]", "[[AL:]]"},
		{"opener with no closer anywhere", "prefix [[AL:" + strings.Repeat("X", 200), "prefix [[AL:" + strings.Repeat("X", 200)},
		{"double bracket text", "array[[0]] and x", "array[[0]] and x"},
		{"nested openers", "[[AL:[[AL:PERSON_1]]", "[[AL:Priya"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := NewRehydrator(v)
			if got := h.Feed(tc.in) + h.Flush(); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestOnceDoesNotDisturbStreamState covers the mixed case inside a streamed
// SSE event, where some fields arrive whole and one arrives incrementally.
func TestOnceDoesNotDisturbStreamState(t *testing.T) {
	v := vault.New()
	person := v.Tokenize("PERSON", "Priya")
	email := v.Tokenize("EMAIL", "p@acme.co")

	h := NewRehydrator(v)
	if got := h.Feed("Hi " + person[:6]); got != "Hi " {
		t.Fatalf("expected the partial placeholder to be held, got %q", got)
	}
	if got := h.Once("whole field: " + email); got != "whole field: p@acme.co" {
		t.Errorf("Once() = %q", got)
	}
	if !h.Pending() {
		t.Error("Once() must not clear the streaming hold")
	}
	if got := h.Feed(person[6:]) + h.Flush(); got != "Priya" {
		t.Errorf("resumed stream = %q, want Priya", got)
	}
}

func TestEmptyFeedsAreHarmless(t *testing.T) {
	v := vault.New()
	h := NewRehydrator(v)
	for i := 0; i < 5; i++ {
		if got := h.Feed(""); got != "" {
			t.Errorf("Feed(\"\") = %q, want empty", got)
		}
	}
	if got := h.Flush(); got != "" {
		t.Errorf("Flush() = %q, want empty", got)
	}
}

func BenchmarkRehydrateStreamed(b *testing.B) {
	v := vault.New()
	person := v.Tokenize("PERSON", "Priya Raghavan")
	text := strings.Repeat("some model output about "+person+" and more prose. ", 50)

	b.ReportAllocs()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := NewRehydrator(v)
		for j := 0; j < len(text); j += 16 {
			end := j + 16
			if end > len(text) {
				end = len(text)
			}
			_ = h.Feed(text[j:end])
		}
		_ = h.Flush()
	}
}

func BenchmarkRehydratePlainText(b *testing.B) {
	v := vault.New()
	text := strings.Repeat("plain model output with nothing to restore at all. ", 100)

	b.ReportAllocs()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := NewRehydrator(v)
		_ = h.Feed(text)
		_ = h.Flush()
	}
}
