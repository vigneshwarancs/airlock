package vault

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestTokenizeIsStableForRepeatedValues(t *testing.T) {
	v := New()
	a := v.Tokenize("PERSON", "Priya Raghavan")
	b := v.Tokenize("PERSON", "Priya Raghavan")
	if a != b {
		t.Errorf("same value produced two placeholders: %q and %q", a, b)
	}
	if v.Len() != 1 {
		t.Errorf("Len() = %d, want 1", v.Len())
	}
}

func TestTokenizeNumbersWithinKind(t *testing.T) {
	v := New()
	first := v.Tokenize("EMAIL", "a@x.com")
	second := v.Tokenize("EMAIL", "b@x.com")
	other := v.Tokenize("PERSON", "Priya")

	if first != "[[AL:EMAIL_1]]" {
		t.Errorf("first = %q, want [[AL:EMAIL_1]]", first)
	}
	if second != "[[AL:EMAIL_2]]" {
		t.Errorf("second = %q, want [[AL:EMAIL_2]]", second)
	}
	// Counters are per kind, so a new kind restarts at 1.
	if other != "[[AL:PERSON_1]]" {
		t.Errorf("other = %q, want [[AL:PERSON_1]]", other)
	}
}

func TestSameValueUnderDifferentKindsStaysDistinct(t *testing.T) {
	v := New()
	a := v.Tokenize("EMAIL", "shared")
	b := v.Tokenize("PERSON", "shared")
	if a == b {
		t.Fatalf("different kinds collided on placeholder %q", a)
	}
	if got, _ := v.Resolve(a); got != "shared" {
		t.Errorf("Resolve(%q) = %q", a, got)
	}
	if got, _ := v.Resolve(b); got != "shared" {
		t.Errorf("Resolve(%q) = %q", b, got)
	}
}

// TestTokenizeIsLossless is the reason keys are exact bytes rather than a
// normalized form: restoring the wrong casing would be a silent data bug.
func TestTokenizeIsLossless(t *testing.T) {
	v := New()
	values := []string{"Priya", "priya", "PRIYA", " priya ", "priya\n"}
	placeholders := make([]string, len(values))
	for i, val := range values {
		placeholders[i] = v.Tokenize("PERSON", val)
	}
	for i, ph := range placeholders {
		got, ok := v.Resolve(ph)
		if !ok {
			t.Fatalf("placeholder %q did not resolve", ph)
		}
		if got != values[i] {
			t.Errorf("Resolve(%q) = %q, want %q", ph, got, values[i])
		}
	}
	if v.Len() != len(values) {
		t.Errorf("Len() = %d, want %d distinct entries", v.Len(), len(values))
	}
}

func TestResolveRejectsUnmintedPlaceholders(t *testing.T) {
	v := New()
	v.Tokenize("PERSON", "Priya")
	if _, ok := v.Resolve("[[AL:PERSON_9]]"); ok {
		t.Error("Resolve accepted a placeholder that was never minted")
	}
	if _, ok := v.Resolve("[[AL:GHOST_1]]"); ok {
		t.Error("Resolve accepted an unknown kind")
	}
}

func TestRedactionSentinelIsPreRegistered(t *testing.T) {
	v := New()
	got, ok := v.Resolve(Redacted)
	if !ok {
		t.Fatal("the redaction sentinel must resolve, not count as unknown")
	}
	if got != "[redacted]" {
		t.Errorf("Resolve(Redacted) = %q, want [redacted]", got)
	}
}

func TestPlaceholderFormatIsASCIIAndParseable(t *testing.T) {
	v := New()
	ph := v.Tokenize("CARD", "4111111111111111")

	if !strings.HasPrefix(ph, Open) || !strings.HasSuffix(ph, Close) {
		t.Fatalf("placeholder %q does not use the documented markers", ph)
	}
	if len(ph) > MaxPlaceholderLen {
		t.Errorf("placeholder %q exceeds MaxPlaceholderLen %d", ph, MaxPlaceholderLen)
	}
	for i := 0; i < len(ph); i++ {
		if ph[i] >= 0x80 {
			t.Fatalf("placeholder %q contains a non-ASCII byte; providers may re-encode it", ph)
		}
	}
}

func TestSummaryCountsPerKind(t *testing.T) {
	v := New()
	v.Tokenize("EMAIL", "a@x.com")
	v.Tokenize("EMAIL", "b@x.com")
	v.Tokenize("EMAIL", "a@x.com") // repeat, already counted
	v.Tokenize("CARD", "4111111111111111")

	got := v.Summary()
	if got["EMAIL"] != 2 || got["CARD"] != 1 {
		t.Errorf("Summary() = %v, want EMAIL:2 CARD:1", got)
	}
}

func TestConcurrentTokenizeIsConsistent(t *testing.T) {
	v := New()
	const workers, perWorker = 16, 100

	var wg sync.WaitGroup
	results := make([][]string, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			out := make([]string, perWorker)
			for i := 0; i < perWorker; i++ {
				out[i] = v.Tokenize("EMAIL", fmt.Sprintf("user%d@x.com", i))
			}
			results[w] = out
		}(w)
	}
	wg.Wait()

	// Every worker must have seen the same placeholder for the same value.
	for w := 1; w < workers; w++ {
		for i := 0; i < perWorker; i++ {
			if results[w][i] != results[0][i] {
				t.Fatalf("value %d: worker %d got %q, worker 0 got %q",
					i, w, results[w][i], results[0][i])
			}
		}
	}
	if v.Len() != perWorker {
		t.Errorf("Len() = %d, want %d", v.Len(), perWorker)
	}
}
