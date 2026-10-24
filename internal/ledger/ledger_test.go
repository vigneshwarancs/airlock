package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempLedger(t *testing.T) (*Ledger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sub", "ledger.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

func sampleEvent(id string) Event {
	return Event{
		RequestID: id,
		Provider:  "anthropic",
		Model:     "claude-opus-5",
		Path:      "/v1/messages",
		Outcome:   "forwarded",
		Detections: map[string]map[string]int{
			"tokenize": {"EMAIL": 2, "CARD": 1},
		},
		Placeholders: map[string]int{"EMAIL": 2, "CARD": 1},
		BytesIn:      1024,
		BytesOut:     2048,
	}
}

func TestAppendBuildsAChain(t *testing.T) {
	l, path := tempLedger(t)

	var prev string
	for i := 1; i <= 3; i++ {
		rec, err := l.Append(sampleEvent("req" + string(rune('0'+i))))
		if err != nil {
			t.Fatal(err)
		}
		if rec.Seq != int64(i) {
			t.Errorf("record %d has seq %d", i, rec.Seq)
		}
		if i == 1 && rec.PrevHash != GenesisHash {
			t.Errorf("first record prev_hash = %q, want genesis", rec.PrevHash)
		}
		if i > 1 && rec.PrevHash != prev {
			t.Errorf("record %d prev_hash does not match the previous hash", i)
		}
		if rec.Hash == "" || rec.Hash == rec.PrevHash {
			t.Errorf("record %d has a degenerate hash", i)
		}
		prev = rec.Hash
	}

	n, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if n != 3 {
		t.Errorf("verified %d records, want 3", n)
	}
}

func TestReopenContinuesTheChain(t *testing.T) {
	l, path := tempLedger(t)
	if _, err := l.Append(sampleEvent("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(sampleEvent("b")); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// A restart must not reset the sequence or orphan the chain.
	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()

	rec, err := l2.Append(sampleEvent("c"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Seq != 3 {
		t.Errorf("seq after reopen = %d, want 3", rec.Seq)
	}
	if n, err := Verify(path); err != nil || n != 3 {
		t.Errorf("Verify after reopen = (%d, %v), want (3, nil)", n, err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(lines []string) []string
		wantErr string
	}{
		{
			name: "edited payload",
			corrupt: func(lines []string) []string {
				lines[1] = strings.Replace(lines[1], `"bytes_in":1024`, `"bytes_in":1`, 1)
				return lines
			},
			wantErr: "does not match its hash",
		},
		{
			name: "deleted middle record",
			corrupt: func(lines []string) []string {
				return append(lines[:1], lines[2:]...)
			},
			wantErr: "seq",
		},
		{
			name: "reordered records",
			corrupt: func(lines []string) []string {
				lines[0], lines[1] = lines[1], lines[0]
				return lines
			},
			wantErr: "seq",
		},
		{
			name: "forged hash",
			corrupt: func(lines []string) []string {
				lines[2] = strings.Replace(lines[2], `"outcome":"forwarded"`, `"outcome":"blocked"`, 1)
				return lines
			},
			wantErr: "does not match its hash",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, path := tempLedger(t)
			for _, id := range []string{"a", "b", "c"} {
				if _, err := l.Append(sampleEvent(id)); err != nil {
					t.Fatal(err)
				}
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
			if len(lines) != 3 {
				t.Fatalf("expected 3 lines, got %d", len(lines))
			}
			lines = tc.corrupt(lines)
			if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err = Verify(path)
			if err == nil {
				t.Fatal("Verify accepted a tampered ledger")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyReportsHowFarItGot(t *testing.T) {
	l, path := tempLedger(t)
	for _, id := range []string{"a", "b", "c", "d"} {
		if _, err := l.Append(sampleEvent(id)); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	lines[2] = strings.Replace(lines[2], `"bytes_out":2048`, `"bytes_out":7`, 1)
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	n, err := Verify(path)
	if err == nil {
		t.Fatal("expected a verification failure")
	}
	if n != 2 {
		t.Errorf("verified %d records before the break, want 2", n)
	}
}

func TestVerifyEmptyAndMissingLedgers(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "absent.jsonl")
	if n, err := Verify(missing); err != nil || n != 0 {
		t.Errorf("Verify(missing) = (%d, %v), want (0, nil)", n, err)
	}

	empty := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := Verify(empty); err != nil || n != 0 {
		t.Errorf("Verify(empty) = (%d, %v), want (0, nil)", n, err)
	}
}

func TestReadRoundTripsEvents(t *testing.T) {
	l, path := tempLedger(t)
	want := sampleEvent("abc123")
	if _, err := l.Append(want); err != nil {
		t.Fatal(err)
	}
	l.Close()

	recs, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("read %d records, want 1", len(recs))
	}
	got := recs[0].Event
	if got.RequestID != want.RequestID || got.Model != want.Model || got.BytesIn != want.BytesIn {
		t.Errorf("event did not round trip: %+v", got)
	}
	if got.Detections["tokenize"]["EMAIL"] != 2 {
		t.Errorf("detections did not round trip: %+v", got.Detections)
	}
}

// TestLedgerStoresNoPayloads is the privacy property: the ledger must be
// safe to keep, which means it records hashes and counts, never content.
func TestLedgerStoresNoPayloads(t *testing.T) {
	l, path := tempLedger(t)

	secret := "priya.r@acme.co"
	ev := sampleEvent("x")
	ev.RequestSHA256 = SHA256([]byte("prompt mentioning " + secret))
	ev.ResponseSHA256 = SHA256([]byte("reply mentioning " + secret))
	if _, err := l.Append(ev); err != nil {
		t.Fatal(err)
	}
	l.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Error("the ledger contains a plaintext value; it must store hashes only")
	}
	if !strings.Contains(string(raw), ev.RequestSHA256) {
		t.Error("the request hash was not recorded")
	}
}

func TestSHA256IsStable(t *testing.T) {
	a := SHA256([]byte("hello"))
	if a != SHA256([]byte("hello")) {
		t.Error("SHA256 is not deterministic")
	}
	if a == SHA256([]byte("hellp")) {
		t.Error("SHA256 collided on different inputs")
	}
	if len(a) != 64 {
		t.Errorf("digest length = %d, want 64 hex chars", len(a))
	}
}

func TestCorruptLineIsReportedOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	if err := os.WriteFile(path, []byte("this is not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Error("Open must refuse a ledger it cannot parse rather than silently restarting the chain")
	}
}
