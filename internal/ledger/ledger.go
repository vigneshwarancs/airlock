// Package ledger is a tamper-evident, append-only record of what crossed the
// boundary.
//
// Each line is a JSON record whose hash commits to the previous record's
// hash, so any edit, reorder, or deletion in the middle of the file breaks
// every hash after it. `airlock verify` walks the chain and reports the first
// sequence number that fails.
package ledger

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// GenesisHash is the prev_hash of the first record.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Event is the payload of one ledger record. It is designed so that the
// ledger is useful without being a second copy of your data: counts, hashes,
// and sizes — not prompts.
type Event struct {
	RequestID string `json:"request_id"`
	Provider  string `json:"provider"`
	Model     string `json:"model,omitempty"`
	Path      string `json:"path"`
	Stream    bool   `json:"stream"`

	// Outcome is "forwarded", "blocked", or "error".
	Outcome    string `json:"outcome"`
	StatusCode int    `json:"status_code,omitempty"`

	// Detections maps action -> detector kind -> count.
	Detections   map[string]map[string]int `json:"detections,omitempty"`
	Placeholders map[string]int            `json:"placeholders,omitempty"`

	// UnknownPlaceholders records placeholders the model invented. Non-empty
	// means the response referenced a value that was never minted.
	UnknownPlaceholders []string `json:"unknown_placeholders,omitempty"`

	BytesIn    int64 `json:"bytes_in"`
	BytesOut   int64 `json:"bytes_out"`
	DurationMS int64 `json:"duration_ms"`

	// Hashes of the sanitized request and the upstream response, so you can
	// prove what was sent without storing it.
	RequestSHA256  string `json:"request_sha256,omitempty"`
	ResponseSHA256 string `json:"response_sha256,omitempty"`

	Error string `json:"error,omitempty"`
}

// Record is one line of the ledger.
type Record struct {
	Seq      int64  `json:"seq"`
	TS       string `json:"ts"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
	Event    Event  `json:"event"`
}

// Ledger appends records under a mutex. A single process owns the file.
type Ledger struct {
	mu   sync.Mutex
	f    *os.File
	path string
	seq  int64
	prev string
	now  func() time.Time
}

// Open creates or resumes a ledger, continuing the existing hash chain.
func Open(path string) (*Ledger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("ledger dir: %w", err)
	}
	seq, prev, err := lastState(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open ledger: %w", err)
	}
	return &Ledger{f: f, path: path, seq: seq, prev: prev, now: time.Now}, nil
}

// Append writes one record and returns it.
func (l *Ledger) Append(ev Event) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	rec := Record{
		Seq:      l.seq + 1,
		TS:       l.now().UTC().Format(time.RFC3339Nano),
		PrevHash: l.prev,
		Event:    ev,
	}
	h, err := hashRecord(rec)
	if err != nil {
		return Record{}, err
	}
	rec.Hash = h

	line, err := json.Marshal(rec)
	if err != nil {
		return Record{}, err
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return Record{}, fmt.Errorf("append ledger: %w", err)
	}
	l.seq, l.prev = rec.Seq, rec.Hash
	return rec, nil
}

func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// hashRecord commits to the sequence, timestamp, previous hash, and the
// canonical encoding of the event. encoding/json sorts map keys and emits
// struct fields in declaration order, so this is stable across runs.
func hashRecord(r Record) (string, error) {
	body, err := json.Marshal(r.Event)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	fmt.Fprintf(h, "%d\n%s\n%s\n", r.Seq, r.TS, r.PrevHash)
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func lastState(path string) (int64, string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, GenesisHash, nil
	}
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	var seq int64
	prev := GenesisHash
	sc := newScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return 0, "", fmt.Errorf("ledger line %d is corrupt: %w", seq+1, err)
		}
		seq, prev = r.Seq, r.Hash
	}
	if err := sc.Err(); err != nil {
		return 0, "", err
	}
	return seq, prev, nil
}

// Read loads every record in the ledger.
func Read(path string) ([]Record, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Record
	sc := newScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("corrupt ledger line: %w", err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// Verify walks the chain and returns the number of records checked, or an
// error naming the first record that fails.
func Verify(path string) (int, error) {
	recs, err := Read(path)
	if err != nil {
		return 0, err
	}
	prev := GenesisHash
	var expect int64 = 1
	for i, r := range recs {
		if r.Seq != expect {
			return i, fmt.Errorf("record %d: expected seq %d, found %d (record inserted or removed)", i+1, expect, r.Seq)
		}
		if r.PrevHash != prev {
			return i, fmt.Errorf("seq %d: prev_hash does not match seq %d (chain broken)", r.Seq, r.Seq-1)
		}
		want, err := hashRecord(r)
		if err != nil {
			return i, err
		}
		if want != r.Hash {
			return i, fmt.Errorf("seq %d: content does not match its hash (record was modified)", r.Seq)
		}
		prev = r.Hash
		expect++
	}
	return len(recs), nil
}

func newScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	return sc
}

// SHA256 returns the hex digest of b, for recording payload identity without
// recording the payload.
func SHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
