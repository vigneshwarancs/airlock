package detect

import (
	"fmt"
	"strings"
	"testing"
)

const samplePEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9OiJjRazXBZ1BjP5CE/Wm/Rr500P
RK+Lh9x5eJPo5CAZ3/ANBE0sTK0ZsDGMak2m1g7oruI3dY3VHqIxFTz0Ta1d+NAj
-----END RSA PRIVATE KEY-----`

const sampleJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
	"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

func scannerFor(t *testing.T, kinds ...Kind) *Scanner {
	t.Helper()
	s, err := NewScanner(kinds, nil, nil)
	if err != nil {
		t.Fatalf("NewScanner(%v): %v", kinds, err)
	}
	return s
}

func TestDetectorsFindExpectedValue(t *testing.T) {
	tests := []struct {
		name string
		kind Kind
		text string
		want string
	}{
		{"email", Email, "please mail priya.r@acme.co today", "priya.r@acme.co"},
		{"email with plus", Email, "to a.b+tag@sub.example.io.", "a.b+tag@sub.example.io"},
		{"card spaced", CreditCard, "card 4111 1111 1111 1111 on file", "4111 1111 1111 1111"},
		{"card bare", CreditCard, "pan 5500005555555559 ok", "5500005555555559"},
		{"card hyphenated", CreditCard, "use 4012-8888-8888-1881 now", "4012-8888-8888-1881"},
		{"iban", IBAN, "send to GB82WEST12345698765432 please", "GB82WEST12345698765432"},
		{"aadhaar spaced", Aadhaar, "uid 2345 6789 0124 verified", "2345 6789 0124"},
		{"aadhaar bare", Aadhaar, "uid 998877665548 verified", "998877665548"},
		{"pan", PAN, "pan ABCDE1234F filed", "ABCDE1234F"},
		{"aws key", AWSKey, "key=AKIAIOSFODNN7EXAMPLE rest", "AKIAIOSFODNN7EXAMPLE"},
		{"aws session key", AWSKey, "ASIAY34FZKBOKMUTVV7A here", "ASIAY34FZKBOKMUTVV7A"},
		{"github token", GitHubToken, "token ghp_" + strings.Repeat("a", 36) + " end", "ghp_" + strings.Repeat("a", 36)},
		{"slack token", SlackToken, "bot xoxb-1234567890-abcdefghijkl end", "xoxb-1234567890-abcdefghijkl"},
		{"anthropic key", APIKey, "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghij1234567890 x", "sk-ant-api03-abcdefghij1234567890"},
		{"jwt", JWT, "Authorization: Bearer " + sampleJWT, sampleJWT},
		{"private key", PrivateKey, "here it is:\n" + samplePEM + "\nthanks", samplePEM},
		{"ipv4", IPv4, "host 203.0.113.42 responded", "203.0.113.42"},
		{"phone local", Phone, "call 9876543210 now", "9876543210"},
		{"phone e164", Phone, "call +919876543210 now", "+919876543210"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := scannerFor(t, tc.kind).Scan(tc.text)
			if len(got) != 1 {
				t.Fatalf("got %d matches, want 1: %+v", len(got), got)
			}
			if got[0].Value != tc.want {
				t.Errorf("value = %q, want %q", got[0].Value, tc.want)
			}
			if got[0].Kind != tc.kind {
				t.Errorf("kind = %q, want %q", got[0].Kind, tc.kind)
			}
			// Offsets must slice the original string back to the value, or
			// right-to-left replacement in guard will corrupt the text.
			if slice := tc.text[got[0].Start:got[0].End]; slice != tc.want {
				t.Errorf("offsets slice %q, want %q", slice, tc.want)
			}
		})
	}
}

func TestDetectorsRejectNearMisses(t *testing.T) {
	tests := []struct {
		name string
		kind Kind
		text string
	}{
		{"card failing luhn", CreditCard, "card 4111111111111112 here"},
		{"card too short", CreditCard, "num 411111111111 here"},
		{"iban failing mod97", IBAN, "iban GB82WEST12345698765433 here"},
		{"aadhaar failing verhoeff", Aadhaar, "uid 234567890123 here"},
		{"aadhaar starting with 1", Aadhaar, "uid 123456789012 here"},
		{"jwt with non-json header", JWT, "token eyJhbGciXXXX.YWJjZGVm.Z2hpams here"},
		{"email without tld", Email, "write to foo@bar now"},
		{"loopback ip", IPv4, "bound to 127.0.0.1 locally"},
		{"unspecified ip", IPv4, "bound to 0.0.0.0 locally"},
		{"pan wrong shape", PAN, "pan ABCD12345F filed"},
		{"aws key wrong length", AWSKey, "key=AKIAIOSFODNN7EX rest"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scannerFor(t, tc.kind).Scan(tc.text); len(got) != 0 {
				t.Errorf("expected no match, got %+v", got)
			}
		})
	}
}

// TestAadhaarChecksumIsSelective is a property check: for any 11-digit
// prefix exactly one of the ten possible check digits may be accepted. If the
// Verhoeff tables were wrong this would fail for most prefixes.
func TestAadhaarChecksumIsSelective(t *testing.T) {
	prefixes := []string{"23456789012", "99887766554", "41234123412", "87654321098"}
	for _, p := range prefixes {
		accepted := 0
		for d := 0; d <= 9; d++ {
			if ValidAadhaar(fmt.Sprintf("%s%d", p, d)) {
				accepted++
			}
		}
		if accepted != 1 {
			t.Errorf("prefix %s: %d check digits accepted, want exactly 1", p, accepted)
		}
	}
}

func TestLuhnKnownVectors(t *testing.T) {
	valid := []string{"4111111111111111", "5500005555555559", "4012888888881881", "378282246310005"}
	invalid := []string{"4111111111111112", "1234567890123456", "0000000000000001"}
	for _, s := range valid {
		if !ValidLuhn(s) {
			t.Errorf("ValidLuhn(%s) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if ValidLuhn(s) {
			t.Errorf("ValidLuhn(%s) = true, want false", s)
		}
	}
}

func TestIBANKnownVectors(t *testing.T) {
	valid := []string{"GB82WEST12345698765432", "DE89370400440532013000", "FR1420041010050500013M02606"}
	for _, s := range valid {
		if !ValidIBAN(s) {
			t.Errorf("ValidIBAN(%s) = false, want true", s)
		}
	}
	if ValidIBAN("GB82WEST12345698765433") {
		t.Error("ValidIBAN accepted a corrupted IBAN")
	}
}

// TestPrivateKeyWinsOverEntropy is the overlap case that matters most: the
// base64 body of a PEM block is itself high entropy, and emitting two
// overlapping placeholders would corrupt the key.
func TestPrivateKeyWinsOverEntropy(t *testing.T) {
	s, err := NewScanner([]Kind{PrivateKey}, nil, &EntropyDetector{MinBits: 4.0, MinLen: 20})
	if err != nil {
		t.Fatal(err)
	}
	text := "key:\n" + samplePEM + "\n"
	got := s.Scan(text)
	if len(got) != 1 {
		t.Fatalf("got %d matches, want 1 covering the whole block: %+v", len(got), got)
	}
	if got[0].Kind != PrivateKey || got[0].Value != samplePEM {
		t.Errorf("got %s %q, want PRIVATE_KEY covering the full PEM", got[0].Kind, got[0].Value)
	}
}

func TestCustomDetectorOutranksBuiltinOnSameSpan(t *testing.T) {
	s, err := NewScanner([]Kind{Email}, []Custom{{Name: "corp_mail", Pattern: `priya\.r@acme\.co`}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := s.Scan("mail priya.r@acme.co now")
	if len(got) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(got), got)
	}
	if got[0].Kind != Kind("CORP_MAIL") {
		t.Errorf("kind = %q, want CORP_MAIL (custom priority should win)", got[0].Kind)
	}
}

func TestResolveOverlapsRules(t *testing.T) {
	prio := map[Kind]int{"HIGH": 90, "LOW": 10}
	tests := []struct {
		name string
		in   []Match
		want []Kind
	}{
		{
			name: "same start, higher priority wins",
			in:   []Match{{Kind: "LOW", Start: 0, End: 10}, {Kind: "HIGH", Start: 0, End: 10}},
			want: []Kind{"HIGH"},
		},
		{
			name: "earlier start claims the span",
			in:   []Match{{Kind: "HIGH", Start: 5, End: 9}, {Kind: "LOW", Start: 0, End: 8}},
			want: []Kind{"LOW"},
		},
		{
			name: "disjoint matches both survive, in order",
			in:   []Match{{Kind: "HIGH", Start: 10, End: 14}, {Kind: "LOW", Start: 0, End: 4}},
			want: []Kind{"LOW", "HIGH"},
		},
		{
			name: "same start, same priority, longer wins",
			in:   []Match{{Kind: "HIGH", Start: 0, End: 4}, {Kind: "HIGH", Start: 0, End: 9}},
			want: []Kind{"HIGH"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveOverlaps(tc.in, prio)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d matches, want %d: %+v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i].Kind != tc.want[i] {
					t.Errorf("match %d kind = %q, want %q", i, got[i].Kind, tc.want[i])
				}
				if i > 0 && got[i].Start < got[i-1].End {
					t.Errorf("match %d overlaps its predecessor", i)
				}
			}
		})
	}
}

func TestScanReturnsNonOverlappingAscendingMatches(t *testing.T) {
	s := scannerFor(t, AllKinds()...)
	text := "mail a@b.com and c@d.org, card 4111 1111 1111 1111, host 203.0.113.42"
	got := s.Scan(text)
	if len(got) < 4 {
		t.Fatalf("expected at least 4 matches, got %d: %+v", len(got), got)
	}
	for i := 1; i < len(got); i++ {
		if got[i].Start < got[i-1].End {
			t.Errorf("match %d (%s@%d) overlaps match %d (%s ends %d)",
				i, got[i].Kind, got[i].Start, i-1, got[i-1].Kind, got[i-1].End)
		}
	}
}

func TestEmptyAndCleanTextProduceNoMatches(t *testing.T) {
	s := scannerFor(t, AllKinds()...)
	for _, text := range []string{"", "   ", "func main() { fmt.Println(\"hello\") }", "the quick brown fox"} {
		if got := s.Scan(text); len(got) != 0 {
			t.Errorf("Scan(%q) = %+v, want no matches", text, got)
		}
	}
}

func TestNewScannerRejectsBadConfiguration(t *testing.T) {
	if _, err := NewScanner([]Kind{"NOT_A_DETECTOR"}, nil, nil); err == nil {
		t.Error("expected an error for an unknown detector kind")
	}
	if _, err := NewScanner(nil, []Custom{{Name: "bad", Pattern: "([unclosed"}}, nil); err == nil {
		t.Error("expected an error for an uncompilable custom pattern")
	}
	if _, err := NewScanner([]Kind{Email, Email}, nil, nil); err != nil {
		t.Errorf("duplicate kinds should be tolerated, got %v", err)
	}
}

func TestEntropyDetectorIgnoresSingleClassRuns(t *testing.T) {
	e := &EntropyDetector{MinBits: 3.5, MinLen: 20}
	// Hex digests and SCREAMING_SNAKE constants clear the entropy bar but are
	// not secrets; the charset-mixing gate is what excludes them.
	for _, s := range []string{
		"a3f5c9d2b8e1a4f7c0d3b6e9a2f5c8d1",
		"SOME_VERY_LONG_CONSTANT_NAME_HERE",
		"111111111111111111111111111111",
	} {
		if got := e.Find(s); len(got) != 0 {
			t.Errorf("entropy detector matched %q, want no match", s)
		}
	}
	secret := "hT8xQ2vLp9ZmR4wK7nB1sD6yF3jA5gC0"
	if got := e.Find("token=" + secret); len(got) != 1 || got[0].Value != secret {
		t.Errorf("entropy detector missed a mixed-charset secret: %+v", got)
	}
}
