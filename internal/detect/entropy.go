package detect

import (
	"math"
	"regexp"
	"strings"
)

// EntropyDetector catches credentials that no prefix or checksum can describe:
// random API tokens, generated passwords, base64 secrets. It is high-recall
// and genuinely noisy, which is why policy has to enable it explicitly.
type EntropyDetector struct {
	MinBits float64 // Shannon bits per character, typically ~4.0-4.5
	MinLen  int
}

// entropyCandidate allows '=' only as trailing base64 padding. Including it
// in the leading class would swallow the assignment in `token=<secret>` and
// tokenize the variable name along with the value.
var entropyCandidate = regexp.MustCompile(`[A-Za-z0-9+/_\-]{20,}={0,2}`)

func (e *EntropyDetector) Kind() Kind    { return Secret }
func (e *EntropyDetector) Priority() int { return 10 }

func (e *EntropyDetector) Find(s string) []Match {
	minLen := e.MinLen
	if minLen <= 0 {
		minLen = 20
	}
	var out []Match
	for _, loc := range entropyCandidate.FindAllStringIndex(s, -1) {
		val := s[loc[0]:loc[1]]
		if len(val) < minLen || !mixedCharset(val) {
			continue
		}
		if shannonBits(val) < e.MinBits {
			continue
		}
		out = append(out, Match{Kind: Secret, Start: loc[0], End: loc[1], Value: val})
	}
	return out
}

// mixedCharset rejects long runs of a single class — hex digests, decimal
// IDs, and SCREAMING_SNAKE identifiers clear the entropy bar but are rarely
// secrets.
func mixedCharset(s string) bool {
	var lower, upper, digit bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	classes := 0
	for _, ok := range []bool{lower, upper, digit} {
		if ok {
			classes++
		}
	}
	return classes >= 3 && !strings.ContainsAny(s, " \t")
}

func shannonBits(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}
