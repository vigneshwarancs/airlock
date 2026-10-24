// Package detect finds sensitive values inside free text.
//
// Detectors are deliberately layered by confidence. Checksum-validated
// detectors (card, IBAN, Aadhaar) and prefix-anchored credential detectors
// (AWS, GitHub, Slack) have near-zero false-positive rates and are enabled by
// default. The entropy detector is high-recall but noisy, so policy must opt
// into it explicitly.
package detect

import (
	"fmt"
	"regexp"
	"sort"
)

// Kind identifies what a detector matched. It becomes the placeholder prefix,
// so it must stay [A-Z0-9_]+.
type Kind string

const (
	Email       Kind = "EMAIL"
	Phone       Kind = "PHONE"
	CreditCard  Kind = "CARD"
	IBAN        Kind = "IBAN"
	AWSKey      Kind = "AWS_KEY"
	PrivateKey  Kind = "PRIVATE_KEY"
	JWT         Kind = "JWT"
	GitHubToken Kind = "GITHUB_TOKEN"
	SlackToken  Kind = "SLACK_TOKEN"
	APIKey      Kind = "API_KEY"
	Aadhaar     Kind = "AADHAAR"
	PAN         Kind = "PAN"
	IPv4        Kind = "IP"
	Secret      Kind = "SECRET"
)

// Match is a detected span within a single string. Start and End are byte
// offsets, half-open, so s[Start:End] == Value.
type Match struct {
	Kind  Kind
	Start int
	End   int
	Value string
}

// Detector finds matches of a single Kind.
type Detector interface {
	Kind() Kind
	// Priority breaks overlaps: higher wins. A 16-digit card and a 10-digit
	// phone can match the same span, and the card is the better answer.
	Priority() int
	Find(s string) []Match
}

// regexDetector covers every builtin except entropy. validate, when non-nil,
// is a second gate applied to the captured value — this is what keeps the
// false-positive rate low enough to tokenize without asking the user.
type regexDetector struct {
	kind     Kind
	re       *regexp.Regexp
	priority int
	group    int // capture group holding the value; 0 means the whole match
	validate func(string) bool
}

func (d *regexDetector) Kind() Kind    { return d.kind }
func (d *regexDetector) Priority() int { return d.priority }

func (d *regexDetector) Find(s string) []Match {
	idx := d.re.FindAllStringSubmatchIndex(s, -1)
	if idx == nil {
		return nil
	}
	out := make([]Match, 0, len(idx))
	for _, loc := range idx {
		g := d.group * 2
		if g+1 >= len(loc) || loc[g] < 0 {
			continue
		}
		start, end := loc[g], loc[g+1]
		val := s[start:end]
		if d.validate != nil && !d.validate(val) {
			continue
		}
		out = append(out, Match{Kind: d.kind, Start: start, End: end, Value: val})
	}
	return out
}

// builtins is the default detector set, keyed by Kind so policy can name them.
var builtins = map[Kind]Detector{
	PrivateKey: &regexDetector{
		kind:     PrivateKey,
		priority: 100,
		re: regexp.MustCompile(
			`(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`),
	},
	JWT: &regexDetector{
		kind:     JWT,
		priority: 90,
		re:       regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]*`),
		validate: validJWT,
	},
	AWSKey: &regexDetector{
		kind:     AWSKey,
		priority: 90,
		re:       regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}\b`),
	},
	GitHubToken: &regexDetector{
		kind:     GitHubToken,
		priority: 90,
		re:       regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,251}\b`),
	},
	SlackToken: &regexDetector{
		kind:     SlackToken,
		priority: 90,
		re:       regexp.MustCompile(`\bxox[baprse]-[A-Za-z0-9\-]{10,}\b`),
	},
	APIKey: &regexDetector{
		kind:     APIKey,
		priority: 85,
		re:       regexp.MustCompile(`\bsk-(?:ant-)?[A-Za-z0-9_\-]{20,}\b`),
	},
	IBAN: &regexDetector{
		kind:     IBAN,
		priority: 80,
		re:       regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b`),
		validate: ValidIBAN,
	},
	CreditCard: &regexDetector{
		kind:     CreditCard,
		priority: 70,
		re:       regexp.MustCompile(`\b[0-9](?:[ -]?[0-9]){12,18}\b`),
		validate: ValidLuhn,
	},
	Aadhaar: &regexDetector{
		kind:     Aadhaar,
		priority: 75,
		re:       regexp.MustCompile(`\b[2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}\b`),
		validate: ValidAadhaar,
	},
	PAN: &regexDetector{
		kind:     PAN,
		priority: 60,
		re:       regexp.MustCompile(`\b[A-Z]{5}[0-9]{4}[A-Z]\b`),
	},
	Email: &regexDetector{
		kind:     Email,
		priority: 50,
		re:       regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b`),
	},
	Phone: &regexDetector{
		kind:     Phone,
		priority: 30,
		re:       regexp.MustCompile(`(?:\+[0-9]{1,3}[ \-]?)?\b[6-9][0-9]{9}\b|\+[0-9]{1,3}[ \-]?[0-9]{6,12}\b`),
	},
	IPv4: &regexDetector{
		kind:     IPv4,
		priority: 20,
		re:       regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b`),
		validate: nonTrivialIP,
	},
}

// DefaultKinds is the detector set `airlock init` writes into a fresh policy.
// Phone and IP are omitted: both are high-recall and low-harm, and turning
// them on by default produces noisy placeholders in ordinary source code.
var DefaultKinds = []Kind{
	PrivateKey, JWT, AWSKey, GitHubToken, SlackToken, APIKey,
	IBAN, CreditCard, Aadhaar, PAN, Email,
}

// AllKinds lists every builtin Kind, in stable order.
func AllKinds() []Kind {
	out := make([]Kind, 0, len(builtins))
	for k := range builtins {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Custom describes a user-supplied regex detector from policy.
type Custom struct {
	Name    string
	Pattern string
}

// Scanner holds a compiled, ordered detector set.
type Scanner struct {
	detectors []Detector
}

// NewScanner builds a Scanner from builtin kind names plus any custom
// patterns. Unknown kinds are an error rather than a silent no-op: a typo in
// a security policy must not quietly disable a detector.
func NewScanner(kinds []Kind, custom []Custom, entropy *EntropyDetector) (*Scanner, error) {
	s := &Scanner{}
	seen := map[Kind]bool{}
	for _, k := range kinds {
		d, ok := builtins[k]
		if !ok {
			return nil, fmt.Errorf("unknown detector %q (known: %v)", k, AllKinds())
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		s.detectors = append(s.detectors, d)
	}
	for _, c := range custom {
		re, err := regexp.Compile(c.Pattern)
		if err != nil {
			return nil, fmt.Errorf("custom detector %q: %w", c.Name, err)
		}
		kind := Kind(normalizeKind(c.Name))
		if kind == "" {
			return nil, fmt.Errorf("custom detector name %q is empty after normalization", c.Name)
		}
		s.detectors = append(s.detectors, &regexDetector{kind: kind, re: re, priority: 95})
	}
	if entropy != nil {
		s.detectors = append(s.detectors, entropy)
	}
	return s, nil
}

var nonKindChar = regexp.MustCompile(`[^A-Z0-9_]+`)

func normalizeKind(s string) string {
	up := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			up = append(up, c-32)
		default:
			up = append(up, c)
		}
	}
	return string(nonKindChar.ReplaceAll(up, []byte("_")))
}

// Scan returns non-overlapping matches in ascending Start order.
func (s *Scanner) Scan(text string) []Match {
	var all []Match
	for _, d := range s.detectors {
		all = append(all, d.Find(text)...)
	}
	return resolveOverlaps(all, s.priorities())
}

func (s *Scanner) priorities() map[Kind]int {
	p := make(map[Kind]int, len(s.detectors))
	for _, d := range s.detectors {
		p[d.Kind()] = d.Priority()
	}
	return p
}

// resolveOverlaps keeps the strongest claim on each span. Sorting by start,
// then priority, then length means a greedy left-to-right sweep picks the
// card over the phone number and the whole PEM block over the base64 inside
// it.
func resolveOverlaps(all []Match, prio map[Kind]int) []Match {
	if len(all) == 0 {
		return nil
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		if prio[a.Kind] != prio[b.Kind] {
			return prio[a.Kind] > prio[b.Kind]
		}
		if a.End != b.End {
			return a.End > b.End
		}
		return a.Kind < b.Kind
	})
	out := make([]Match, 0, len(all))
	end := -1
	for _, m := range all {
		if m.Start < end {
			continue
		}
		out = append(out, m)
		end = m.End
	}
	return out
}
