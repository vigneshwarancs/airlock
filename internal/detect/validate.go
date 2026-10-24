package detect

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
)

// ValidLuhn reports whether s passes the Luhn checksum after separators are
// stripped. This is what turns a greedy 13-19 digit regex into a card
// detector you can trust.
func ValidLuhn(s string) bool {
	digits := onlyDigits(s)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// ValidIBAN applies the ISO 13616 mod-97 check.
func ValidIBAN(s string) bool {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(s))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	// Rotate the first four characters to the end, then expand letters to
	// their two-digit values and require the whole number ≡ 1 (mod 97).
	rotated := s[4:] + s[:4]
	rem := 0
	for i := 0; i < len(rotated); i++ {
		c := rotated[i]
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			v := int(c-'A') + 10
			rem = (rem*100 + v) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// Verhoeff tables, used by Aadhaar's trailing check digit.
var verhoeffD = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

var verhoeffP = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

// ValidAadhaar checks the 12-digit format and its Verhoeff check digit.
func ValidAadhaar(s string) bool {
	digits := onlyDigits(s)
	if len(digits) != 12 || digits[0] < '2' {
		return false
	}
	c, p := 0, 0
	for i := len(digits) - 1; i >= 0; i-- {
		c = verhoeffD[c][verhoeffP[p%8][int(digits[i]-'0')]]
		p++
	}
	return c == 0
}

// validJWT requires the header segment to decode to JSON carrying an "alg"
// claim, which rules out ordinary dotted base64-ish strings.
func validJWT(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var hdr map[string]any
	if json.Unmarshal(raw, &hdr) != nil {
		return false
	}
	_, ok := hdr["alg"]
	return ok
}

// nonTrivialIP drops addresses that carry no identifying information.
func nonTrivialIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return !ip.IsLoopback() && !ip.IsUnspecified() && s != "255.255.255.255"
}

func onlyDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
