package jsonwalk

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMapStringsTransformsContentLeaves(t *testing.T) {
	raw := []byte(`{"model":"claude-opus-5","messages":[{"role":"user","content":"hello"}]}`)

	out, err := MapStrings(raw, func(_, v string) string { return strings.ToUpper(v) })
	if err != nil {
		t.Fatal(err)
	}

	var got struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got.Messages[0].Content != "HELLO" {
		t.Errorf("content = %q, want HELLO", got.Messages[0].Content)
	}
	// Structural fields must survive untouched or the request breaks.
	if got.Model != "claude-opus-5" {
		t.Errorf("model = %q, want it unchanged", got.Model)
	}
	if got.Messages[0].Role != "user" {
		t.Errorf("role = %q, want it unchanged", got.Messages[0].Role)
	}
}

func TestSkipKeysAreNeverRewritten(t *testing.T) {
	raw := []byte(`{
      "model":"m","role":"user","type":"text","id":"msg_1",
      "tool_use_id":"tu_1","stop_reason":"end_turn","media_type":"image/png",
      "name":"Read","data":"aGVsbG8=","content":"rewrite me"
    }`)

	out, err := MapStrings(raw, func(_, v string) string { return "XXX" })
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"model", "role", "type", "id", "tool_use_id", "stop_reason", "media_type", "name", "data"} {
		if got[k] == "XXX" {
			t.Errorf("key %q was rewritten but is structural", k)
		}
	}
	if got["content"] != "XXX" {
		t.Errorf("content was not rewritten, got %v", got["content"])
	}
}

// TestToolCallArgumentsAreRewritten covers the case that makes the proxy
// useful: a sensitive value nested inside a tool call's arguments.
func TestToolCallArgumentsAreRewritten(t *testing.T) {
	raw := []byte(`{
      "content":[{
        "type":"tool_use","id":"tu_1","name":"send_email",
        "input":{"to":"priya@acme.co","subject":"hi","cc":["a@x.com","b@x.com"]}
      }]
    }`)

	var seen []string
	out, err := MapStrings(raw, func(_, v string) string {
		seen = append(seen, v)
		if strings.Contains(v, "@") {
			return "REDACTED"
		}
		return v
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "priya@acme.co") {
		t.Error("nested tool argument was not rewritten")
	}
	if strings.Contains(string(out), "a@x.com") || strings.Contains(string(out), "b@x.com") {
		t.Error("strings inside a nested array were not rewritten")
	}
	if !strings.Contains(string(out), `"name":"send_email"`) {
		t.Error("tool name should be preserved")
	}
	if len(seen) != 4 { // to, subject, cc[0], cc[1]
		t.Errorf("visited %d leaves (%v), want 4", len(seen), seen)
	}
}

// TestNumbersSurviveRoundTrip guards against encoding/json turning large
// integers into scientific notation, which would corrupt max_tokens.
func TestNumbersSurviveRoundTrip(t *testing.T) {
	raw := []byte(`{"max_tokens":1000000,"temperature":0.7,"top_k":40,"big":12345678901234567890}`)

	out, err := MapStrings(raw, func(_, v string) string { return v })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"1000000", "0.7", "40", "12345678901234567890"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("number %s was reformatted; got %s", want, out)
		}
	}
}

func TestNonStringLeavesArePreserved(t *testing.T) {
	raw := []byte(`{"stream":true,"stop":null,"tools":[],"meta":{}}`)
	out, err := MapStrings(raw, func(_, v string) string { return "XXX" })
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["stream"] != true {
		t.Errorf("stream = %v, want true", got["stream"])
	}
	if got["stop"] != nil {
		t.Errorf("stop = %v, want nil", got["stop"])
	}
}

func TestInvalidJSONIsReportedNotSwallowed(t *testing.T) {
	if _, err := MapStrings([]byte(`{"broken":`), func(_, v string) string { return v }); err == nil {
		t.Error("expected an error for malformed JSON")
	}
}

func TestHTMLCharactersAreNotEscaped(t *testing.T) {
	// SetEscapeHTML(false) matters: < in a prompt would change the
	// bytes the model sees and break byte-for-byte comparisons.
	raw := []byte(`{"content":"if a < b && c > d"}`)
	out, err := MapStrings(raw, func(_, v string) string { return v })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "a < b && c > d") {
		t.Errorf("HTML characters were escaped: %s", out)
	}
}

func TestStringsCollectsLeavesWithoutMutating(t *testing.T) {
	raw := []byte(`{"role":"user","content":"one","extra":{"deep":"two"}}`)
	got, err := Strings(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("Strings() = %v, want 2 leaves", got)
	}
}
