package proxy

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigneshwarancs/airlock/internal/ledger"
	"github.com/vigneshwarancs/airlock/internal/policy"
	"github.com/vigneshwarancs/airlock/internal/rewrite"
	"github.com/vigneshwarancs/airlock/internal/vault"
)

const pemKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9OiJjRazXBZ1BjP5CE/Wm/Rr500P
-----END RSA PRIVATE KEY-----`

type gateway struct {
	url        string
	ledgerPath string
}

// newGateway wires a real Airlock in front of a fake upstream.
func newGateway(t *testing.T, upstream http.HandlerFunc, mutate func(*policy.Policy)) *gateway {
	t.Helper()

	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)

	pol := policy.Default()
	pol.Upstream = map[string]string{"anthropic": up.URL, "openai": up.URL}
	pol.Ledger.Path = filepath.Join(t.TempDir(), "ledger.jsonl")
	if mutate != nil {
		mutate(pol)
	}
	if err := pol.Validate(); err != nil {
		t.Fatalf("test policy is invalid: %v", err)
	}

	led, err := ledger.Open(pol.LedgerPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })

	srv, err := New(pol, led, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(srv.Handler())
	t.Cleanup(gw.Close)

	return &gateway{url: gw.URL, ledgerPath: pol.LedgerPath()}
}

func (g *gateway) post(t *testing.T, path, body string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, g.url+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (g *gateway) records(t *testing.T) []ledger.Record {
	t.Helper()
	recs, err := ledger.Read(g.ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// ---------------------------------------------------------------- non-stream

func TestRoundTripTokenizesOutboundAndRestoresInbound(t *testing.T) {
	var sentUpstream string
	gw := newGateway(t, func(w http.ResponseWriter, r *http.Request) {
		sentUpstream = readAll(t, r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant",`+
			`"content":[{"type":"text","text":"Emailed [[AL:EMAIL_1]] about order AC-88412."}]}`)
	}, nil)

	resp := gw.post(t, "/v1/messages",
		`{"model":"claude-opus-5","messages":[{"role":"user","content":"mail priya.r@acme.co about it"}]}`, nil)
	body := readAll(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	// What actually left the machine.
	if strings.Contains(sentUpstream, "priya.r@acme.co") {
		t.Error("the real address was sent upstream")
	}
	if !strings.Contains(sentUpstream, "[[AL:EMAIL_1]]") {
		t.Errorf("expected a placeholder upstream, got %s", sentUpstream)
	}
	if !strings.Contains(sentUpstream, `"model":"claude-opus-5"`) {
		t.Error("the model field was altered")
	}

	// What the agent got back.
	if !strings.Contains(body, "priya.r@acme.co") {
		t.Errorf("the response was not rehydrated: %s", body)
	}
	if strings.Contains(body, "[[AL:") {
		t.Errorf("a placeholder leaked to the client: %s", body)
	}
}

func TestBlockedRequestNeverReachesUpstream(t *testing.T) {
	called := false
	gw := newGateway(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		io.WriteString(w, `{}`)
	}, nil)

	payload, err := json.Marshal(map[string]any{
		"model":    "claude-opus-5",
		"messages": []any{map[string]any{"role": "user", "content": "deploy with\n" + pemKey}},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp := gw.post(t, "/v1/messages", string(payload), nil)
	body := readAll(t, resp.Body)

	if called {
		t.Fatal("a blocked request was forwarded upstream")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if !strings.Contains(body, "PRIVATE_KEY") {
		t.Errorf("the error should name what was detected: %s", body)
	}
	// The refusal must be shaped like a provider error so SDKs surface it.
	var errResp struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &errResp); err != nil {
		t.Fatalf("error body is not JSON: %v", err)
	}
	if errResp.Type != "error" || errResp.Error.Message == "" {
		t.Errorf("unexpected error shape: %s", body)
	}

	recs := gw.records(t)
	if len(recs) != 1 || recs[0].Event.Outcome != "blocked" {
		t.Errorf("expected one blocked ledger record, got %+v", recs)
	}
}

func TestOpenAIErrorShapeOnBlock(t *testing.T) {
	gw := newGateway(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}, nil)

	payload, _ := json.Marshal(map[string]any{
		"model":    "gpt-x",
		"messages": []any{map[string]any{"role": "user", "content": pemKey}},
	})
	resp := gw.post(t, "/v1/chat/completions", string(payload), nil)
	body := readAll(t, resp.Body)

	var errResp struct {
		Error struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &errResp); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if errResp.Error.Code != "airlock_blocked" {
		t.Errorf("code = %q, want airlock_blocked (OpenAI error shape)", errResp.Error.Code)
	}
}

func TestCredentialsAndHeadersReachUpstream(t *testing.T) {
	var gotAuth, gotVersion, gotEncoding string
	gw := newGateway(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		gotEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "upstream-123")
		io.WriteString(w, `{"ok":true}`)
	}, nil)

	resp := gw.post(t, "/v1/messages", `{"model":"m","messages":[]}`, map[string]string{
		"x-api-key":         "sk-test-key",
		"anthropic-version": "2023-06-01",
	})
	readAll(t, resp.Body)

	if gotAuth != "sk-test-key" {
		t.Errorf("x-api-key = %q, want it forwarded unchanged", gotAuth)
	}
	if gotVersion != "2023-06-01" {
		t.Errorf("anthropic-version = %q, want it forwarded", gotVersion)
	}
	// Compressed upstream responses would defeat rehydration.
	if gotEncoding != "identity" {
		t.Errorf("Accept-Encoding = %q, want identity", gotEncoding)
	}
	if resp.Header.Get("X-Request-Id") != "upstream-123" {
		t.Error("upstream response headers should be passed back")
	}
}

func TestNonJSONRequestsPassThrough(t *testing.T) {
	gw := newGateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":[{"id":"claude-opus-5"}]}`)
	}, nil)

	resp, err := http.Get(gw.url + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(readAll(t, resp.Body), "claude-opus-5") {
		t.Error("model listing did not pass through")
	}
}

func TestUpstreamErrorBodyIsRelayed(t *testing.T) {
	gw := newGateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`)
	}, nil)

	resp := gw.post(t, "/v1/messages", `{"model":"m","messages":[]}`, nil)
	body := readAll(t, resp.Body)

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want the upstream 429 preserved", resp.StatusCode)
	}
	if !strings.Contains(body, "rate_limit_error") {
		t.Errorf("upstream error body was not relayed: %s", body)
	}
}

func TestHealthz(t *testing.T) {
	gw := newGateway(t, func(w http.ResponseWriter, r *http.Request) {}, nil)
	resp, err := http.Get(gw.url + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// -------------------------------------------------------------------- stream

func sseEvent(name string, payload any) string {
	b, _ := json.Marshal(payload)
	return "event: " + name + "\ndata: " + string(b) + "\n\n"
}

func textDelta(index int, text string) string {
	return sseEvent("content_block_delta", map[string]any{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]any{"type": "text_delta", "text": text},
	})
}

func streamUpstream(events ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		for _, e := range events {
			io.WriteString(w, e)
			if f != nil {
				f.Flush()
			}
		}
	}
}

// collectStream parses a proxied SSE body back into the text the agent would
// render, plus the order of event types it saw.
func collectStream(t *testing.T, body io.Reader) (string, []string) {
	t.Helper()
	var text strings.Builder
	var order []string

	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			order = append(order, "[DONE]")
			continue
		}
		var ev struct {
			Type  string `json:"type"`
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			t.Fatalf("proxied stream emitted invalid JSON %q: %v", payload, err)
		}
		order = append(order, ev.Type)
		text.WriteString(ev.Delta.Text)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return text.String(), order
}

// TestStreamRehydratesPlaceholderSplitAcrossEvents is the streaming
// equivalent of the round-trip test: the provider breaks the placeholder into
// three tokens and the agent must still see one address.
func TestStreamRehydratesPlaceholderSplitAcrossEvents(t *testing.T) {
	gw := newGateway(t, streamUpstream(
		sseEvent("message_start", map[string]any{
			"type": "message_start",
			"message": map[string]any{
				"id": "msg_1", "type": "message", "role": "assistant",
				"model": "claude-opus-5", "content": []any{},
			},
		}),
		sseEvent("content_block_start", map[string]any{
			"type": "content_block_start", "index": 0,
			"content_block": map[string]any{"type": "text", "text": ""},
		}),
		textDelta(0, "Emailed "),
		textDelta(0, "[[AL"),
		textDelta(0, ":EMAIL"),
		textDelta(0, "_1]]"),
		textDelta(0, " about the refund."),
		sseEvent("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0}),
		sseEvent("message_stop", map[string]any{"type": "message_stop"}),
	), nil)

	resp := gw.post(t, "/v1/messages",
		`{"model":"claude-opus-5","stream":true,"messages":[{"role":"user","content":"mail priya.r@acme.co"}]}`, nil)

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	text, order := collectStream(t, resp.Body)
	const want = "Emailed priya.r@acme.co about the refund."
	if text != want {
		t.Errorf("reassembled text = %q, want %q", text, want)
	}
	if strings.Contains(text, "[[AL") {
		t.Error("a placeholder fragment leaked to the client")
	}
	if len(order) == 0 || order[len(order)-1] != "message_stop" {
		t.Errorf("event order = %v, want message_stop last", order)
	}
}

// TestStreamTruncatedMidPlaceholderEmitsHeldBytesInOrder covers the failure
// path: the stream ends while a placeholder is still incomplete. The held
// bytes must still reach the client, and must arrive before the terminal
// events rather than after them.
func TestStreamTruncatedMidPlaceholderEmitsHeldBytesInOrder(t *testing.T) {
	gw := newGateway(t, streamUpstream(
		sseEvent("content_block_start", map[string]any{
			"type": "content_block_start", "index": 0,
			"content_block": map[string]any{"type": "text", "text": ""},
		}),
		textDelta(0, "Hi "),
		textDelta(0, "[[AL:EMA"),
		sseEvent("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0}),
		sseEvent("message_stop", map[string]any{"type": "message_stop"}),
	), nil)

	resp := gw.post(t, "/v1/messages",
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"mail priya.r@acme.co"}]}`, nil)

	text, order := collectStream(t, resp.Body)
	if text != "Hi [[AL:EMA" {
		t.Errorf("text = %q, want the held fragment preserved verbatim", text)
	}

	lastDelta, firstStop := -1, -1
	for i, typ := range order {
		if typ == "content_block_delta" {
			lastDelta = i
		}
		if typ == "content_block_stop" && firstStop == -1 {
			firstStop = i
		}
	}
	if lastDelta == -1 || firstStop == -1 {
		t.Fatalf("missing expected events: %v", order)
	}
	if lastDelta > firstStop {
		t.Errorf("held text was emitted after content_block_stop: %v", order)
	}
}

func TestStreamPassesThroughDoneAndPings(t *testing.T) {
	gw := newGateway(t, streamUpstream(
		"event: ping\ndata: {\"type\":\"ping\"}\n\n",
		": keepalive comment\n\n",
		textDelta(0, "ok"),
		"data: [DONE]\n\n",
	), nil)

	resp := gw.post(t, "/v1/messages", `{"model":"m","stream":true,"messages":[]}`, nil)
	raw := readAll(t, resp.Body)

	if !strings.Contains(raw, "data: [DONE]") {
		t.Error("the [DONE] sentinel was dropped")
	}
	if !strings.Contains(raw, "event: ping") {
		t.Error("the ping event name was dropped")
	}
	if !strings.Contains(raw, ": keepalive comment") {
		t.Error("the SSE comment was dropped")
	}
}

func TestOpenAIStreamIsRehydrated(t *testing.T) {
	chunk := func(content string, finish any) string {
		b, _ := json.Marshal(map[string]any{
			"id": "chatcmpl-1", "object": "chat.completion.chunk",
			"created": 1700000000, "model": "gpt-x",
			"choices": []any{map[string]any{
				"index": 0, "delta": map[string]any{"content": content}, "finish_reason": finish,
			}},
		})
		return "data: " + string(b) + "\n\n"
	}
	gw := newGateway(t, streamUpstream(
		chunk("Emailed ", nil),
		chunk("[[AL:EM", nil),
		chunk("AIL_1]]", nil),
		chunk(" today.", nil),
		chunk("", "stop"),
		"data: [DONE]\n\n",
	), nil)

	resp := gw.post(t, "/v1/chat/completions",
		`{"model":"gpt-x","stream":true,"messages":[{"role":"user","content":"mail priya.r@acme.co"}]}`, nil)

	var text strings.Builder
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if !strings.HasPrefix(line, "data:") || payload == "[DONE]" {
			continue
		}
		var ev struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			t.Fatalf("invalid chunk %q: %v", payload, err)
		}
		for _, c := range ev.Choices {
			text.WriteString(c.Delta.Content)
		}
	}
	if got := text.String(); got != "Emailed priya.r@acme.co today." {
		t.Errorf("text = %q", got)
	}
}

// --------------------------------------------------------------------ledger

func TestLedgerRecordsDetectionsWithoutValues(t *testing.T) {
	gw := newGateway(t, func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"content":[{"type":"text","text":"done"}]}`)
	}, nil)

	resp := gw.post(t, "/v1/messages",
		`{"model":"claude-opus-5","messages":[{"role":"user","content":"mail priya.r@acme.co and a@b.com"}]}`, nil)
	readAll(t, resp.Body)

	recs := gw.records(t)
	if len(recs) != 1 {
		t.Fatalf("got %d ledger records, want 1", len(recs))
	}
	ev := recs[0].Event
	if ev.Outcome != "forwarded" {
		t.Errorf("outcome = %q, want forwarded", ev.Outcome)
	}
	if ev.Model != "claude-opus-5" {
		t.Errorf("model = %q", ev.Model)
	}
	if ev.Detections["tokenize"]["EMAIL"] != 2 {
		t.Errorf("detections = %+v, want two tokenized emails", ev.Detections)
	}
	if ev.Placeholders["EMAIL"] != 2 {
		t.Errorf("placeholders = %+v", ev.Placeholders)
	}
	if ev.RequestSHA256 == "" {
		t.Error("the sanitized request hash should be recorded")
	}
	if ev.RequestID == "" {
		t.Error("a request id should be recorded")
	}

	if n, err := ledger.Verify(gw.ledgerPath); err != nil || n != 1 {
		t.Errorf("Verify = (%d, %v), want (1, nil)", n, err)
	}
}

// TestInventedPlaceholderIsRecorded covers the integrity check: the model
// returns a placeholder that was never minted.
func TestInventedPlaceholderIsRecorded(t *testing.T) {
	gw := newGateway(t, func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"content":[{"type":"text","text":"See [[AL:PERSON_42]] for details."}]}`)
	}, nil)

	resp := gw.post(t, "/v1/messages",
		`{"model":"m","messages":[{"role":"user","content":"mail priya.r@acme.co"}]}`, nil)
	body := readAll(t, resp.Body)

	// It cannot leak a value, so it is passed through literally and flagged.
	if !strings.Contains(body, "[[AL:PERSON_42]]") {
		t.Errorf("unknown placeholder should pass through literally: %s", body)
	}
	recs := gw.records(t)
	if len(recs) != 1 {
		t.Fatalf("got %d records", len(recs))
	}
	got := recs[0].Event.UnknownPlaceholders
	if len(got) != 1 || got[0] != "[[AL:PERSON_42]]" {
		t.Errorf("unknown_placeholders = %v, want [[[AL:PERSON_42]]]", got)
	}
}

func TestOversizedBodyIsRefused(t *testing.T) {
	gw := newGateway(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("an oversized request must not be forwarded")
	}, nil)

	huge := `{"model":"m","messages":[{"role":"user","content":"` +
		strings.Repeat("a", MaxBodyBytes+10) + `"}]}`
	resp := gw.post(t, "/v1/messages", huge, nil)

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
}

// ---------------------------------------------------------------- unit tests

func TestSSEMetaTerminalDetection(t *testing.T) {
	stop := "stop"
	tests := []struct {
		name string
		meta sseMeta
		want bool
	}{
		{"text delta is not terminal", sseMeta{Type: "content_block_delta"}, false},
		{"ping is not terminal", sseMeta{Type: "ping"}, false},
		{"content_block_stop is terminal", sseMeta{Type: "content_block_stop"}, true},
		{"message_stop is terminal", sseMeta{Type: "message_stop"}, true},
		{"error is terminal", sseMeta{Type: "error"}, true},
		{
			name: "openai finish_reason is terminal",
			meta: sseMeta{Choices: []struct {
				Index        int     `json:"index"`
				FinishReason *string `json:"finish_reason"`
			}{{Index: 0, FinishReason: &stop}}},
			want: true,
		},
		{
			name: "openai chunk without finish_reason is not terminal",
			meta: sseMeta{Choices: []struct {
				Index        int     `json:"index"`
				FinishReason *string `json:"finish_reason"`
			}{{Index: 0}}},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.meta.terminal(); got != tc.want {
				t.Errorf("terminal() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSyntheticDeltaIsValidForBothProviders(t *testing.T) {
	for _, provider := range []string{"anthropic", "openai"} {
		st := &streamState{provider: provider, lastIndex: 2, id: "x", model: "m", created: "1700000000"}
		out := st.syntheticDelta("leftover")

		if !strings.HasSuffix(out, "\n\n") {
			t.Errorf("%s: event is not terminated by a blank line: %q", provider, out)
		}
		idx := strings.Index(out, "data: ")
		if idx < 0 {
			t.Fatalf("%s: no data line in %q", provider, out)
		}
		payload := strings.TrimSpace(out[idx+len("data: "):])
		var parsed map[string]any
		if err := json.Unmarshal([]byte(payload), &parsed); err != nil {
			t.Errorf("%s: payload is not valid JSON: %v", provider, err)
		}
		if !strings.Contains(payload, "leftover") {
			t.Errorf("%s: leftover text missing from %q", provider, payload)
		}
	}
}

func TestLooksLikeJSON(t *testing.T) {
	for _, s := range []string{`{"a":1}`, `  {"a":1}`, "\n[1,2]", "[]"} {
		if !looksLikeJSON([]byte(s)) {
			t.Errorf("looksLikeJSON(%q) = false", s)
		}
	}
	for _, s := range []string{"", "   ", "plain text", "<html>"} {
		if looksLikeJSON([]byte(s)) {
			t.Errorf("looksLikeJSON(%q) = true", s)
		}
	}
	// It is a cheap structural prefix check, not a parser: "[DONE]" starts
	// with '[' and passes. rewriteEvent is what must special-case the
	// sentinel, which TestRewriteEventTreatsDoneAsTerminal covers.
	if !looksLikeJSON([]byte("[DONE]")) {
		t.Error("expected the cheap prefix check to accept [DONE]")
	}
}

func TestRewriteEventTreatsDoneAsTerminal(t *testing.T) {
	srv := &Server{}
	v := vault.New()
	h := rewrite.NewRehydrator(v)
	st := &streamState{provider: "openai"}

	tests := []struct {
		name         string
		payload      string
		wantOut      string
		wantTerminal bool
	}{
		{"done sentinel", "[DONE]", "[DONE]", true},
		{"empty payload", "", "", true},
		{"unparseable payload", "[not json at all", "[not json at all", true},
		{"ordinary delta", `{"type":"content_block_delta","index":0}`, "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, terminal := srv.rewriteEvent(tc.payload, h, st)
			if terminal != tc.wantTerminal {
				t.Errorf("terminal = %v, want %v", terminal, tc.wantTerminal)
			}
			if tc.wantOut != "" && out != tc.wantOut {
				t.Errorf("out = %q, want %q", out, tc.wantOut)
			}
		})
	}
}

// TestOpenAIStreamTruncatedBeforeDone is the regression test for the [DONE]
// ordering bug: held bytes must be emitted before the sentinel, not after it.
func TestOpenAIStreamTruncatedBeforeDone(t *testing.T) {
	chunk := func(content string) string {
		b, _ := json.Marshal(map[string]any{
			"id": "chatcmpl-1", "object": "chat.completion.chunk",
			"created": 1700000000, "model": "gpt-x",
			"choices": []any{map[string]any{
				"index": 0, "delta": map[string]any{"content": content}, "finish_reason": nil,
			}},
		})
		return "data: " + string(b) + "\n\n"
	}
	gw := newGateway(t, streamUpstream(
		chunk("Hi "),
		chunk("[[AL:EM"), // stream dies mid-placeholder
		"data: [DONE]\n\n",
	), nil)

	resp := gw.post(t, "/v1/chat/completions",
		`{"model":"gpt-x","stream":true,"messages":[{"role":"user","content":"mail priya.r@acme.co"}]}`, nil)
	raw := readAll(t, resp.Body)

	if !strings.Contains(raw, "[[AL:EM") {
		t.Fatalf("the held fragment was dropped entirely:\n%s", raw)
	}
	heldAt := strings.LastIndex(raw, "[[AL:EM")
	doneAt := strings.Index(raw, "data: [DONE]")
	if doneAt == -1 {
		t.Fatalf("the [DONE] sentinel was dropped:\n%s", raw)
	}
	if heldAt > doneAt {
		t.Errorf("held bytes were emitted after [DONE]:\n%s", raw)
	}
}

func TestRequestMeta(t *testing.T) {
	model, stream := requestMeta([]byte(`{"model":"claude-opus-5","stream":true}`))
	if model != "claude-opus-5" || !stream {
		t.Errorf("requestMeta = (%q, %v)", model, stream)
	}
	model, stream = requestMeta([]byte(`{"messages":[]}`))
	if model != "" || stream {
		t.Errorf("requestMeta on a body without those fields = (%q, %v)", model, stream)
	}
}
