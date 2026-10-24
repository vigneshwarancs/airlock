// Package proxy is the HTTP boundary: it sanitizes outbound requests,
// forwards them, and rehydrates whatever comes back.
package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vigneshwarancs/airlock/internal/guard"
	"github.com/vigneshwarancs/airlock/internal/jsonwalk"
	"github.com/vigneshwarancs/airlock/internal/ledger"
	"github.com/vigneshwarancs/airlock/internal/policy"
	"github.com/vigneshwarancs/airlock/internal/rewrite"
	"github.com/vigneshwarancs/airlock/internal/vault"
)

// MaxBodyBytes caps the request body Airlock will scan. Beyond this the
// policy's fail mode decides whether to refuse or pass through unscanned.
const MaxBodyBytes = 32 << 20

// hopByHop headers must not be forwarded.
var hopByHop = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// Server holds immutable configuration; all per-request state is local.
type Server struct {
	pol    *policy.Policy
	g      *guard.Guard
	led    *ledger.Ledger
	client *http.Client
	logger *log.Logger
}

// New builds a Server. led may be nil to disable the ledger.
func New(p *policy.Policy, led *ledger.Ledger, logger *log.Logger) (*Server, error) {
	g, err := guard.New(p)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Server{
		pol: p,
		g:   g,
		led: led,
		client: &http.Client{
			// No overall timeout: streaming responses are long-lived. The
			// transport bounds connection setup and response headers instead.
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   32,
				ResponseHeaderTimeout: 120 * time.Second,
				IdleConnTimeout:       90 * time.Second,
			},
		},
		logger: logger,
	}, nil
}

// Handler returns the mux Airlock listens on.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/", s.serve)
	return mux
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqID := newRequestID()

	provider, base, ok := s.route(r)
	if !ok {
		writeError(w, http.StatusNotFound, "anthropic",
			fmt.Sprintf("airlock: no upstream configured for %s", r.URL.Path))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, provider, "airlock: could not read request body")
		return
	}
	if len(body) > MaxBodyBytes {
		s.record(ledger.Event{RequestID: reqID, Provider: provider, Path: r.URL.Path,
			Outcome: "blocked", StatusCode: http.StatusRequestEntityTooLarge,
			Error: "request body exceeds scan limit"})
		writeError(w, http.StatusRequestEntityTooLarge, provider,
			"airlock: request body exceeds the scan limit, refusing to forward unscanned")
		return
	}

	ev := ledger.Event{
		RequestID: reqID,
		Provider:  provider,
		Path:      r.URL.Path,
		BytesIn:   int64(len(body)),
	}

	// Requests without a JSON body (model listings, health checks) are
	// forwarded untouched — there is nothing to scan.
	sanitized := body
	v := vault.New()
	if len(body) > 0 && looksLikeJSON(body) {
		ev.Model, ev.Stream = requestMeta(body)

		out, report, err := s.g.SanitizeDocument(body, v)
		if err != nil {
			if s.pol.FailClosed() {
				ev.Outcome, ev.Error, ev.StatusCode = "blocked", err.Error(), http.StatusBadGateway
				s.record(ev)
				writeError(w, http.StatusBadGateway, provider, "airlock: scan failed, failing closed: "+err.Error())
				return
			}
			s.logger.Printf("[%s] scan failed, failing open: %v", reqID, err)
		} else {
			sanitized = out
			ev.Detections = report.Map()
			if report.IsBlocked() {
				kinds := strings.Join(report.BlockedKinds(), ", ")
				ev.Outcome, ev.StatusCode = "blocked", http.StatusForbidden
				ev.Error = "policy blocks: " + kinds
				s.record(ev)
				s.logger.Printf("[%s] BLOCKED %s (%s)", reqID, r.URL.Path, kinds)
				writeError(w, http.StatusForbidden, provider,
					"airlock: request blocked by policy — detected "+kinds+
						". Remove the value or change the action in airlock.yaml.")
				return
			}
		}
	}
	ev.RequestSHA256 = ledger.SHA256(sanitized)

	upstream, err := s.forward(r, base, sanitized)
	if err != nil {
		ev.Outcome, ev.Error, ev.StatusCode = "error", err.Error(), http.StatusBadGateway
		ev.DurationMS = time.Since(start).Milliseconds()
		s.record(ev)
		writeError(w, http.StatusBadGateway, provider, "airlock: upstream request failed: "+err.Error())
		return
	}
	defer upstream.Body.Close()

	copyResponseHeaders(w.Header(), upstream.Header)
	ev.StatusCode = upstream.StatusCode

	var unknown []string
	if isSSE(upstream) {
		w.WriteHeader(upstream.StatusCode)
		ev.BytesOut, unknown, err = s.streamResponse(w, upstream.Body, v, provider)
	} else {
		ev.BytesOut, unknown, err = s.bufferedResponse(w, upstream, v)
	}
	if err != nil {
		s.logger.Printf("[%s] response relay error: %v", reqID, err)
		ev.Error = err.Error()
	}

	ev.Outcome = "forwarded"
	ev.Placeholders = v.Summary()
	ev.UnknownPlaceholders = unknown
	ev.DurationMS = time.Since(start).Milliseconds()
	s.record(ev)

	if len(unknown) > 0 {
		// The model referenced a placeholder that was never minted. It cannot
		// leak a value, but it does mean the response is not trustworthy.
		s.logger.Printf("[%s] WARNING: model emitted %d unknown placeholder(s): %v",
			reqID, len(unknown), unknown)
	}
}

// route maps a request path to a configured upstream.
func (s *Server) route(r *http.Request) (provider, base string, ok bool) {
	if p := r.Header.Get("X-Airlock-Provider"); p != "" {
		base, ok = s.pol.UpstreamFor(p)
		return p, base, ok
	}
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/v1/messages"), strings.HasPrefix(path, "/v1/complete"):
		provider = "anthropic"
	case strings.HasPrefix(path, "/v1/chat/"), strings.HasPrefix(path, "/v1/responses"),
		strings.HasPrefix(path, "/v1/completions"), strings.HasPrefix(path, "/v1/embeddings"):
		provider = "openai"
	default:
		// Unknown paths go to Anthropic if configured, else OpenAI. Model
		// listings and similar incidental endpoints land here.
		if _, has := s.pol.UpstreamFor("anthropic"); has {
			provider = "anthropic"
		} else {
			provider = "openai"
		}
	}
	base, ok = s.pol.UpstreamFor(provider)
	return provider, base, ok
}

func (s *Server) forward(r *http.Request, base string, body []byte) (*http.Response, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("bad upstream %q: %w", base, err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + r.URL.Path
	u.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, vals := range r.Header {
		if hopByHop[strings.ToLower(k)] || strings.EqualFold(k, "content-length") ||
			strings.EqualFold(k, "host") || strings.EqualFold(k, "accept-encoding") {
			continue
		}
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	// Compressed responses would have to be decoded before rehydration;
	// asking for identity keeps the hot path simple and the latency bounded.
	req.Header.Set("Accept-Encoding", "identity")
	req.ContentLength = int64(len(body))

	return s.client.Do(req)
}

// bufferedResponse rehydrates a complete response body.
func (s *Server) bufferedResponse(w http.ResponseWriter, resp *http.Response, v *vault.Vault) (int64, []string, error) {
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return 0, nil, err
	}

	var unknown []string
	out := raw
	if looksLikeJSON(raw) {
		h := rewrite.NewRehydrator(v)
		rewritten, jerr := jsonwalk.MapStrings(raw, func(_, s string) string {
			return h.Feed(s) + h.Flush()
		})
		if jerr == nil {
			out, unknown = rewritten, h.Unknown()
		}
	}
	if len(out) == len(raw) && !looksLikeJSON(raw) {
		// Non-JSON (an upstream error page, say) may still echo placeholders.
		text, u := rewrite.All(v, string(raw))
		out, unknown = []byte(text), u
	}

	w.Header().Set("Content-Length", fmt.Sprint(len(out)))
	w.WriteHeader(resp.StatusCode)
	n, err := w.Write(out)
	return int64(n), unknown, err
}

func copyResponseHeaders(dst, src http.Header) {
	for k, vals := range src {
		if hopByHop[strings.ToLower(k)] || strings.EqualFold(k, "content-length") {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func (s *Server) record(ev ledger.Event) {
	if s.led == nil {
		return
	}
	if _, err := s.led.Append(ev); err != nil {
		s.logger.Printf("ledger append failed: %v", err)
	}
}

func isSSE(resp *http.Response) bool {
	return strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")
}

func looksLikeJSON(b []byte) bool {
	t := bytes.TrimLeft(b, " \t\r\n")
	return len(t) > 0 && (t[0] == '{' || t[0] == '[')
}

// requestMeta pulls the model name and stream flag without fully modelling
// the provider schema.
func requestMeta(body []byte) (model string, stream bool) {
	var m struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	_ = json.Unmarshal(body, &m)
	return m.Model, m.Stream
}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// writeError emits an error in the shape the calling provider's SDK expects,
// so agents surface the reason instead of a generic failure.
func writeError(w http.ResponseWriter, status int, provider, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	var payload any
	if provider == "openai" {
		payload = map[string]any{"error": map[string]any{
			"message": msg, "type": "airlock_policy_error", "code": "airlock_blocked",
		}}
	} else {
		payload = map[string]any{"type": "error", "error": map[string]any{
			"type": "permission_error", "message": msg,
		}}
	}
	_ = json.NewEncoder(w).Encode(payload)
}
