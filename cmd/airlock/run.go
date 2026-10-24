package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/vigneshwarancs/airlock/internal/ledger"
	"github.com/vigneshwarancs/airlock/internal/policy"
	"github.com/vigneshwarancs/airlock/internal/proxy"
)

func runCmd(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	policyPath := fs.String("policy", "airlock.yaml", "path to the policy file")
	listen := fs.String("listen", "", "override the listen address from policy")
	anthropic := fs.String("anthropic", "", "override the Anthropic upstream base URL")
	openai := fs.String("openai", "", "override the OpenAI upstream base URL")
	noLedger := fs.Bool("no-ledger", false, "disable the audit ledger for this run")
	if err := fs.Parse(args); err != nil {
		return errSilent
	}

	pol, err := loadPolicy(*policyPath)
	if err != nil {
		return err
	}
	if *listen != "" {
		pol.Listen = *listen
	}
	if *anthropic != "" {
		pol.Upstream["anthropic"] = *anthropic
	}
	if *openai != "" {
		pol.Upstream["openai"] = *openai
	}

	logger := log.New(os.Stderr, "", log.LstdFlags)

	var led *ledger.Ledger
	if pol.LedgerEnabled() && !*noLedger {
		led, err = ledger.Open(pol.LedgerPath())
		if err != nil {
			return err
		}
		defer led.Close()
	}

	srv, err := proxy.New(pol, led, logger)
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:    pol.Listen,
		Handler: srv.Handler(),
		// No WriteTimeout: streamed responses are long-lived by design.
		ReadHeaderTimeout: 30 * time.Second,
	}

	printBanner(pol, led != nil)

	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case <-stop:
		fmt.Fprintln(os.Stderr, "\nairlock: shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(ctx)
	}
}

func printBanner(pol *policy.Policy, ledgerOn bool) {
	addr := pol.Listen
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}

	detectors := append([]string(nil), pol.Detectors.Builtin...)
	for _, c := range pol.Detectors.Custom {
		detectors = append(detectors, c.Name)
	}
	sort.Strings(detectors)

	blocked := make([]string, 0, len(pol.Actions))
	for k, a := range pol.Actions {
		if a == policy.Block {
			blocked = append(blocked, k)
		}
	}
	sort.Strings(blocked)

	w := os.Stderr
	fmt.Fprintf(w, "\n  airlock %s — listening on http://%s\n\n", Version, addr)
	fmt.Fprintf(w, "  detectors   %s\n", wrapList(detectors, 54))
	fmt.Fprintf(w, "  default     %s\n", pol.Defaults.OnDetect)
	if len(blocked) > 0 {
		fmt.Fprintf(w, "  blocked     %s\n", wrapList(blocked, 54))
	}
	fmt.Fprintf(w, "  on error    fail %s\n", pol.Defaults.Fail)
	if ledgerOn {
		fmt.Fprintf(w, "  ledger      %s\n", pol.LedgerPath())
	} else {
		fmt.Fprintf(w, "  ledger      disabled\n")
	}
	fmt.Fprintf(w, "\n  point your agent at it:\n")
	if _, ok := pol.Upstream["anthropic"]; ok {
		fmt.Fprintf(w, "    export ANTHROPIC_BASE_URL=http://%s\n", addr)
	}
	if _, ok := pol.Upstream["openai"]; ok {
		fmt.Fprintf(w, "    export OPENAI_BASE_URL=http://%s/v1\n", addr)
	}
	fmt.Fprintln(w)
}

// wrapList keeps the banner readable when many detectors are enabled.
func wrapList(items []string, width int) string {
	var lines []string
	cur := ""
	for _, it := range items {
		if cur != "" && len(cur)+len(it)+2 > width {
			lines = append(lines, cur)
			cur = ""
		}
		if cur != "" {
			cur += ", "
		}
		cur += it
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return strings.Join(lines, "\n              ")
}

func loadPolicy(path string) (*policy.Policy, error) {
	pol, err := policy.Load(path)
	// errors.Is unwraps the %w chain; os.IsNotExist would not.
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no policy at %s — run `airlock init` first", path)
	}
	if err != nil {
		return nil, err
	}
	return pol, nil
}
