package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/vigneshwarancs/airlock/internal/guard"
	"github.com/vigneshwarancs/airlock/internal/ledger"
	"github.com/vigneshwarancs/airlock/internal/policy"
	"github.com/vigneshwarancs/airlock/internal/vault"
)

// defaultPolicyYAML is the shipped template. It lives in the policy
// package so the test suite can assert that it loads and validates.
const defaultPolicyYAML = policy.DefaultYAML

func initCmd(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	out := fs.String("out", "airlock.yaml", "where to write the policy")
	force := fs.Bool("force", false, "overwrite an existing policy file")
	if err := fs.Parse(args); err != nil {
		return errSilent
	}

	if _, err := os.Stat(*out); err == nil && !*force {
		return fmt.Errorf("%s already exists (use --force to overwrite)", *out)
	}
	if err := os.WriteFile(*out, []byte(defaultPolicyYAML), 0o600); err != nil {
		return err
	}

	// Self-check: a template that does not load is a broken release.
	pol, err := policy.Load(*out)
	if err != nil {
		return fmt.Errorf("wrote %s but it failed validation: %w", *out, err)
	}

	fmt.Printf("wrote %s (%d detectors, default action %q)\n",
		*out, len(pol.Detectors.Builtin)+len(pol.Detectors.Custom), pol.Defaults.OnDetect)
	fmt.Printf("start the gateway with:\n  airlock run --policy %s\n", *out)
	return nil
}

// scanCmd is the dry run: it shows exactly what the policy would do to a
// piece of text without contacting any model.
func scanCmd(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	policyPath := fs.String("policy", "airlock.yaml", "path to the policy file")
	quiet := fs.Bool("quiet", false, "print only the transformed text")
	if err := fs.Parse(args); err != nil {
		return errSilent
	}

	pol, err := loadPolicy(*policyPath)
	if err != nil {
		return err
	}
	g, err := guard.New(pol)
	if err != nil {
		return err
	}

	var raw []byte
	if fs.NArg() > 0 {
		raw, err = os.ReadFile(fs.Arg(0))
	} else {
		raw, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		return err
	}

	v := vault.New()
	out, rep := g.SanitizeText(string(raw), v)

	if *quiet {
		fmt.Print(out)
		return nil
	}

	fmt.Println("── what the model would see ──────────────────────────────")
	fmt.Println(out)
	fmt.Println("── what airlock did ──────────────────────────────────────")
	if rep.Total() == 0 {
		fmt.Println("nothing detected")
		return nil
	}
	for _, line := range summarize(rep) {
		fmt.Println("  " + line)
	}
	if rep.IsBlocked() {
		fmt.Printf("\nthis request would be REFUSED: %s\n", strings.Join(rep.BlockedKinds(), ", "))
	}
	return nil
}

func summarize(rep *guard.Report) []string {
	var lines []string
	for _, group := range []struct {
		label string
		m     map[string]int
	}{
		{"tokenized", rep.Tokenized},
		{"redacted", rep.Redacted},
		{"blocked", rep.Blocked},
		{"allowed", rep.Allowed},
	} {
		kinds := make([]string, 0, len(group.m))
		for k := range group.m {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			lines = append(lines, fmt.Sprintf("%-10s %-14s ×%d", group.label, k, group.m[k]))
		}
	}
	return lines
}

func logCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: airlock log tail|show")
	}
	switch args[0] {
	case "tail":
		return logTail(args[1:])
	case "show":
		return logShow(args[1:])
	default:
		return fmt.Errorf("unknown log subcommand %q (want tail or show)", args[0])
	}
}

func logTail(args []string) error {
	fs := flag.NewFlagSet("log tail", flag.ContinueOnError)
	policyPath := fs.String("policy", "airlock.yaml", "path to the policy file")
	n := fs.Int("n", 20, "number of records to show")
	if err := fs.Parse(args); err != nil {
		return errSilent
	}

	recs, err := readLedger(*policyPath)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		fmt.Println("ledger is empty")
		return nil
	}
	if *n > 0 && len(recs) > *n {
		recs = recs[len(recs)-*n:]
	}

	fmt.Printf("%-5s %-20s %-18s %-10s %-9s %s\n", "SEQ", "TIME", "ID", "OUTCOME", "DURATION", "DETECTIONS")
	for _, r := range recs {
		ts := r.TS
		if len(ts) > 19 {
			ts = ts[:19]
		}
		fmt.Printf("%-5d %-20s %-18s %-10s %-9s %s\n",
			r.Seq, ts, r.Event.RequestID, r.Event.Outcome,
			fmt.Sprintf("%dms", r.Event.DurationMS), flatDetections(r.Event.Detections))
	}
	return nil
}

func logShow(args []string) error {
	fs := flag.NewFlagSet("log show", flag.ContinueOnError)
	policyPath := fs.String("policy", "airlock.yaml", "path to the policy file")
	if err := fs.Parse(args); err != nil {
		return errSilent
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: airlock log show <request-id|seq>")
	}
	want := fs.Arg(0)

	recs, err := readLedger(*policyPath)
	if err != nil {
		return err
	}
	seq, isSeq := parseSeq(want)
	for _, r := range recs {
		if r.Event.RequestID == want || (isSeq && r.Seq == seq) {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(r)
		}
	}
	return fmt.Errorf("no ledger record matching %q", want)
}

func verifyCmd(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	policyPath := fs.String("policy", "airlock.yaml", "path to the policy file")
	if err := fs.Parse(args); err != nil {
		return errSilent
	}
	pol, err := loadPolicy(*policyPath)
	if err != nil {
		return err
	}
	path := pol.LedgerPath()

	n, err := ledger.Verify(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "LEDGER TAMPERED: %v\n", err)
		fmt.Fprintf(os.Stderr, "%d record(s) verified before the break\n", n)
		return errSilent
	}
	fmt.Printf("ledger intact: %d record(s) verified, hash chain unbroken\n", n)
	fmt.Printf("  %s\n", path)
	return nil
}

func readLedger(policyPath string) ([]ledger.Record, error) {
	pol, err := loadPolicy(policyPath)
	if err != nil {
		return nil, err
	}
	return ledger.Read(pol.LedgerPath())
}

func flatDetections(d map[string]map[string]int) string {
	if len(d) == 0 {
		return "-"
	}
	actions := make([]string, 0, len(d))
	for a := range d {
		actions = append(actions, a)
	}
	sort.Strings(actions)

	var parts []string
	for _, a := range actions {
		kinds := make([]string, 0, len(d[a]))
		for k := range d[a] {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			parts = append(parts, fmt.Sprintf("%s:%s×%d", a, k, d[a][k]))
		}
	}
	return strings.Join(parts, " ")
}

func parseSeq(s string) (int64, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}
