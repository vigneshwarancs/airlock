# Contributing to Airlock

Airlock sits on the path between an agent and a model provider. A bug here
either leaks data or breaks someone's agent, so the bar is: **every change
arrives with a test that fails without it.**

## Getting started

```bash
git clone https://github.com/vigneshwarancs/airlock
cd airlock
make check        # gofmt + go vet + go test -race
```

No Go locally? `make docker-test` runs the same suite in a container.

## The two contributions we want most

### 1. Detectors

Airlock can only protect what it recognizes, and PII formats are intensely
local. National ID numbers, bank account shapes, tax identifiers, carrier
phone formats, and credential prefixes for services we have not covered are
all welcome.

A good detector contribution:

- Adds the pattern to `internal/detect/detect.go`, with a `validate` function
  if the format carries a checksum. **Prefer a checksum over a longer regex.**
  `ValidLuhn`, `ValidIBAN`, and `ValidAadhaar` in `validate.go` are the models
  to follow.
- Picks a `priority` relative to the existing detectors. Higher wins when two
  detectors claim the same span.
- Adds **both** a positive and a near-miss case to the tables in
  `internal/detect/detect_test.go`. The near-miss is the important half: a
  detector that fires on ordinary source code is worse than no detector,
  because people turn the whole thing off.

Leave high-recall, high-noise detectors out of `DefaultKinds`. Opt-in beats a
default that floods a Go file with placeholders.

### 2. Prompts that defeat the rehydrator

The streaming rehydrator (`internal/rewrite`) is the subtlest code here. If
you can produce a chunk sequence where the agent sees different text than the
model wrote, that is a genuine bug and we want it.

Add it to `internal/rewrite/rehydrate_test.go`. The existing tests split a
fixture at every byte offset and at nine fixed chunk sizes — extend that style
rather than writing a one-off.

## Ground rules for the hot path

- **No third-party code on the data path.** `gopkg.in/yaml.v3` parses the
  policy at startup and is the only dependency. Keep it that way: the fewer
  people with commit rights to code that sees your prompts, the better.
- **Fail closed.** When a scan errors, the default is to refuse, not forward.
- **Never log a detected value.** The ledger records counts and hashes. If you
  add a field, ask what it would reveal to someone who steals the file —
  `TestLedgerStoresNoPayloads` enforces this.
- **Bound the latency.** The rehydrator may hold at most one placeholder's
  width. Anything that buffers a whole response breaks streaming.

## Pull requests

- Run `make check` first; CI runs exactly that.
- One concern per PR.
- Explain *why* in the description. The *what* is in the diff.
- Security-relevant changes should say what an attacker gains or loses.

## Reporting a vulnerability

Please do not open a public issue for a data-leak bug. Email the maintainer
and give us a chance to ship a fix first.
