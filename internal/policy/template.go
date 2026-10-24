package policy

// DefaultYAML is the policy file `airlock init` writes.
//
// It lives here rather than in the CLI so the test suite can assert that the
// shipped template actually loads and validates — a default policy that fails
// to parse is a broken release.
const DefaultYAML = `# airlock policy — commit this file. It is the data boundary.
version: 1

listen: 127.0.0.1:4455

upstream:
  anthropic: https://api.anthropic.com
  openai: https://api.openai.com

defaults:
  # tokenize = reversible placeholder, restored in the response
  # redact   = one-way removal
  # block    = refuse the request
  # allow    = forward untouched
  on_detect: tokenize

  # closed = refuse to forward if a scan fails. open = forward anyway.
  fail: closed

  # Treat a placeholder the model invented as a violation, not as text.
  strict_placeholders: true

detectors:
  # Every builtin here is either checksum-validated or prefix-anchored, so
  # false positives are rare enough to tokenize without asking.
  builtin:
    - PRIVATE_KEY
    - JWT
    - AWS_KEY
    - GITHUB_TOKEN
    - SLACK_TOKEN
    - API_KEY
    - IBAN
    - CARD
    - AADHAAR
    - PAN
    - EMAIL
    # - PHONE       # high recall, noisy in source code
    # - IP          # high recall, noisy in logs and configs

  # Catches random credentials that no pattern describes. Off by default:
  # it is the one detector that will surprise you.
  entropy:
    enabled: false
    min_bits: 4.2
    min_len: 24

  custom:
    - name: employee_id
      pattern: 'EMP-[0-9]{6}'
      action: tokenize

# Per-detector overrides of defaults.on_detect. Credentials are blocked
# outright: there is no legitimate reason to send one to a model.
actions:
  PRIVATE_KEY: block
  AWS_KEY: block
  GITHUB_TOKEN: block
  SLACK_TOKEN: block
  API_KEY: block

ledger:
  enabled: true
  path: ~/.airlock/ledger.jsonl
  # Record hashes and counts, never prompt contents.
  redact_payloads: true
`
