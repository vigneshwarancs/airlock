// Command airlock is a privacy gateway for AI agents.
package main

import (
	"errors"
	"fmt"
	"os"
)

// Version is overridden at build time via -ldflags "-X main.Version=...".
var Version = "0.1.0-alpha"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "run":
		err = runCmd(os.Args[2:])
	case "init":
		err = initCmd(os.Args[2:])
	case "scan":
		err = scanCmd(os.Args[2:])
	case "log":
		err = logCmd(os.Args[2:])
	case "verify":
		err = verifyCmd(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("airlock " + Version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "airlock: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		if errors.Is(err, errSilent) {
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "airlock: "+err.Error())
		os.Exit(1)
	}
}

// errSilent signals that the command already printed its own diagnostics.
var errSilent = errors.New("failed")

func usage() {
	fmt.Fprint(os.Stderr, `airlock — a privacy gateway for AI agents

Usage:
  airlock init [--out airlock.yaml] [--force]
      Write a policy file with safe defaults.

  airlock run [--policy airlock.yaml] [--listen host:port] [--anthropic URL] [--openai URL]
      Start the gateway.

  airlock scan [--policy airlock.yaml] [file]
      Show what the policy would do to a file or stdin. Nothing is sent anywhere.

  airlock log tail [--policy airlock.yaml] [-n 20]
  airlock log show [--policy airlock.yaml] <request-id|seq>
      Inspect the ledger.

  airlock verify [--policy airlock.yaml]
      Check the ledger hash chain.

  airlock version

Point your agent at it:
  export ANTHROPIC_BASE_URL=http://127.0.0.1:4455
  export OPENAI_BASE_URL=http://127.0.0.1:4455/v1
`)
}
