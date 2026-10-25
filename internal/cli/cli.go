// Package cli implements the netreach command line. Run is the testable entry
// point: it takes arguments and output streams and returns an exit code.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/SlateGitOrg/netreach/report"
)

// Exit codes.
const (
	ExitOK       = 0
	ExitFailure  = 1 // runtime error, or verification mismatch
	ExitUsage    = 2 // bad flags or invalid snapshot
	ExitFindings = 3 // analyze -fail-on threshold reached
)

const usage = `netreach - reachability analysis for AWS-style VPC snapshots

Usage:
  netreach analyze  -s SNAPSHOT [-from SRC] [-egress] [-to CIDRS] [-target ENI] [-format md|json] [-o FILE] [-fail-on SEV]
  netreach why      -s SNAPSHOT -from SRC -to DST [-proto P] [-port N] [-sport N]
  netreach validate -s SNAPSHOT
  netreach verify   [-dir DIR]
  netreach gen      [-seed N] [-vpcs N] [-subnets N] [-enis N] [-rules N] [-o FILE]
  netreach bench    [-sizes LIST] [-seed N]
  netreach version

SRC is "internet", one or more comma-separated CIDRs (treated as internet
sources), or an ENI/instance ID. Run "netreach COMMAND -h" for flags.
`

type env struct {
	stdout, stderr io.Writer
	out, errOut    *printer
	log            *slog.Logger
}

// printer writes formatted output and remembers the first write error, so
// commands can print freely and report a failed write (e.g. a closed pipe)
// once at the end.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}

// Run executes the command line args (without the program name).
func Run(args []string, stdout, stderr io.Writer) int {
	e := &env{stdout: stdout, stderr: stderr, out: &printer{w: stdout}, errOut: &printer{w: stderr}}
	if len(args) == 0 {
		e.errOut.printf("%s", usage)
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "analyze":
		err = e.analyze(rest)
	case "why":
		err = e.why(rest)
	case "validate":
		err = e.validate(rest)
	case "verify":
		err = e.verify(rest)
	case "gen":
		err = e.gen(rest)
	case "bench":
		err = e.bench(rest)
	case "version":
		e.out.printf("netreach %s\n", report.Version)
	case "-h", "-help", "--help", "help":
		e.out.printf("%s", usage)
	default:
		e.errOut.printf("unknown command %q\n\n%s", cmd, usage)
		return ExitUsage
	}
	if err == nil && e.out.err != nil {
		err = fmt.Errorf("write output: %w", e.out.err)
	}
	return e.exitCode(err)
}

// exitError carries a specific exit code.
type exitError struct {
	code int
	err  error
}

func (x *exitError) Error() string { return x.err.Error() }
func (x *exitError) Unwrap() error { return x.err }

func usageErr(format string, args ...any) error {
	return &exitError{code: ExitUsage, err: fmt.Errorf(format, args...)}
}

func (e *env) exitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	e.errOut.printf("netreach: %v\n", err)
	var x *exitError
	if errors.As(err, &x) {
		return x.code
	}
	return ExitFailure
}

// newFlags creates a flag set that reports errors through Run's error path.
func (e *env) newFlags(name string) (*flag.FlagSet, *bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	verbose := fs.Bool("v", false, "verbose (debug) logging to stderr")
	return fs, verbose
}

func (e *env) parse(fs *flag.FlagSet, verbose *bool, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return &exitError{code: ExitUsage, err: err}
	}
	if fs.NArg() > 0 {
		return usageErr("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelDebug
	}
	e.log = slog.New(slog.NewTextHandler(e.stderr, &slog.HandlerOptions{Level: level}))
	return nil
}
