// Package cli implements the bastion command line.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/larptard/bastion/internal/advisory"
	"github.com/larptard/bastion/internal/sarif"
	"github.com/larptard/bastion/internal/scan"
	"github.com/larptard/bastion/internal/ui"
)

// Exit codes are part of the interface so Bastion can gate CI and cron jobs.
const (
	ExitOK         = 0 // nothing affected / no indicators
	ExitAffected   = 1 // vulnerable or likely vulnerable build, or compromise indicators
	ExitUnknown    = 2 // some builds could not be verified, or only weak indicators
	ExitUsageError = 64
	ExitFailure    = 70
)

// Version is set at build time with -ldflags.
var Version = "dev"

type env struct {
	stdout, stderr io.Writer
	outFile        *os.File
}

const usage = `Bastion — local PHP security checks. Reads only; never changes the server.

Usage:
  bastion scan    [flags]        find every PHP build and check it against known vulnerabilities
  bastion trace   [flags] [dir…] look for signs of compromise: webshells, persistence, log traces
  bastion report  [flags]        run scan + trace and write a single-file offline HTML report
  bastion check   [text|-]       assess pasted "php -v" / package output (same engine as the website)
  bastion advisories [--json]    list the built-in vulnerability data
  bastion version

Run "bastion <command> -h" for flags. Exit codes: 0 ok, 1 affected/compromised, 2 unknown, 64 usage, 70 error.
`

// Main runs the CLI and returns the exit code.
func Main(args []string) int {
	e := &env{stdout: os.Stdout, stderr: os.Stderr, outFile: os.Stdout}
	if len(args) == 0 {
		fmt.Fprint(e.stderr, usage)
		return ExitUsageError
	}
	ctx := context.Background()
	var err error
	code := ExitOK
	switch args[0] {
	case "scan":
		code, err = e.cmdScan(ctx, args[1:])
	case "trace":
		code, err = e.cmdTrace(ctx, args[1:])
	case "report":
		code, err = e.cmdReport(ctx, args[1:])
	case "check":
		code, err = e.cmdCheck(args[1:])
	case "advisories", "db":
		code, err = e.cmdAdvisories(args[1:])
	case "version", "--version", "-v":
		fmt.Fprintf(e.stdout, "bastion %s\n", Version)
	case "help", "-h", "--help":
		fmt.Fprint(e.stdout, usage)
	default:
		fmt.Fprintf(e.stderr, "unknown command %q\n\n%s", args[0], usage)
		return ExitUsageError
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		var ue usageErr
		if errors.As(err, &ue) {
			fmt.Fprintf(e.stderr, "bastion: %v\n", err)
			return ExitUsageError
		}
		fmt.Fprintf(e.stderr, "bastion: %v\n", err)
		return ExitFailure
	}
	return code
}

type usageErr struct{ error }

type common struct {
	color   string
	json    bool
	dbDir   string
	quiet   bool
	verbose bool
	format  string
}

// machine reports whether output is for programs (JSON or SARIF).
func (c *common) machine() bool { return c.json || c.format == "json" || c.format == "sarif" }

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.format, "format", "text", "output format: text, json or sarif (scan and trace)")
	fs.StringVar(&c.color, "color", "auto", "colour output: auto, always, never")
	fs.BoolVar(&c.json, "json", false, "print machine-readable JSON instead of the terminal view")
	fs.StringVar(&c.dbDir, "db", "", "directory with extra advisory JSON files (overrides built-ins with the same id)")
	fs.BoolVar(&c.quiet, "q", false, "no progress output on stderr")
	fs.BoolVar(&c.verbose, "v", false, "show details for every instance, including fixed ones")
}

func (c *common) loadDB() (*advisory.DB, error) {
	db, err := advisory.Builtin()
	if err != nil {
		return nil, err
	}
	if c.dbDir != "" {
		if err := db.LoadDir(c.dbDir); err != nil {
			return nil, fmt.Errorf("loading %s: %w", c.dbDir, err)
		}
	}
	return db, nil
}

func (e *env) style(c *common) ui.Style { return ui.NewStyle(c.color, e.outFile) }

func (e *env) progress(c *common) func(string) {
	if c.quiet || c.machine() {
		return nil
	}
	errStyle := ui.NewStyle(c.color, os.Stderr)
	if !errStyle.Color {
		return nil
	}
	return func(msg string) {
		fmt.Fprintf(e.stderr, "\r\x1b[2K  %s %s", errStyle.Accent("…"), errStyle.Gray(msg))
	}
}

func (e *env) clearProgress(c *common) {
	if p := e.progress(c); p != nil {
		fmt.Fprint(e.stderr, "\r\x1b[2K")
	}
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func newFlagSet(name, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: bastion %s\n\nFlags:\n", synopsis)
		fs.PrintDefaults()
	}
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageErr{err}
	}
	if f := fs.Lookup("format"); f != nil {
		switch f.Value.String() {
		case "text", "json", "sarif":
		default:
			return usageErr{fmt.Errorf("--format must be text, json or sarif")}
		}
	}
	return nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

type scanFlags struct {
	sysroot   string
	noDocker  bool
	noExec    bool
	globs     multiFlag
	images    multiFlag
	allImages bool
}

func (f *scanFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.sysroot, "sysroot", "", "scan a mounted filesystem (image, backup, chroot) instead of the live host")
	fs.BoolVar(&f.noDocker, "no-containers", false, "skip Docker/Podman containers")
	fs.BoolVar(&f.noExec, "no-exec", false, "never execute anything (no php -v, no docker exec); rely on static analysis only")
	fs.Var(&f.images, "image", "also scan this container image (repeatable); read with docker save, never run")
	fs.BoolVar(&f.allImages, "images", false, "also scan every local container image (reads each image once; can take a while)")
	fs.Var(&f.globs, "glob", "extra glob of PHP binaries to inspect (repeatable), e.g. --glob '/srv/*/bin/php'")
}

func (e *env) runScan(ctx context.Context, c *common, f *scanFlags) (*scan.Result, error) {
	db, err := c.loadDB()
	if err != nil {
		return nil, err
	}
	opt := scan.Options{DB: db, SysRoot: f.sysroot, Containers: !f.noDocker, Exec: !f.noExec, ExtraGlobs: f.globs, Images: f.images, AllImages: f.allImages, Progress: e.progress(c)}
	res, err := scan.Run(ctx, opt, Version)
	e.clearProgress(c)
	return res, err
}

func scanExit(r *scan.Result) int {
	worst := advisory.Fixed
	for _, i := range r.Instances {
		if i.Worst().Severity() > worst.Severity() {
			worst = i.Worst()
		}
	}
	switch worst {
	case advisory.Vulnerable, advisory.LikelyVulnerable:
		return ExitAffected
	case advisory.Unknown:
		return ExitUnknown
	}
	return ExitOK
}

func (e *env) cmdScan(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet("scan", "scan [flags]")
	var c common
	var f scanFlags
	c.register(fs)
	f.register(fs)
	if err := parse(fs, args); err != nil {
		return 0, err
	}
	res, err := e.runScan(ctx, &c, &f)
	if err != nil {
		return 0, err
	}
	switch {
	case c.format == "sarif":
		return scanExit(res), writeJSON(e.stdout, sarif.FromScan(res))
	case c.machine():
		return scanExit(res), writeJSON(e.stdout, res)
	}
	s := e.style(&c)
	RenderScan(e.stdout, s, ui.TerminalWidth(e.outFile), res, c.verbose)
	return scanExit(res), nil
}
