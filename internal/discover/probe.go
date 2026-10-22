package discover

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const poweredBy = "X-Powered-By: PHP/"

var versionChars = regexp.MustCompile(`^[0-9A-Za-z.+~-]+`)

// StaticProbe reads a binary without executing it. PHP's SAPI layer compiles
// the literal "X-Powered-By: PHP/" PHP_VERSION into every build (CLI, FPM,
// CGI, mod_php, embed), so the version can be read straight from the file.
// needles are extra byte strings (advisory fingerprints) to look for.
type StaticResult struct {
	IsBinary bool
	Version  string
	Found    []string
}

// magic numbers of executable formats we accept.
var magics = [][]byte{
	{0x7f, 'E', 'L', 'F'},
	{0xcf, 0xfa, 0xed, 0xfe}, {0xce, 0xfa, 0xed, 0xfe}, // Mach-O
	{0xca, 0xfe, 0xba, 0xbe}, // Mach-O universal
}

func StaticProbe(path string, needles []string) (StaticResult, error) {
	var res StaticResult
	f, err := os.Open(path)
	if err != nil {
		return res, err
	}
	defer f.Close()
	head := make([]byte, 4)
	if _, err := io.ReadFull(f, head); err != nil {
		return res, nil
	}
	for _, m := range magics {
		if bytes.Equal(head, m) {
			res.IsBinary = true
		}
	}
	if !res.IsBinary {
		return res, nil
	}
	all := append([]string{poweredBy}, needles...)
	maxNeedle := 0
	for _, n := range all {
		maxNeedle = max(maxNeedle, len(n)+64)
	}
	found := map[string]bool{}
	buf := make([]byte, 1<<20+maxNeedle)
	carry := 0
	copy(buf, head)
	carry = len(head)
	for {
		n, rerr := f.Read(buf[carry:])
		chunk := buf[:carry+n]
		if res.Version == "" {
			if i := bytes.Index(chunk, []byte(poweredBy)); i >= 0 {
				rest := chunk[i+len(poweredBy):]
				if v := versionChars.Find(rest); v != nil && len(rest) > len(v) {
					res.Version = string(v)
				}
			}
		}
		for _, nd := range needles {
			if !found[nd] && bytes.Contains(chunk, []byte(nd)) {
				found[nd] = true
				res.Found = append(res.Found, nd)
			}
		}
		if rerr != nil {
			break
		}
		keep := min(maxNeedle, len(chunk))
		copy(buf, chunk[len(chunk)-keep:])
		carry = keep
	}
	return res, nil
}

var phpVLine = regexp.MustCompile(`(?m)^PHP ([0-9][0-9A-Za-z.+~-]*) \(([^)]*)\)(?: \(built: ([^)]*)\))?`)

// ExecInfo is what `php -v` printed.
type ExecInfo struct {
	Version string
	SAPI    string
	Built   string
	Raw     string
}

// ParseVersionOutput parses `php -v` output.
func ParseVersionOutput(out string) (ExecInfo, bool) {
	m := phpVLine.FindStringSubmatch(out)
	if m == nil {
		return ExecInfo{}, false
	}
	return ExecInfo{Version: m[1], SAPI: m[2], Built: m[3], Raw: strings.TrimSpace(out)}, true
}

// ExecProbe runs `<bin> -v` on the host with a short timeout and a clean
// environment. It is only used when the static probe could not find a version.
func ExecProbe(ctx context.Context, bin string) (ExecInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-n", "-v")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	out, err := cmd.Output()
	if info, ok := ParseVersionOutput(string(out)); ok {
		return info, nil
	}
	if err == nil {
		err = errNoVersion
	}
	return ExecInfo{}, err
}

type constErr string

func (e constErr) Error() string { return string(e) }

const errNoVersion = constErr("no version in output")
