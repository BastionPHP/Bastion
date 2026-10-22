package trace

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
)

//go:embed rules/*.json
var rulesFS embed.FS

// Rule is a content signature.
type Rule struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Pattern  string `json:"pattern"`
	Title    Text   `json:"title"`
	Why      Text   `json:"why"`
	// MinLength requires the match to be at least this long (RE2 caps
	// repetition counts at 1000).
	MinLength int `json:"min_length,omitempty"`
	re        *regexp.Regexp
}

// LoadRules returns the built-in content rules, compiled.
func LoadRules() ([]*Rule, error) {
	b, err := rulesFS.ReadFile("rules/content.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Schema string  `json:"schema"`
		Rules  []*Rule `json:"rules"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if doc.Schema != "bastion.rules/v1" {
		return nil, fmt.Errorf("unsupported rules schema %q", doc.Schema)
	}
	for _, r := range doc.Rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		if sevRank(r.Severity) == 0 {
			return nil, fmt.Errorf("rule %s: bad severity %q", r.ID, r.Severity)
		}
		r.re = re
	}
	return doc.Rules, nil
}

// Match is one rule hit inside a file.
type Match struct {
	Rule    *Rule
	Line    int
	Snippet string
}

// MatchContent runs every rule over content and returns at most one match
// per rule (the first).
func MatchContent(rules []*Rule, content []byte) []Match {
	var out []Match
	for _, r := range rules {
		var loc []int
		if r.MinLength > 0 {
			for _, l := range r.re.FindAllIndex(content, -1) {
				if l[1]-l[0] >= r.MinLength {
					loc = l
					break
				}
			}
		} else {
			loc = r.re.FindIndex(content)
		}
		if loc == nil {
			continue
		}
		out = append(out, Match{Rule: r, Line: lineOf(content, loc[0]), Snippet: snippet(content, loc[0], loc[1])})
	}
	return out
}

func lineOf(b []byte, off int) int {
	n := 1
	for _, c := range b[:off] {
		if c == '\n' {
			n++
		}
	}
	return n
}

// snippet returns printable text around a match, capped at ~160 columns.
func snippet(b []byte, start, end int) string {
	from := max(0, start-40)
	to := min(len(b), max(end, start+80))
	if to-from > 160 {
		to = from + 160
	}
	out := make([]rune, 0, to-from)
	for _, r := range string(b[from:to]) {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			out = append(out, ' ')
		case r < 32 || r == 0x7f || r == 0xfffd:
			out = append(out, '·')
		default:
			out = append(out, r)
		}
	}
	s := string(out)
	if from > 0 {
		s = "…" + s
	}
	if to < len(b) {
		s += "…"
	}
	return s
}
