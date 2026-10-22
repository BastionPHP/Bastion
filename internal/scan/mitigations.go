package scan

import (
	"strings"

	"github.com/larptard/bastion/internal/advisory"
	"github.com/larptard/bastion/internal/phpini"
	"github.com/larptard/bastion/internal/version"
)

// Mitigation is the observed state of one interim mitigation for one
// configuration scope (php.ini, or one PHP-FPM pool).
type Mitigation struct {
	Setting string `json:"setting"`
	Scope   string `json:"scope"` // "php.ini" or "pool <name>"
	Value   string `json:"value"`
	Source  string `json:"source"`
	Want    string `json:"want"`
	OK      bool   `json:"ok"`
	Why     string `json:"why"`
}

// SafeValue reports whether value satisfies a ConfigCheck's Safe rule.
func SafeValue(rule, value string) bool {
	switch {
	case rule == "off":
		return !phpini.Bool(value)
	case strings.HasPrefix(rule, "<="):
		limit, ok1 := phpini.Bytes(strings.TrimPrefix(rule, "<="))
		got, ok2 := phpini.Bytes(value)
		return ok1 && ok2 && got >= 0 && got <= limit
	}
	return strings.TrimSpace(value) == rule
}

func wantText(rule string) string {
	switch {
	case rule == "off":
		return "0 / Off"
	case strings.HasPrefix(rule, "<="):
		return "≤ " + strings.TrimPrefix(rule, "<=")
	}
	return rule
}

// mitigations reads the configuration that applies to inst and evaluates
// the advisory's config checks. It only reads files.
func (t *Target) mitigations(inst *Instance, a *advisory.Advisory) []Mitigation {
	if len(a.ConfigChecks) == 0 || inst.Version == "" || inst.Stale {
		return nil
	}
	v, err := version.ParsePHP(inst.Version)
	if err != nil {
		return nil
	}
	var checks []advisory.ConfigCheck
	for _, c := range a.ConfigChecks {
		if len(c.Branches) == 0 || containsStr(c.Branches, v.Branch()) {
			checks = append(checks, c)
		}
	}
	keys := make([]string, len(checks))
	defaults := map[string]string{}
	for i, c := range checks {
		keys[i] = c.Setting
		defaults[c.Setting] = c.Default
	}
	layout := phpini.Locate(t.root, inst.Path, v.Branch(), inst.SAPI)
	base := phpini.Effective(t.root, layout.INI, keys, defaults)
	var out []Mitigation
	for _, c := range checks {
		bv := base[c.Setting]
		out = append(out, Mitigation{Setting: c.Setting, Scope: "php.ini", Value: bv.Value, Source: bv.Source, Want: wantText(c.Safe), OK: SafeValue(c.Safe, bv.Value), Why: c.Text.Get("en")})
	}
	for _, p := range phpini.Pools(t.root, layout.Pools, keys) {
		for _, c := range checks {
			pv, ok := p.Values[c.Setting]
			if !ok {
				continue
			}
			out = append(out, Mitigation{Setting: c.Setting, Scope: "pool " + p.Name, Value: pv.Value, Source: pv.Source, Want: wantText(c.Safe), OK: SafeValue(c.Safe, pv.Value), Why: c.Text.Get("en")})
		}
	}
	return out
}
