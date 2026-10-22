// Package advisory holds Bastion's vulnerability database and the engine
// that decides whether a PHP build is affected by an advisory.
//
// Advisories are plain JSON documents (see data/). Supporting a new
// vulnerability means adding a file, not writing code.
package advisory

// Text is a small bilingual string.
type Text map[string]string

// Get returns the text in lang, falling back to English.
func (t Text) Get(lang string) string {
	if s, ok := t[lang]; ok && s != "" {
		return s
	}
	return t["en"]
}

type Advisory struct {
	Schema          string          `json:"schema"`
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Product         string          `json:"product"`
	Published       string          `json:"published"`
	Severity        string          `json:"severity"`
	CVSS            CVSS            `json:"cvss"`
	Aliases         []string        `json:"aliases"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Summary         Text            `json:"summary"`
	SAPIRisk        map[string]Risk `json:"sapi_risk"`
	Branches        []Branch        `json:"branches"`
	// OlderBranches and NewerBranches say how to treat branches that are
	// older or newer than every branch listed ("affected" or "fixed").
	OlderBranches    string        `json:"older_branches"`
	NewerBranches    string        `json:"newer_branches"`
	VendorFixes      []VendorFix   `json:"vendor_fixes"`
	ChangelogMarkers []string      `json:"changelog_markers"`
	Fingerprints     []Fingerprint `json:"fingerprints"`
	Mitigations      []Text        `json:"mitigations"`
	References       []Reference   `json:"references"`
	Notes            Text          `json:"notes"`
}

type CVSS struct {
	Version string  `json:"version"`
	Score   float64 `json:"score"`
	Vector  string  `json:"vector"`
}

type Vulnerability struct {
	CVE        string   `json:"cve"`
	GHSA       string   `json:"ghsa"`
	Title      Text     `json:"title"`
	Weaknesses []string `json:"weaknesses"`
	URL        string   `json:"url"`
}

type Risk struct {
	Level string `json:"level"`
	En    string `json:"en"`
	Zh    string `json:"zh"`
}

// Branch describes one upstream release line.
type Branch struct {
	Branch string `json:"branch"`
	// Fixed is the first upstream release containing the fix. Empty means
	// upstream never shipped a fixed release for this branch.
	Fixed          string `json:"fixed,omitempty"`
	Status         string `json:"status"`
	SourceBackport string `json:"source_backport,omitempty"`
	Note           Text   `json:"note,omitempty"`
}

// VendorFix is a distribution package that carries a backported fix.
type VendorFix struct {
	Distro   string `json:"distro"`
	Release  string `json:"release"`
	Package  string `json:"package"`
	Fixed    string `json:"fixed"`
	Format   string `json:"format"`
	Advisory string `json:"advisory"`
	Channel  string `json:"channel,omitempty"`
	URL      string `json:"url"`
}

// Fingerprint is a byte string whose presence in a binary is evidence.
type Fingerprint struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Indicates string `json:"indicates"`
	MinBranch string `json:"min_branch,omitempty"`
	Note      Text   `json:"note"`
}

type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}
