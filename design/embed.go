// Package design holds Bastion's shared visual language: one stylesheet,
// the logo and an icon set (Lucide, ISC), used by the HTML report and the
// website.
package design

import (
	_ "embed"
	"encoding/json"
	"html/template"
)

//go:embed bastion.css
var CSS string

//go:embed logo.svg
var Logo string

//go:embed icons.json
var iconsJSON []byte

var icons map[string]string

func init() {
	if err := json.Unmarshal(iconsJSON, &icons); err != nil {
		panic(err)
	}
}

// Icon returns an inline SVG icon that inherits the text colour. Unknown
// names panic so a typo fails tests rather than rendering nothing.
func Icon(name string) template.HTML {
	inner, ok := icons[name]
	if !ok {
		panic("design: unknown icon " + name)
	}
	return template.HTML(`<svg class="i i-` + name + `" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">` + inner + `</svg>`)
}
