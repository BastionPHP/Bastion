// Package design holds Bastion's shared visual language: one stylesheet and
// the logo, used by the HTML report and the website.
package design

import _ "embed"

//go:embed bastion.css
var CSS string

//go:embed logo.svg
var Logo string
