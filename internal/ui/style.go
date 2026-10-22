// Package ui renders Bastion's terminal output: status colours, aligned
// tables and timelines. It has no dependencies beyond the standard library.
package ui

import (
	"os"
	"regexp"
	"strings"
)

// Style holds the colour decision for one output stream.
type Style struct{ Color bool }

// NewStyle decides whether to colour output: mode is "auto", "always" or
// "never"; auto honours NO_COLOR, FORCE_COLOR, TERM=dumb and whether the
// stream is a terminal.
func NewStyle(mode string, f *os.File) Style {
	switch mode {
	case "always":
		return Style{true}
	case "never":
		return Style{false}
	}
	if os.Getenv("NO_COLOR") != "" {
		return Style{false}
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return Style{true}
	}
	if os.Getenv("TERM") == "dumb" {
		return Style{false}
	}
	fi, err := f.Stat()
	return Style{err == nil && fi.Mode()&os.ModeCharDevice != 0}
}

const (
	reset = "\x1b[0m"
)

func (s Style) wrap(code, t string) string {
	if !s.Color || t == "" {
		return t
	}
	return "\x1b[" + code + "m" + t + reset
}

func (s Style) Bold(t string) string   { return s.wrap("1", t) }
func (s Style) Dim(t string) string    { return s.wrap("2", t) }
func (s Style) Red(t string) string    { return s.wrap("38;5;203", t) }
func (s Style) Amber(t string) string  { return s.wrap("38;5;214", t) }
func (s Style) Green(t string) string  { return s.wrap("38;5;78", t) }
func (s Style) Blue(t string) string   { return s.wrap("38;5;111", t) }
func (s Style) Violet(t string) string { return s.wrap("38;5;141", t) }
func (s Style) Gray(t string) string   { return s.wrap("38;5;245", t) }
func (s Style) Faint(t string) string  { return s.wrap("38;5;240", t) }
func (s Style) White(t string) string  { return s.wrap("38;5;255", t) }
func (s Style) Accent(t string) string { return s.wrap("38;5;117", t) }
func (s Style) BadgeRed(t string) string {
	return s.wrap("1;38;5;232;48;5;203", " "+t+" ")
}
func (s Style) BadgeAmber(t string) string {
	return s.wrap("1;38;5;232;48;5;214", " "+t+" ")
}
func (s Style) BadgeGreen(t string) string {
	return s.wrap("1;38;5;232;48;5;78", " "+t+" ")
}
func (s Style) BadgeGray(t string) string {
	return s.wrap("1;38;5;232;48;5;250", " "+t+" ")
}
func (s Style) Badge(t string) string {
	return s.wrap("1;38;5;232;48;5;117", " "+t+" ")
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// StripANSI removes colour codes.
func StripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

// Width is the number of terminal columns s occupies.
func Width(s string) int {
	w := 0
	for _, r := range StripANSI(s) {
		w += runeWidth(r)
	}
	return w
}

func runeWidth(r rune) int {
	switch {
	case r == 0 || r < 32:
		return 0
	case r >= 0x1100 && r <= 0x115F, r >= 0x2E80 && r <= 0xA4CF && r != 0x303F,
		r >= 0xAC00 && r <= 0xD7A3, r >= 0xF900 && r <= 0xFAFF, r >= 0xFE30 && r <= 0xFE4F,
		r >= 0xFF00 && r <= 0xFF60, r >= 0xFFE0 && r <= 0xFFE6, r >= 0x1F300 && r <= 0x1FAFF,
		r >= 0x20000 && r <= 0x3FFFD:
		return 2
	}
	return 1
}

// Pad right-pads s to w columns.
func Pad(s string, w int) string {
	if d := w - Width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// Truncate shortens plain text to w columns, eliding the middle so both
// ends of a path stay readable.
func Truncate(s string, w int) string {
	if Width(s) <= w || w < 5 {
		return s
	}
	runes := []rune(s)
	keepEnd := (w - 1) * 3 / 5
	keepStart := w - 1 - keepEnd
	var b strings.Builder
	cw := 0
	for _, r := range runes {
		if cw+runeWidth(r) > keepStart {
			break
		}
		b.WriteRune(r)
		cw += runeWidth(r)
	}
	b.WriteString("…")
	end := []rune{}
	cw = 0
	for i := len(runes) - 1; i >= 0; i-- {
		if cw+runeWidth(runes[i]) > keepEnd {
			break
		}
		end = append([]rune{runes[i]}, end...)
		cw += runeWidth(runes[i])
	}
	b.WriteString(string(end))
	return b.String()
}

// Wrap breaks plain text into lines of at most w columns at spaces.
func Wrap(s string, w int) []string {
	if w < 10 {
		w = 10
	}
	var lines []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		cur := ""
		for _, word := range words {
			if cur != "" && Width(cur)+1+Width(word) > w {
				lines = append(lines, cur)
				cur = ""
			}
			for Width(word) > w {
				cut := 0
				cw := 0
				for i, r := range word {
					if cw+runeWidth(r) > w {
						cut = i
						break
					}
					cw += runeWidth(r)
				}
				if cur != "" {
					lines = append(lines, cur)
					cur = ""
				}
				lines = append(lines, word[:cut])
				word = word[cut:]
			}
			if cur == "" {
				cur = word
			} else {
				cur += " " + word
			}
		}
		lines = append(lines, cur)
	}
	return lines
}
