package ui

import (
	"strings"
	"testing"
)

func TestWidth(t *testing.T) {
	s := Style{Color: true}
	if Width(s.Red("abc")) != 3 {
		t.Fatal("ansi codes must not count")
	}
	if Width("🔒🔒🔒🔒") != 8 {
		t.Fatal("wide runes are double width")
	}
	if Pad("🔒🔒", 6) != "🔒🔒  " {
		t.Fatalf("%q", Pad("🔒🔒", 6))
	}
}

func TestTruncateKeepsEnds(t *testing.T) {
	got := Truncate("/opt/cpanel/ea-php83/root/usr/sbin/php-fpm", 20)
	if Width(got) > 20 || !strings.HasPrefix(got, "/opt") || !strings.HasSuffix(got, "php-fpm") {
		t.Fatalf("%q", got)
	}
}

func TestTableAligns(t *testing.T) {
	tb := &Table{Cols: []Column{{Title: "a"}, {Title: "path", Flex: true}, {Title: "z"}}}
	tb.Add("🔒🔒", "/www/server/php/74/bin/php", "x")
	tb.Add("host", "/usr/bin/php", "y")
	out := tb.Render(Style{}, 200)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatal(out)
	}
	// The third column starts at the same display column on every row.
	col := func(l, needle string) int { return Width(l[:strings.Index(l, needle)]) }
	if col(lines[1], "x") != col(lines[2], "y") {
		t.Fatalf("misaligned:\n%s", out)
	}
	narrow := tb.Render(Style{}, 30)
	for _, l := range strings.Split(strings.TrimRight(narrow, "\n"), "\n") {
		if Width(l) > 30 {
			t.Fatalf("too wide (%d): %q", Width(l), l)
		}
	}
}

func TestWrap(t *testing.T) {
	lines := Wrap("the quick brown fox jumps over the lazy dog", 12)
	for _, l := range lines {
		if Width(l) > 12 {
			t.Fatal(l)
		}
	}
}
