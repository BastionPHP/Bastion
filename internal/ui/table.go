package ui

import (
	"os"
	"strconv"
	"strings"
)

// TerminalWidth returns the width of f, $COLUMNS, or 110.
func TerminalWidth(f *os.File) int {
	if w := termWidth(f); w > 0 {
		return w
	}
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 20 {
		return n
	}
	return 110
}

// Column describes one table column. Flex columns absorb shrinking when
// the table is wider than the terminal; they must hold plain text.
type Column struct {
	Title string
	Flex  bool
	Min   int
}

// Table renders rows with aligned columns, a dim header and no borders.
type Table struct {
	Cols   []Column
	Rows   [][]string
	Indent int
}

func (t *Table) Add(cells ...string) { t.Rows = append(t.Rows, cells) }

func (t *Table) Render(s Style, maxWidth int) string {
	widths := make([]int, len(t.Cols))
	for i, c := range t.Cols {
		widths[i] = Width(c.Title)
	}
	for _, r := range t.Rows {
		for i, cell := range r {
			if i < len(widths) {
				widths[i] = max(widths[i], Width(cell))
			}
		}
	}
	gap := 2
	total := t.Indent
	for _, w := range widths {
		total += w + gap
	}
	// Shrink flex columns, widest first, until the table fits.
	for total > maxWidth {
		best := -1
		for i, c := range t.Cols {
			if c.Flex && widths[i] > max(c.Min, 8) && (best < 0 || widths[i] > widths[best]) {
				best = i
			}
		}
		if best < 0 {
			break
		}
		widths[best]--
		total--
	}
	var b strings.Builder
	ind := strings.Repeat(" ", t.Indent)
	b.WriteString(ind)
	for i, c := range t.Cols {
		b.WriteString(s.Faint(Pad(strings.ToUpper(c.Title), widths[i])))
		if i < len(t.Cols)-1 {
			b.WriteString(strings.Repeat(" ", gap))
		}
	}
	b.WriteString("\n")
	for _, r := range t.Rows {
		b.WriteString(ind)
		for i := range t.Cols {
			cell := ""
			if i < len(r) {
				cell = r[i]
			}
			if t.Cols[i].Flex && Width(cell) > widths[i] {
				cell = Truncate(StripANSI(cell), widths[i])
			}
			if i < len(t.Cols)-1 {
				b.WriteString(Pad(cell, widths[i]))
				b.WriteString(strings.Repeat(" ", gap))
			} else {
				b.WriteString(cell)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}
