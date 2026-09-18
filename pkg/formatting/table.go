package formatting

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Table aligns and formats multi-column tabular data for terminal output.
type Table struct {
	Headers []string
	Rows    [][]string
}

// NewTable initializes an empty table with headers.
func NewTable(headers ...string) *Table {
	return &Table{
		Headers: headers,
		Rows:    make([][]string, 0),
	}
}

// AddRow adds a row of cell values.
func (t *Table) AddRow(cells ...string) {
	t.Rows = append(t.Rows, cells)
}

// Render writes the formatted table to the given writer.
func (t *Table) Render(w io.Writer) {
	tw := tabwriter.NewWriter(w, 2, 4, 3, ' ', 0)

	// Headers
	if len(t.Headers) > 0 {
		var headerCells []string
		for _, h := range t.Headers {
			headerCells = append(headerCells, CurrentTheme.Bold.Sprint(h))
		}
		fmt.Fprintln(tw, strings.Join(headerCells, "\t"))
	}

	// Rows
	for _, row := range t.Rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}

	tw.Flush()
}

// PrintBanner prints a prominent section banner.
func PrintBanner(w io.Writer, title string) {
	theme := CurrentTheme
	termWidth := GetTerminalWidth()
	if termWidth > 80 {
		termWidth = 80
	}

	border := strings.Repeat("─", termWidth)
	fmt.Fprintf(w, "\n%s\n", theme.Dim.Sprint(border))
	fmt.Fprintf(w, "%s\n", theme.BoldCyan.Sprint(title))
	fmt.Fprintf(w, "%s\n\n", theme.Dim.Sprint(border))
}

// PrintSection prints a clean sub-section header.
func PrintSection(w io.Writer, title string) {
	theme := CurrentTheme
	fmt.Fprintf(w, "%s\n", theme.Bold.Sprint(title))
}
