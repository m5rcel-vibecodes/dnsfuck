package formatting

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// GetTerminalWidth returns the width of the current terminal or a standard default (80).
func GetTerminalWidth() int {
	fd := int(os.Stdout.Fd())
	if term.IsTerminal(fd) {
		width, _, err := term.GetSize(fd)
		if err == nil && width > 20 {
			return width
		}
	}
	return 80
}

// ClearScreen clears the terminal screen and resets cursor position (for watch mode).
func ClearScreen() {
	fmt.Print("\033[H\033[2J")
}

// FormatLatency returns colorized latency string based on speed thresholds.
// < 50ms: green, 50-150ms: yellow, > 150ms: red
func (t *Theme) FormatLatency(latencyStr string, ms float64) string {
	if t.NoColor {
		return latencyStr
	}
	switch {
	case ms < 50:
		return t.Green.Sprint(latencyStr)
	case ms <= 150:
		return t.Yellow.Sprint(latencyStr)
	default:
		return t.Red.Sprint(latencyStr)
	}
}
