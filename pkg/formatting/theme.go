package formatting

import (
	"os"

	"github.com/fatih/color"
)

// Theme controls CLI coloring and text styling.
type Theme struct {
	NoColor     bool
	Bold        *color.Color
	Dim         *color.Color
	Cyan        *color.Color
	Green       *color.Color
	Yellow      *color.Color
	Red         *color.Color
	Magenta     *color.Color
	Blue        *color.Color
	BoldCyan    *color.Color
	BoldGreen   *color.Color
	BoldYellow  *color.Color
	BoldRed     *color.Color
	BoldMagenta *color.Color
}

// CurrentTheme holds the active terminal color configuration.
var CurrentTheme = NewTheme(false)

// NewTheme initializes color profiles respecting NO_COLOR environment or explicit flag.
func NewTheme(noColor bool) *Theme {
	if _, exists := os.LookupEnv("NO_COLOR"); exists {
		noColor = true
	}

	if noColor {
		color.NoColor = true
	}

	return &Theme{
		NoColor:     noColor,
		Bold:        color.New(color.Bold),
		Dim:         color.New(color.Faint),
		Cyan:        color.New(color.FgCyan),
		Green:       color.New(color.FgGreen),
		Yellow:      color.New(color.FgYellow),
		Red:         color.New(color.FgRed),
		Magenta:     color.New(color.FgMagenta),
		Blue:        color.New(color.FgBlue),
		BoldCyan:    color.New(color.FgCyan, color.Bold),
		BoldGreen:   color.New(color.FgGreen, color.Bold),
		BoldYellow:  color.New(color.FgYellow, color.Bold),
		BoldRed:     color.New(color.FgRed, color.Bold),
		BoldMagenta: color.New(color.FgMagenta, color.Bold),
	}
}

// DisableColor turns off all ANSI coloring.
func (t *Theme) DisableColor() {
	t.NoColor = true
	color.NoColor = true
}

// Symbols provides standard Unicode status indicators with graceful ASCII fallbacks.
type Symbols struct {
	Check   string
	Cross   string
	Warning string
	Info    string
	Arrow   string
	Bullet  string
}

// DefaultSymbols returns the standard glyphs.
var DefaultSymbols = Symbols{
	Check:   "✔",
	Cross:   "✖",
	Warning: "⚠",
	Info:    "ℹ",
	Arrow:   "↓",
	Bullet:  "●",
}
