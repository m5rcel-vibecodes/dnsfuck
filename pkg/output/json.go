package output

import (
	"encoding/json"
	"io"
	"time"

	"github.com/m5rcel-vibecodes/dnsfuck/pkg/dnssec"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/propagation"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/records"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/resolver"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/trace"
)

// Report provides an overarching structured JSON envelope.
type Report struct {
	Mode            string                   `json:"mode"`
	Target          string                   `json:"target"`
	Timestamp       time.Time                `json:"timestamp"`
	TotalDurationMs float64                  `json:"total_duration_ms"`
	Diagnostic      *DiagnosticReport        `json:"diagnostic,omitempty"`
	Comparison      *ComparisonReport        `json:"comparison,omitempty"`
	Propagation     *propagation.Result      `json:"propagation,omitempty"`
	DNSSEC          *dnssec.DiagnosticResult `json:"dnssec,omitempty"`
	Trace           *trace.TraceResult       `json:"trace,omitempty"`
	Errors          []string                 `json:"errors,omitempty"`
}

// DiagnosticReport represents the standard diagnostic JSON structure.
type DiagnosticReport struct {
	Domain   string                      `json:"domain"`
	Resolver resolver.Resolver           `json:"resolver"`
	Records  map[string][]records.Record `json:"records"`
	DNSSEC   *dnssec.DiagnosticResult    `json:"dnssec,omitempty"`
	Rcode    string                      `json:"rcode"`
}

// ComparisonReport represents multi-resolver comparison data in JSON.
type ComparisonReport struct {
	Domain      string                 `json:"domain"`
	Type        string                 `json:"type"`
	Discrepancy bool                   `json:"discrepancy"`
	Results     []resolver.QueryResult `json:"results"`
}

// PrintJSON writes indented JSON to writer.
func PrintJSON(w io.Writer, data any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(data)
}
