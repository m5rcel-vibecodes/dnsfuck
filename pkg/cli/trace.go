package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/m5rcel-vibecodes/dnsfuck/pkg/formatting"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/output"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/records"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/trace"
)

func runTrace(ctx context.Context, w io.Writer, domain string, types []string, timeout time.Duration, jsonOutput bool) error {
	theme := formatting.CurrentTheme

	targetType := "A"
	if len(types) > 0 {
		targetType = strings.ToUpper(types[0])
	}
	qtype, err := records.TypeToUint16(targetType)
	if err != nil {
		return err
	}

	res := trace.Trace(ctx, domain, qtype, timeout)

	if jsonOutput {
		rep := output.Report{
			Mode:            "trace",
			Target:          records.NormalizeDomain(domain),
			Timestamp:       time.Now().UTC(),
			TotalDurationMs: float64(res.TotalDuration.Microseconds()) / 1000.0,
			Trace:           res,
		}
		return output.PrintJSON(w, rep)
	}

	fmt.Fprintf(w, "\n%s %s (%s record)\n\n",
		theme.BoldCyan.Sprint("ITERATIVE RESOLUTION TRACE —"),
		theme.Bold.Sprint(records.NormalizeDomain(domain)),
		targetType,
	)

	for i, hop := range res.Hops {
		zoneLabel := hop.Zone
		if zoneLabel == "" {
			zoneLabel = "."
		}

		// Zone classification
		role := "Zone"
		if hop.Level == 1 {
			role = "Root"
		} else if strings.Count(strings.TrimSuffix(zoneLabel, "."), ".") == 0 {
			role = "TLD"
		} else {
			role = "Authoritative"
		}

		timeStr := theme.FormatLatency(hop.LatencyStr, float64(hop.Latency.Milliseconds()))

		serverDesc := fmt.Sprintf("%s [%s]", hop.ServerName, hop.ServerIP)
		if hop.ServerName == "" {
			serverDesc = hop.ServerIP
		}

		fmt.Fprintf(w, "%s %s %s\n",
			theme.Bold.Sprint(zoneLabel),
			theme.Dim.Sprintf("(%s: %s)", role, serverDesc),
			timeStr,
		)

		// Print delegated NS records if any
		if len(hop.Authorities) > 0 && len(hop.Answers) == 0 {
			var nsNames []string
			for _, auth := range hop.Authorities {
				if auth.Type == "NS" {
					nsNames = append(nsNames, auth.Value)
				}
			}
			if len(nsNames) > 0 {
				fmt.Fprintf(w, "  %s %s\n",
					theme.Dim.Sprint("Delegation to:"),
					strings.Join(nsNames, ", "),
				)
			}
		}

		// Arrow indicator to next step
		if i < len(res.Hops)-1 || len(res.FinalAnswers) > 0 || res.Error != "" {
			fmt.Fprintf(w, "%s\n", theme.Cyan.Sprint(formatting.DefaultSymbols.Arrow))
		}
	}

	if len(res.FinalAnswers) > 0 {
		fmt.Fprintf(w, "%s\n", theme.BoldGreen.Sprint("final answer:"))
		for _, ans := range res.FinalAnswers {
			fmt.Fprintf(w, "  %s: %s %s\n",
				theme.Bold.Sprint(ans.Type),
				ans.Value,
				theme.Dim.Sprintf("(TTL: %d)", ans.TTL),
			)
		}
		fmt.Fprintln(w)
	} else if res.Error != "" {
		fmt.Fprintf(w, "%s %s\n\n",
			theme.BoldRed.Sprint(formatting.DefaultSymbols.Cross),
			theme.Red.Sprint(res.Error),
		)
	}

	fmt.Fprintf(w, "%s %s (%d hops)\n",
		theme.Dim.Sprint("Trace resolved in:"),
		theme.Bold.Sprint(res.TotalDuration.Round(time.Millisecond)),
		len(res.Hops),
	)

	return nil
}
