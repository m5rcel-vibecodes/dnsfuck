package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/m5rcel-vibecodes/dnsfuck/pkg/formatting"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/output"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/propagation"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/records"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/resolver"
)

func runPropagation(ctx context.Context, w io.Writer, domain string, types []string, timeout time.Duration, resolvers []resolver.Resolver, jsonOutput bool) error {
	theme := formatting.CurrentTheme

	targetType := "A"
	if len(types) > 0 {
		targetType = strings.ToUpper(types[0])
	}
	qtype, err := records.TypeToUint16(targetType)
	if err != nil {
		return err
	}

	res := propagation.Check(ctx, domain, qtype, timeout, resolvers)

	if jsonOutput {
		rep := output.Report{
			Mode:            "propagation",
			Target:          records.NormalizeDomain(domain),
			Timestamp:       time.Now().UTC(),
			TotalDurationMs: float64(res.TotalDuration.Microseconds()) / 1000.0,
			Propagation:     res,
		}
		return output.PrintJSON(w, rep)
	}

	fmt.Fprintf(w, "\n%s %s (%s RECORD)\n\n",
		theme.BoldCyan.Sprint("DNS PROPAGATION CHECK —"),
		theme.Bold.Sprint(records.NormalizeDomain(domain)),
		targetType,
	)

	table := formatting.NewTable("Resolver", "Location", targetType+" Result", "TTL", "Latency")

	for _, item := range res.Items {
		var resultText string
		if item.Error != "" {
			resultText = theme.Red.Sprintf("(%s)", item.Error)
		} else {
			resultText = item.AnswerSummary
		}

		ttlText := "—"
		if item.MinTTL > 0 {
			if item.MinTTL == item.MaxTTL {
				ttlText = fmt.Sprintf("%ds", item.MinTTL)
			} else {
				ttlText = fmt.Sprintf("%d-%ds", item.MinTTL, item.MaxTTL)
			}
		}

		latencyCol := theme.FormatLatency(item.LatencyStr, float64(item.Latency.Milliseconds()))

		table.AddRow(
			item.ResolverName,
			theme.Dim.Sprint(item.Location),
			resultText,
			theme.Dim.Sprint(ttlText),
			latencyCol,
		)
	}

	table.Render(w)
	fmt.Fprintln(w)

	if res.DisagreementDetected {
		fmt.Fprintf(w, "%s %s\n",
			theme.BoldYellow.Sprint(formatting.DefaultSymbols.Warning),
			theme.BoldYellow.Sprint("Resolver disagreement detected"),
		)
		fmt.Fprintf(w, "%s Across %d responsive resolvers, %d distinct answer sets were returned.\n\n",
			theme.Dim.Sprint("Summary:"),
			res.ResponsiveResolvers,
			res.UniqueAnswerSets,
		)
	} else {
		fmt.Fprintf(w, "%s %s\n\n",
			theme.BoldGreen.Sprint(formatting.DefaultSymbols.Check),
			theme.Green.Sprint("Full resolver consensus (all responsive resolvers agree)"),
		)
	}

	fmt.Fprintf(w, "%s %d/%d responsive  %s %s\n",
		theme.Dim.Sprint("Resolvers:"),
		res.ResponsiveResolvers,
		res.TotalResolvers,
		theme.Dim.Sprint("Check duration:"),
		theme.Bold.Sprint(res.TotalDuration.Round(time.Millisecond)),
	)

	return nil
}
