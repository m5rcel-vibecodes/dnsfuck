package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/m5rcel-vibecodes/dnsfuck/pkg/formatting"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/output"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/records"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/resolver"
)

func runCompare(ctx context.Context, w io.Writer, domain string, types []string, resolvers []resolver.Resolver, jsonOutput bool) error {
	start := time.Now()
	theme := formatting.CurrentTheme

	// Default to "A" record if no specific type given
	targetType := "A"
	if len(types) > 0 {
		targetType = strings.ToUpper(types[0])
	}
	qtype, err := records.TypeToUint16(targetType)
	if err != nil {
		return err
	}

	// Use default comparison resolvers if none supplied
	targetResolvers := resolvers
	if len(targetResolvers) == 0 {
		targetResolvers = resolver.DefaultComparisonResolvers()
	}

	results := make([]resolver.QueryResult, len(targetResolvers))
	var wg sync.WaitGroup
	wg.Add(len(targetResolvers))

	for i, r := range targetResolvers {
		go func(idx int, res resolver.Resolver) {
			defer wg.Done()
			qRes := res.Query(ctx, domain, qtype)
			results[idx] = *qRes
		}(i, r)
	}

	wg.Wait()
	totalDuration := time.Since(start)

	// Check for discrepancies among successful responses
	answerSignatures := make(map[string][]int) // signature -> slice of indices
	for i, r := range results {
		var sig string
		if len(r.Records) > 0 {
			var vals []string
			for _, rec := range r.Records {
				vals = append(vals, rec.Value)
			}
			sort.Strings(vals)
			sig = strings.Join(vals, ", ")
		} else if r.Error != "" {
			sig = "[ERROR] " + r.Error
		} else {
			sig = "[" + r.RcodeName + "]"
		}
		answerSignatures[sig] = append(answerSignatures[sig], i)
	}

	hasDiscrepancy := len(answerSignatures) > 1

	// JSON mode
	if jsonOutput {
		rep := output.Report{
			Mode:            "compare",
			Target:          records.NormalizeDomain(domain),
			Timestamp:       time.Now().UTC(),
			TotalDurationMs: float64(totalDuration.Microseconds()) / 1000.0,
			Comparison: &output.ComparisonReport{
				Domain:      records.NormalizeDomain(domain),
				Type:        targetType,
				Discrepancy: hasDiscrepancy,
				Results:     results,
			},
		}
		return output.PrintJSON(w, rep)
	}

	// Terminal output
	fmt.Fprintf(w, "\n%s %s (%s record)\n\n",
		theme.BoldCyan.Sprint("RESOLVER COMPARISON —"),
		theme.Bold.Sprint(records.NormalizeDomain(domain)),
		targetType,
	)

	table := formatting.NewTable("Resolver", targetType+" Result", "Time")

	for _, res := range results {
		resCol := res.Resolver.Name
		var resultCol string
		if len(res.Records) > 0 {
			var vals []string
			for _, rec := range res.Records {
				vals = append(vals, rec.Value)
			}
			resultCol = strings.Join(vals, ", ")
		} else if res.Error != "" {
			resultCol = theme.Red.Sprintf("(%s)", res.Error)
		} else {
			resultCol = theme.Dim.Sprintf("(%s)", res.RcodeName)
		}

		timeCol := theme.FormatLatency(res.LatencyFormatted, float64(res.Latency.Milliseconds()))

		// If discrepancy detected and multiple distinct groups exist, format cleanly
		table.AddRow(resCol, resultCol, timeCol)
	}

	table.Render(w)
	fmt.Fprintln(w)

	if hasDiscrepancy {
		fmt.Fprintf(w, "%s %s\n",
			theme.BoldYellow.Sprint(formatting.DefaultSymbols.Warning),
			theme.BoldYellow.Sprint("Resolver disagreement detected (answers differ across resolvers)"),
		)
		fmt.Fprintf(w, "%s\n\n",
			theme.Dim.Sprint("Note: Different results do not imply any single resolver is inherently correct (e.g. Anycast routing, CDN geolocation, or active propagation)."),
		)
	}

	fmt.Fprintf(w, "%s %s\n",
		theme.Dim.Sprint("Comparison completed in:"),
		theme.Bold.Sprint(totalDuration.Round(time.Millisecond)),
	)

	return nil
}
