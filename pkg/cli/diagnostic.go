package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/m5rcel-vibecodes/dnsfuck/pkg/dnssec"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/formatting"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/output"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/records"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/resolver"
	"github.com/miekg/dns"
)

func runDiagnostic(ctx context.Context, w io.Writer, domain string, types []string, r resolver.Resolver, isCustomResolver bool, jsonOutput bool, shortOutput bool) error {
	start := time.Now()
	theme := formatting.CurrentTheme

	// Determine record types to query
	typesToQuery := types
	if len(typesToQuery) == 0 {
		typesToQuery = records.DefaultDiagnosticTypes
	}

	results := make(map[string]*resolver.QueryResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, t := range typesToQuery {
		qtype, err := records.TypeToUint16(t)
		if err != nil {
			continue
		}
		wg.Add(1)
		go func(typeName string, qt uint16) {
			defer wg.Done()
			res := r.Query(ctx, domain, qt)
			mu.Lock()
			results[typeName] = res
			mu.Unlock()
		}(strings.ToUpper(t), qtype)
	}

	// Also check DNSSEC in default diagnostic mode
	var dnssecResult *dnssec.DiagnosticResult
	if len(types) == 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dnssecResult = dnssec.Diagnose(ctx, domain, r)
		}()
	}

	wg.Wait()

	// Check if entire domain returned NXDOMAIN or empty on primary resolver
	hasNXDOMAIN := false
	allEmptyOrError := true
	for _, res := range results {
		if res.Rcode == dns.RcodeNameError {
			hasNXDOMAIN = true
		}
		if len(res.Records) > 0 {
			allEmptyOrError = false
		}
	}

	var fallbackNotice string

	// If local/system resolver returned NXDOMAIN or error, verify whether domain exists in public DNS
	if (hasNXDOMAIN || allEmptyOrError) && !isCustomResolver {
		fallbackRes := resolver.Cloudflare
		fbResults := make(map[string]*resolver.QueryResult)
		var fbWg sync.WaitGroup
		var fbMu sync.Mutex

		for _, t := range typesToQuery {
			qtype, err := records.TypeToUint16(t)
			if err != nil {
				continue
			}
			fbWg.Add(1)
			go func(typeName string, qt uint16) {
				defer fbWg.Done()
				fbRes := fallbackRes.Query(ctx, domain, qt)
				fbMu.Lock()
				fbResults[typeName] = fbRes
				fbMu.Unlock()
			}(strings.ToUpper(t), qtype)
		}
		fbWg.Wait()

		fallbackHasRecords := false
		for _, res := range fbResults {
			if len(res.Records) > 0 {
				fallbackHasRecords = true
				break
			}
		}

		if fallbackHasRecords {
			// Domain exists in public DNS! Local resolver is blocking/sinkholing or split-DNS
			localHost := r.Host
			results = fbResults
			r = fallbackRes
			hasNXDOMAIN = false
			fallbackNotice = fmt.Sprintf("Local resolver (%s) returned NXDOMAIN (possible DNS sinkhole, VPN split, or blocklist).\nDisplaying verified records from %s (%s):",
				localHost, fallbackRes.Name, fallbackRes.Host)

			// Update DNSSEC result using fallback resolver
			if len(types) == 0 {
				dnssecResult = dnssec.Diagnose(ctx, domain, fallbackRes)
			}
		}
	}

	totalDuration := time.Since(start)

	// JSON mode
	if jsonOutput {
		recordMap := make(map[string][]records.Record)
		rcode := "NOERROR"
		for t, res := range results {
			recordMap[t] = res.Records
			if res.RcodeName != "NOERROR" && res.RcodeName != "" {
				rcode = res.RcodeName
			}
		}

		var errs []string
		if fallbackNotice != "" {
			errs = append(errs, fallbackNotice)
		}

		rep := output.Report{
			Mode:            "diagnostic",
			Target:          records.NormalizeDomain(domain),
			Timestamp:       time.Now().UTC(),
			TotalDurationMs: float64(totalDuration.Microseconds()) / 1000.0,
			Errors:          errs,
			Diagnostic: &output.DiagnosticReport{
				Domain:   records.NormalizeDomain(domain),
				Resolver: r,
				Records:  recordMap,
				DNSSEC:   dnssecResult,
				Rcode:    rcode,
			},
		}
		return output.PrintJSON(w, rep)
	}

	// Short mode
	if shortOutput {
		for _, t := range typesToQuery {
			tUpper := strings.ToUpper(t)
			if res, ok := results[tUpper]; ok {
				for _, rec := range res.Records {
					fmt.Fprintln(w, rec.Value)
				}
			}
		}
		return nil
	}

	// Human-readable terminal output
	fmt.Fprintf(w, "\n%s %s\n\n", theme.BoldCyan.Sprint("DNS DIAGNOSTIC —"), theme.Bold.Sprint(records.NormalizeDomain(domain)))

	if fallbackNotice != "" {
		fmt.Fprintf(w, "%s %s\n\n",
			theme.BoldYellow.Sprint(formatting.DefaultSymbols.Warning),
			theme.Yellow.Sprint(fallbackNotice),
		)
	}

	if hasNXDOMAIN {
		fmt.Fprintf(w, "%s %s\n\n", theme.BoldRed.Sprint(formatting.DefaultSymbols.Cross), theme.BoldRed.Sprint("Domain does not exist (NXDOMAIN)"))
		fmt.Fprintf(w, "%s %s\n", theme.Dim.Sprint("Resolver:"), r.Host)
		fmt.Fprintf(w, "%s %v\n\n", theme.Dim.Sprint("Diagnostic time:"), totalDuration.Round(time.Millisecond))
		return nil
	}

	for _, t := range typesToQuery {
		tUpper := strings.ToUpper(t)
		res, ok := results[tUpper]
		if !ok {
			continue
		}

		// When queried specifically via --type, always show the section even if empty
		isExplicitType := len(types) > 0

		if len(res.Records) > 0 {
			fmt.Fprintf(w, "%s\n", theme.Bold.Sprint(tUpper))
			for _, rec := range res.Records {
				fmt.Fprintf(w, "  %s\n", rec.Value)
			}
			fmt.Fprintln(w)
		} else if isExplicitType {
			fmt.Fprintf(w, "%s\n", theme.Bold.Sprint(tUpper))
			if res.Error != "" {
				fmt.Fprintf(w, "  %s\n", theme.Red.Sprintf("(Error: %s)", res.Error))
			} else {
				fmt.Fprintf(w, "  %s\n", theme.Dim.Sprintf("(No %s records found - %s)", tUpper, res.RcodeName))
			}
			fmt.Fprintln(w)
		}
	}

	// DNSSEC Summary
	if dnssecResult != nil {
		fmt.Fprintf(w, "%s\n", theme.Bold.Sprint("DNSSEC"))
		switch dnssecResult.Status {
		case dnssec.StatusSecure:
			fmt.Fprintf(w, "  %s %s\n", theme.BoldGreen.Sprint(formatting.DefaultSymbols.Check), "Supported (Chain of Trust intact)")
		case dnssec.StatusUnsigned:
			fmt.Fprintf(w, "  %s %s\n", theme.Dim.Sprint("—"), "Unsigned (No DNSSEC records)")
		case dnssec.StatusBogus:
			fmt.Fprintf(w, "  %s %s\n", theme.BoldRed.Sprint(formatting.DefaultSymbols.Warning), theme.Red.Sprint(dnssecResult.Summary))
		default:
			fmt.Fprintf(w, "  %s\n", dnssecResult.Summary)
		}
		fmt.Fprintln(w)
	}

	// Timing footer
	fmt.Fprintf(w, "%s %s  %s %s\n",
		theme.Dim.Sprint("Resolver:"), r.Host,
		theme.Dim.Sprint("Total diagnostic time:"), theme.Bold.Sprint(totalDuration.Round(time.Millisecond)),
	)

	return nil
}
