package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/m5rcel-vibecodes/dnsfuck/pkg/dnssec"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/formatting"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/output"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/records"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/resolver"
)

func runDNSSEC(ctx context.Context, w io.Writer, domain string, r resolver.Resolver, isCustomResolver bool, jsonOutput bool) error {
	theme := formatting.CurrentTheme

	res := dnssec.Diagnose(ctx, domain, r)
	var fallbackNotice string

	if (!res.HasDS && !res.HasDNSKEY) && !isCustomResolver {
		cfRes := dnssec.Diagnose(ctx, domain, resolver.Cloudflare)
		if cfRes.HasDS || cfRes.HasDNSKEY {
			localHost := r.Host
			res = cfRes
			r = resolver.Cloudflare
			fallbackNotice = fmt.Sprintf("Local resolver (%s) returned no DNSSEC data (possible DNS sinkhole or VPN split).\nDisplaying verified DNSSEC diagnostics from %s (%s):",
				localHost, resolver.Cloudflare.Name, resolver.Cloudflare.Host)
		}
	}

	if jsonOutput {
		rep := output.Report{
			Mode:            "dnssec",
			Target:          records.NormalizeDomain(domain),
			Timestamp:       time.Now().UTC(),
			TotalDurationMs: float64(res.Duration.Microseconds()) / 1000.0,
			DNSSEC:          res,
		}
		return output.PrintJSON(w, rep)
	}

	fmt.Fprintf(w, "\n%s %s\n\n",
		theme.BoldCyan.Sprint("DNSSEC DIAGNOSTIC —"),
		theme.Bold.Sprint(records.NormalizeDomain(domain)),
	)

	if fallbackNotice != "" {
		fmt.Fprintf(w, "%s %s\n\n",
			theme.BoldYellow.Sprint(formatting.DefaultSymbols.Warning),
			theme.Yellow.Sprint(fallbackNotice),
		)
	}

	// Status badge
	var statusBadge string
	switch res.Status {
	case dnssec.StatusSecure:
		statusBadge = theme.BoldGreen.Sprintf("[SECURE] %s", res.Summary)
	case dnssec.StatusUnsigned:
		statusBadge = theme.Dim.Sprintf("[UNSIGNED] %s", res.Summary)
	case dnssec.StatusBogus:
		statusBadge = theme.BoldRed.Sprintf("[BOGUS] %s", res.Summary)
	default:
		statusBadge = theme.BoldYellow.Sprintf("[INDETERMINATE] %s", res.Summary)
	}

	fmt.Fprintf(w, "%s %s\n", theme.Bold.Sprint("Overall Status:"), statusBadge)
	fmt.Fprintf(w, "%s %s\n\n", theme.Dim.Sprint("Validation:"), res.ValidationNote)

	// Records presence overview
	tablePresence := formatting.NewTable("Component", "Status", "Details")
	tablePresence.AddRow(
		"Parent DS Delegation",
		formatPresence(res.HasDS),
		fmt.Sprintf("%d record(s) found at parent zone", len(res.DSRecords)),
	)
	tablePresence.AddRow(
		"Apex DNSKEY Keys",
		formatPresence(res.HasDNSKEY),
		fmt.Sprintf("%d key(s) published at apex", len(res.Keys)),
	)
	tablePresence.AddRow(
		"Cryptographic Signatures (RRSIG)",
		formatPresence(res.HasRRSIG),
		fmt.Sprintf("%d active signature(s) inspected", len(res.Signatures)),
	)
	tablePresence.AddRow(
		"Resolver AD Flag (Authenticated Data)",
		formatValidationFlag(res.ResolverAD, res.ValidatingResolverAD),
		"Resolver cryptographic chain verification",
	)
	tablePresence.Render(w)
	fmt.Fprintln(w)

	// Display DS Records if present
	if len(res.DSRecords) > 0 {
		fmt.Fprintf(w, "%s\n", theme.Bold.Sprint("DELEGATION SIGNER (DS) RECORDS"))
		tDS := formatting.NewTable("Key Tag", "Algorithm", "Digest Type", "Digest", "Matches Apex DNSKEY")
		for _, ds := range res.DSRecords {
			matchStr := theme.Dim.Sprint("No match")
			if ds.MatchesKey {
				matchStr = theme.BoldGreen.Sprint("✔ Match confirmed")
			}
			digestTrunc := ds.Digest
			if len(digestTrunc) > 28 {
				digestTrunc = digestTrunc[:24] + "..."
			}
			tDS.AddRow(fmt.Sprintf("%d", ds.KeyTag), ds.Algorithm, ds.DigestType, digestTrunc, matchStr)
		}
		tDS.Render(w)
		fmt.Fprintln(w)
	}

	// Display DNSKEY Records if present
	if len(res.Keys) > 0 {
		fmt.Fprintf(w, "%s\n", theme.Bold.Sprint("DNSKEY RECORDS (ZONE KEYS)"))
		tKey := formatting.NewTable("Key Tag", "Role", "Algorithm", "Flags", "Public Key Preview")
		for _, k := range res.Keys {
			pkPreview := k.PublicKey
			if len(pkPreview) > 24 {
				pkPreview = pkPreview[:20] + "..."
			}
			tKey.AddRow(fmt.Sprintf("%d", k.KeyTag), k.Type, k.Algorithm, fmt.Sprintf("%d", k.Flags), pkPreview)
		}
		tKey.Render(w)
		fmt.Fprintln(w)
	}

	// Display Signatures if present
	if len(res.Signatures) > 0 {
		fmt.Fprintf(w, "%s\n", theme.Bold.Sprint("RESOURCE RECORD SIGNATURES (RRSIG)"))
		tSig := formatting.NewTable("Type Covered", "Algorithm", "Key Tag", "Expiration", "Status")
		for _, s := range res.Signatures {
			statusStr := theme.Green.Sprint("Valid")
			if s.IsExpired {
				statusStr = theme.BoldRed.Sprint("Expired")
			}
			tSig.AddRow(
				s.TypeCovered,
				s.Algorithm,
				fmt.Sprintf("%d", s.KeyTag),
				s.Expiration.Format(time.RFC3339),
				statusStr,
			)
		}
		tSig.Render(w)
		fmt.Fprintln(w)
	}

	if len(res.Errors) > 0 {
		fmt.Fprintf(w, "%s\n", theme.BoldRed.Sprint("DNSSEC ERRORS / WARNINGS"))
		for _, errStr := range res.Errors {
			fmt.Fprintf(w, "  %s %s\n", theme.Red.Sprint(formatting.DefaultSymbols.Warning), errStr)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "%s %s  %s %s\n",
		theme.Dim.Sprint("Inspected via:"), r.Host,
		theme.Dim.Sprint("Diagnostic time:"), theme.Bold.Sprint(res.Duration.Round(time.Millisecond)),
	)

	return nil
}

func formatPresence(present bool) string {
	theme := formatting.CurrentTheme
	if present {
		return theme.BoldGreen.Sprint("✔ Present")
	}
	return theme.Dim.Sprint("— Absent")
}

func formatValidationFlag(localAD, publicAD bool) string {
	theme := formatting.CurrentTheme
	if localAD {
		return theme.BoldGreen.Sprint("✔ Set (Local resolver)")
	}
	if publicAD {
		return theme.Green.Sprint("✔ Set (Public resolver)")
	}
	return theme.Dim.Sprint("— Not Set")
}
