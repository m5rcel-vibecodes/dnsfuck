package cli

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/formatting"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/records"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/resolver"
)

var (
	// Version info (can be populated via -ldflags)
	Version   = "1.0.0"
	Commit    = "none"
	BuildDate = "unknown"
)

// Options holds CLI flag options.
type Options struct {
	Types       []string
	Resolvers   []string
	Compare     bool
	Propagation bool
	DNSSEC      bool
	Trace       bool
	JSON        bool
	Short       bool
	NoColor     bool
	ForceTCP    bool
	Timeout     time.Duration
	Watch       int
	ShowVersion bool
}

// NewRootCmd creates and returns the base cobra command for dnsfuck.
func NewRootCmd() *cobra.Command {
	opts := &Options{}

	cmd := &cobra.Command{
		Use:   "dnsfuck <domain>",
		Short: "A production-grade, serious DNS diagnostic and troubleshooting CLI tool",
		Long: `dnsfuck is a fast, reliable, and comprehensive DNS diagnostic utility.
It replaces repetitive dig/nslookup queries with instant domain diagnostics,
multi-resolver comparisons, global propagation checks, DNSSEC chain inspection,
and iterative root traces.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.ShowVersion {
				fmt.Printf("dnsfuck v%s (%s, %s)\n", Version, Commit, BuildDate)
				return nil
			}

			if len(args) == 0 {
				return cmd.Help()
			}

			domain := cleanDomainInput(args[0])
			if domain == "" {
				return fmt.Errorf("invalid or empty domain provided")
			}

			if opts.NoColor {
				formatting.CurrentTheme.DisableColor()
			}

			// Validate record types if provided
			for _, t := range opts.Types {
				if !records.IsSupportedType(t) {
					return fmt.Errorf("unsupported record type: %q. Supported types: %s",
						t, strings.Join(records.SupportedTypes, ", "))
				}
			}

			// Parse custom resolvers
			var parsedResolvers []resolver.Resolver
			for _, rStr := range opts.Resolvers {
				res, err := resolver.ParseResolver(rStr)
				if err != nil {
					return fmt.Errorf("invalid resolver %q: %w", rStr, err)
				}
				res.Timeout = opts.Timeout
				res.ForceTCP = opts.ForceTCP
				parsedResolvers = append(parsedResolvers, res)
			}

			// Determine primary resolver for standard / dnssec diagnostics
			primaryResolver := resolver.GetPrimarySystemResolver()
			if len(parsedResolvers) > 0 {
				primaryResolver = parsedResolvers[0]
			}
			primaryResolver.Timeout = opts.Timeout
			primaryResolver.ForceTCP = opts.ForceTCP

			// Watch mode execution
			if opts.Watch > 0 {
				return runWatchLoop(cmd.OutOrStdout(), domain, opts, primaryResolver, parsedResolvers)
			}

			// Single-shot execution
			return executeAction(context.Background(), cmd.OutOrStdout(), domain, opts, primaryResolver, parsedResolvers)
		},
	}

	// Register flags
	cmd.Flags().StringSliceVarP(&opts.Types, "type", "t", nil, "DNS record type(s) to query (A, AAAA, MX, NS, TXT, SOA, SRV, CAA, PTR, DNSKEY, DS)")
	cmd.Flags().StringSliceVarP(&opts.Resolvers, "resolver", "r", nil, "Custom resolver(s) (e.g. 1.1.1.1, 8.8.8.8:5353, [::1]:53, or alias)")
	cmd.Flags().BoolVarP(&opts.Compare, "compare", "c", false, "Compare resolution across multiple resolvers")
	cmd.Flags().BoolVarP(&opts.Propagation, "propagation", "p", false, "Check worldwide propagation across public resolvers")
	cmd.Flags().BoolVarP(&opts.DNSSEC, "dnssec", "d", false, "Inspect DNSSEC keys, DS records, signatures, and validation status")
	cmd.Flags().BoolVar(&opts.Trace, "trace", false, "Trace iterative resolution from root servers down to authoritative")
	cmd.Flags().BoolVarP(&opts.JSON, "json", "j", false, "Output results as structured JSON")
	cmd.Flags().BoolVarP(&opts.Short, "short", "s", false, "Output record values only (ideal for scripts)")
	cmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "Disable colored output")
	cmd.Flags().BoolVar(&opts.ForceTCP, "tcp", false, "Force TCP for DNS queries")
	cmd.Flags().DurationVar(&opts.Timeout, "timeout", resolver.DefaultTimeout, "Query timeout duration")
	cmd.Flags().IntVarP(&opts.Watch, "watch", "w", 0, "Re-run diagnostic every N seconds")
	cmd.Flags().BoolVarP(&opts.ShowVersion, "version", "v", false, "Display version and build information")

	return cmd
}

func executeAction(ctx context.Context, out io.Writer, domain string, opts *Options, primary resolver.Resolver, customResolvers []resolver.Resolver) error {
	isCustom := len(customResolvers) > 0
	switch {
	case opts.Trace:
		return runTrace(ctx, out, domain, opts.Types, opts.Timeout, opts.JSON)
	case opts.DNSSEC:
		return runDNSSEC(ctx, out, domain, primary, isCustom, opts.JSON)
	case opts.Propagation:
		return runPropagation(ctx, out, domain, opts.Types, opts.Timeout, customResolvers, opts.JSON)
	case opts.Compare:
		return runCompare(ctx, out, domain, opts.Types, customResolvers, opts.JSON)
	default:
		return runDiagnostic(ctx, out, domain, opts.Types, primary, isCustom, opts.JSON, opts.Short)
	}
}

func runWatchLoop(out io.Writer, domain string, opts *Options, primary resolver.Resolver, customResolvers []resolver.Resolver) error {
	interval := time.Duration(opts.Watch) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if !opts.JSON {
			formatting.ClearScreen()
			fmt.Fprintf(out, "dnsfuck watch mode (every %ds) — %s — Press Ctrl+C to exit\n", opts.Watch, time.Now().Format("15:04:05"))
		}

		ctx, cancel := context.WithTimeout(context.Background(), interval)
		_ = executeAction(ctx, out, domain, opts, primary, customResolvers)
		cancel()

		select {
		case <-sigChan:
			fmt.Fprintln(out, "\nWatch mode stopped.")
			return nil
		case <-ticker.C:
		}
	}
}

// cleanDomainInput strips http/https protocols or URL paths if mistakenly pasted.
func cleanDomainInput(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
	}
	// Strip trailing slashes
	raw = strings.TrimRight(raw, "/")
	return records.NormalizeDomain(raw)
}
