package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/records"
)

// DefaultTimeout is the standard DNS query timeout.
const DefaultTimeout = 3 * time.Second

// DefaultEDNS0Size is the recommended DNS buffer size per DNS Flag Day (1232 bytes).
const DefaultEDNS0Size = 1232

// Resolver represents a target DNS nameserver configuration.
type Resolver struct {
	Name      string        `json:"name"`
	Host      string        `json:"host"`
	Timeout   time.Duration `json:"timeout"`
	ForceTCP  bool          `json:"force_tcp"`
	EDNS0Size uint16        `json:"edns0_size"`
	DNSSECOk  bool          `json:"dnssec_ok"`
}

// QueryResult holds the complete result of a DNS query against a specific resolver.
type QueryResult struct {
	Resolver            Resolver         `json:"resolver"`
	Domain              string           `json:"domain"`
	Type                string           `json:"type"`
	Rcode               int              `json:"rcode"`
	RcodeName           string           `json:"rcode_name"`
	Latency             time.Duration    `json:"latency_ns"`
	LatencyFormatted    string           `json:"latency"`
	Records             []records.Record `json:"records"`
	Authorities         []records.Record `json:"authorities,omitempty"`
	Additionals         []records.Record `json:"additionals,omitempty"`
	Truncated           bool             `json:"truncated"`
	AuthenticatedData   bool             `json:"authenticated_data"` // AD flag
	AuthoritativeAnswer bool             `json:"authoritative"`      // AA flag
	Error               string           `json:"error,omitempty"`
	RawError            error            `json:"-"`
}

// New creates a Resolver with standard defaults.
func New(name, host string) Resolver {
	return Resolver{
		Name:      name,
		Host:      NormalizeHostPort(host),
		Timeout:   DefaultTimeout,
		ForceTCP:  false,
		EDNS0Size: DefaultEDNS0Size,
		DNSSECOk:  true,
	}
}

// NormalizeHostPort formats a server address, ensuring port :53 is appended if not present.
func NormalizeHostPort(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") {
		// IPv6 with brackets
		if !strings.Contains(host, "]:") {
			return host + ":53"
		}
		return host
	}
	// Check if already has host:port
	_, _, err := net.SplitHostPort(host)
	if err == nil {
		return host
	}
	// If IPv6 without brackets
	if strings.Count(host, ":") > 1 {
		return "[" + host + "]:53"
	}
	return net.JoinHostPort(host, "53")
}

// Query executes a DNS query against the resolver for domain and record type.
func (r Resolver) Query(ctx context.Context, domain string, qtype uint16) *QueryResult {
	fqdn := records.EnsureFQDN(domain)
	typeName := records.Uint16ToType(qtype)

	result := &QueryResult{
		Resolver: r,
		Domain:   records.NormalizeDomain(domain),
		Type:     typeName,
		Records:  make([]records.Record, 0),
	}

	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, qtype)
	msg.RecursionDesired = true

	if r.EDNS0Size > 0 || r.DNSSECOk {
		msg.SetEdns0(r.EDNS0Size, r.DNSSECOk)
	}

	client := &dns.Client{
		Timeout: r.Timeout,
	}

	if r.ForceTCP {
		client.Net = "tcp"
	} else {
		client.Net = "udp"
	}

	start := time.Now()
	resp, rtt, err := client.ExchangeContext(ctx, msg, r.Host)
	result.Latency = rtt
	if rtt == 0 {
		result.Latency = time.Since(start)
	}
	result.LatencyFormatted = fmt.Sprintf("%v", result.Latency.Round(time.Millisecond))

	if err != nil {
		result.RawError = err
		result.Error = FormatNetworkError(err)
		result.RcodeName = "ERROR"
		return result
	}

	// Automatic TCP retry on truncation if UDP was used
	if resp.Truncated && !r.ForceTCP {
		tcpClient := &dns.Client{
			Net:     "tcp",
			Timeout: r.Timeout,
		}
		tcpStart := time.Now()
		tcpResp, tcpRtt, tcpErr := tcpClient.ExchangeContext(ctx, msg, r.Host)
		if tcpErr == nil {
			resp = tcpResp
			result.Latency = tcpRtt
			if tcpRtt == 0 {
				result.Latency = time.Since(tcpStart)
			}
			result.LatencyFormatted = fmt.Sprintf("%v", result.Latency.Round(time.Millisecond))
		}
	}

	result.Rcode = resp.Rcode
	result.RcodeName = dns.RcodeToString[resp.Rcode]
	if result.RcodeName == "" {
		result.RcodeName = fmt.Sprintf("RCODE%d", resp.Rcode)
	}
	result.Truncated = resp.Truncated
	result.AuthenticatedData = resp.AuthenticatedData
	result.AuthoritativeAnswer = resp.Authoritative

	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG && qtype != dns.TypeRRSIG && qtype != dns.TypeANY {
			continue
		}
		result.Records = append(result.Records, records.ParseRR(rr))
	}
	for _, rr := range resp.Ns {
		result.Authorities = append(result.Authorities, records.ParseRR(rr))
	}
	for _, rr := range resp.Extra {
		// Ignore EDNS0 pseudo-RR in extra records
		if rr.Header().Rrtype != dns.TypeOPT {
			result.Additionals = append(result.Additionals, records.ParseRR(rr))
		}
	}

	return result
}

// FormatNetworkError provides friendly context for network failures.
func FormatNetworkError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if strings.Contains(s, "i/o timeout") {
		return "Query timeout (no response within deadline)"
	}
	if strings.Contains(s, "connection refused") {
		return "Connection refused by server"
	}
	if strings.Contains(s, "no such host") {
		return "Resolver address could not be resolved"
	}
	if strings.Contains(s, "network is unreachable") {
		return "Network unreachable"
	}
	return s
}
