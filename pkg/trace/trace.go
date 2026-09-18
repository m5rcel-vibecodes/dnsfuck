package trace

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/records"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/resolver"
)

// Hop represents a single iterative resolution step in the DNS hierarchy.
type Hop struct {
	Level       int              `json:"level"`
	Zone        string           `json:"zone"`
	ServerName  string           `json:"server_name"`
	ServerIP    string           `json:"server_ip"`
	Latency     time.Duration    `json:"latency_ns"`
	LatencyStr  string           `json:"latency"`
	Rcode       int              `json:"rcode"`
	RcodeName   string           `json:"rcode_name"`
	Authorities []records.Record `json:"authorities,omitempty"`
	Answers     []records.Record `json:"answers,omitempty"`
	Error       string           `json:"error,omitempty"`
}

// TraceResult contains the complete root-to-leaf resolution trace.
type TraceResult struct {
	Domain        string           `json:"domain"`
	Type          string           `json:"type"`
	Hops          []Hop            `json:"hops"`
	FinalAnswers  []records.Record `json:"final_answers,omitempty"`
	TotalDuration time.Duration    `json:"total_duration_ns"`
	Error         string           `json:"error,omitempty"`
}

// Trace performs an iterative resolution from IANA root servers down to authoritative servers.
func Trace(ctx context.Context, domain string, qtype uint16, timeout time.Duration) *TraceResult {
	start := time.Now()
	cleanDomain := records.NormalizeDomain(domain)
	fqdn := records.EnsureFQDN(domain)
	typeName := records.Uint16ToType(qtype)

	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	result := &TraceResult{
		Domain: cleanDomain,
		Type:   typeName,
		Hops:   make([]Hop, 0),
	}

	// Pick initial root server
	root := RootHints[0] // a.root-servers.net
	currentServer := root.IPv4
	currentServerName := root.Name
	currentZone := "."

	client := &dns.Client{
		Timeout: timeout,
	}

	visitedServers := make(map[string]bool)
	const maxHops = 15

	for hopCount := 1; hopCount <= maxHops; hopCount++ {
		hostPort := resolver.NormalizeHostPort(currentServer)

		hop := Hop{
			Level:      hopCount,
			Zone:       currentZone,
			ServerName: currentServerName,
			ServerIP:   currentServer,
		}

		msg := new(dns.Msg)
		msg.SetQuestion(fqdn, qtype)
		msg.RecursionDesired = false // Iterative resolution
		msg.SetEdns0(1232, false)

		qStart := time.Now()
		resp, rtt, err := client.ExchangeContext(ctx, msg, hostPort)
		hop.Latency = rtt
		if rtt == 0 {
			hop.Latency = time.Since(qStart)
		}
		hop.LatencyStr = fmt.Sprintf("%v", hop.Latency.Round(time.Millisecond))

		if err != nil {
			hop.Error = resolver.FormatNetworkError(err)
			hop.RcodeName = "ERROR"
			result.Hops = append(result.Hops, hop)
			result.Error = fmt.Sprintf("Query to %s (%s) failed: %v", currentServerName, currentServer, err)
			break
		}

		hop.Rcode = resp.Rcode
		hop.RcodeName = dns.RcodeToString[resp.Rcode]
		if hop.RcodeName == "" {
			hop.RcodeName = fmt.Sprintf("RCODE%d", resp.Rcode)
		}

		for _, rr := range resp.Answer {
			hop.Answers = append(hop.Answers, records.ParseRR(rr))
		}
		for _, rr := range resp.Ns {
			hop.Authorities = append(hop.Authorities, records.ParseRR(rr))
		}

		result.Hops = append(result.Hops, hop)

		// Check if we received answer records
		if len(resp.Answer) > 0 {
			result.FinalAnswers = hop.Answers
			break
		}

		// Handle NXDOMAIN or other terminating RCODEs
		if resp.Rcode == dns.RcodeNameError {
			result.Error = fmt.Sprintf("Domain does not exist (NXDOMAIN) at %s", currentZone)
			break
		}
		if resp.Rcode != dns.RcodeSuccess {
			result.Error = fmt.Sprintf("Resolution halted with %s at %s", hop.RcodeName, currentZone)
			break
		}

		// Check Authority section for delegations
		var nextNSNames []string
		var newZone string
		for _, rr := range resp.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nextNSNames = append(nextNSNames, records.NormalizeDomain(ns.Ns))
				if newZone == "" {
					newZone = records.NormalizeDomain(ns.Header().Name)
				}
			} else if soa, ok := rr.(*dns.SOA); ok {
				// NODATA response (zone exists, but no records of requested type)
				newZone = records.NormalizeDomain(soa.Header().Name)
				result.Error = fmt.Sprintf("NODATA response from authoritative zone %s (SOA present, no %s records)", newZone, typeName)
				break
			}
		}

		if len(nextNSNames) == 0 {
			if result.Error == "" {
				result.Error = "No delegation NS records or answers returned"
			}
			break
		}

		if newZone != "" {
			currentZone = newZone
		}

		// Look for glue records in Additionals section first
		var nextIP string
		var nextName string

		for _, rr := range resp.Extra {
			if a, ok := rr.(*dns.A); ok {
				name := records.NormalizeDomain(a.Header().Name)
				for _, nsName := range nextNSNames {
					if name == nsName && !visitedServers[a.A.String()] {
						nextIP = a.A.String()
						nextName = name
						break
					}
				}
			}
			if nextIP != "" {
				break
			}
		}

		// If no IPv4 glue found, try IPv6 glue
		if nextIP == "" {
			for _, rr := range resp.Extra {
				if aaaa, ok := rr.(*dns.AAAA); ok {
					name := records.NormalizeDomain(aaaa.Header().Name)
					for _, nsName := range nextNSNames {
						if name == nsName && !visitedServers[aaaa.AAAA.String()] {
							nextIP = aaaa.AAAA.String()
							nextName = name
							break
						}
					}
				}
				if nextIP != "" {
					break
				}
			}
		}

		// If no glue records at all, resolve nameserver out-of-band
		if nextIP == "" {
			for _, nsName := range nextNSNames {
				ips, err := net.LookupHost(nsName)
				if err == nil && len(ips) > 0 {
					for _, ip := range ips {
						if !visitedServers[ip] {
							nextIP = ip
							nextName = nsName
							break
						}
					}
					if nextIP != "" {
						break
					}
				}
			}
		}

		if nextIP == "" {
			result.Error = fmt.Sprintf("Could not resolve IP for delegated nameservers: %s", strings.Join(nextNSNames, ", "))
			break
		}

		visitedServers[nextIP] = true
		currentServer = nextIP
		currentServerName = nextName
	}

	result.TotalDuration = time.Since(start)
	return result
}
