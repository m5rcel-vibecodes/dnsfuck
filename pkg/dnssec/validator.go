package dnssec

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/m5rcel-vibecodes/dnsfuck/pkg/records"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/resolver"
	"github.com/miekg/dns"
)

// Diagnose inspects the DNSSEC status of a domain.
func Diagnose(ctx context.Context, domain string, r resolver.Resolver) *DiagnosticResult {
	start := time.Now()
	cleanDomain := records.NormalizeDomain(domain)
	fqdn := records.EnsureFQDN(domain)

	diag := &DiagnosticResult{
		Domain:   cleanDomain,
		Duration: 0,
	}

	// 1. Query DNSKEY
	dnskeyRes := r.Query(ctx, fqdn, dns.TypeDNSKEY)
	// 2. Query DS
	dsRes := r.Query(ctx, fqdn, dns.TypeDS)
	// 3. Query SOA (or A) with DO bit to check AD flag and RRSIGs
	soaRes := r.Query(ctx, fqdn, dns.TypeSOA)

	// Collect AD flag from target resolver
	diag.ResolverAD = soaRes.AuthenticatedData || dnskeyRes.AuthenticatedData || dsRes.AuthenticatedData

	var parsedKeys []*dns.DNSKEY
	for _, rec := range dnskeyRes.Records {
		diag.RawRecords = append(diag.RawRecords, rec)
	}

	// Re-parse raw records for deep DNSKEY info
	client := &dns.Client{Timeout: r.Timeout}
	msgKey := new(dns.Msg)
	msgKey.SetQuestion(fqdn, dns.TypeDNSKEY)
	msgKey.SetEdns0(1232, true)
	if respKey, _, err := client.ExchangeContext(ctx, msgKey, r.Host); err == nil && respKey != nil {
		for _, rr := range respKey.Answer {
			if k, ok := rr.(*dns.DNSKEY); ok {
				parsedKeys = append(parsedKeys, k)
				diag.HasDNSKEY = true
				keyType := "ZSK"
				if k.Flags&257 == 257 {
					keyType = "KSK / SEP"
				}
				diag.Keys = append(diag.Keys, KeyInfo{
					KeyTag:    k.KeyTag(),
					Algorithm: records.AlgorithmToString(k.Algorithm),
					AlgoID:    k.Algorithm,
					Type:      keyType,
					Flags:     k.Flags,
					PublicKey: k.PublicKey,
				})
			} else if sig, ok := rr.(*dns.RRSIG); ok {
				diag.HasRRSIG = true
				exp := time.Unix(int64(sig.Expiration), 0)
				inc := time.Unix(int64(sig.Inception), 0)
				diag.Signatures = append(diag.Signatures, RRSIGInfo{
					TypeCovered: dns.TypeToString[sig.TypeCovered],
					Algorithm:   records.AlgorithmToString(sig.Algorithm),
					KeyTag:      sig.KeyTag,
					SignerName:  records.NormalizeDomain(sig.SignerName),
					Expiration:  exp,
					Inception:   inc,
					IsExpired:   time.Now().After(exp),
				})
			}
		}
	}

	// Parse DS records
	msgDS := new(dns.Msg)
	msgDS.SetQuestion(fqdn, dns.TypeDS)
	msgDS.SetEdns0(1232, true)
	var parsedDS []*dns.DS
	if respDS, _, err := client.ExchangeContext(ctx, msgDS, r.Host); err == nil && respDS != nil {
		for _, rr := range respDS.Answer {
			if dsRec, ok := rr.(*dns.DS); ok {
				parsedDS = append(parsedDS, dsRec)
				diag.HasDS = true
				diag.RawRecords = append(diag.RawRecords, records.ParseRR(rr))

				matches := false
				for _, key := range parsedKeys {
					calculatedDS := key.ToDS(dsRec.DigestType)
					if calculatedDS != nil && strings.EqualFold(calculatedDS.Digest, dsRec.Digest) {
						matches = true
						break
					}
				}

				diag.DSRecords = append(diag.DSRecords, DSInfo{
					KeyTag:     dsRec.KeyTag,
					Algorithm:  records.AlgorithmToString(dsRec.Algorithm),
					DigestType: records.DigestTypeToString(dsRec.DigestType),
					Digest:     dsRec.Digest,
					MatchesKey: matches,
				})
			}
		}
	}

	// Also check public validating resolver (e.g. Cloudflare 1.1.1.1) to see if AD flag is set there
	// in case the user's primary resolver is not validating DNSSEC.
	if !diag.ResolverAD && r.Host != "1.1.1.1:53" {
		cfRes := resolver.Cloudflare.Query(ctx, fqdn, dns.TypeA)
		if cfRes != nil && cfRes.AuthenticatedData {
			diag.ValidatingResolverAD = true
		}
	} else if diag.ResolverAD {
		diag.ValidatingResolverAD = true
	}

	// Determine overall status
	switch {
	case !diag.HasDS && !diag.HasDNSKEY:
		diag.Status = StatusUnsigned
		diag.Summary = "Unsigned (No DNSSEC records detected)"
		diag.ValidationNote = "Domain does not implement DNSSEC. Records are not cryptographically signed."

	case diag.HasDS && diag.HasDNSKEY:
		hasMatch := false
		for _, ds := range diag.DSRecords {
			if ds.MatchesKey {
				hasMatch = true
				break
			}
		}

		if hasMatch {
			diag.Status = StatusSecure
			diag.Summary = "Supported & Validated (Chain of Trust intact)"
			if diag.ResolverAD {
				diag.ValidationNote = fmt.Sprintf("Validated by resolver %s (Authenticated Data flag set)", r.Name)
			} else if diag.ValidatingResolverAD {
				diag.ValidationNote = "Public validating resolver confirmed AD flag (Local resolver does not enforce validation)"
			} else {
				diag.ValidationNote = "DS matches DNSKEY digest, but neither resolver returned AD flag (Validation unavailable in local environment)"
			}
		} else {
			diag.Status = StatusBogus
			diag.Summary = "Bogus / Broken Chain (DS does not match any DNSKEY)"
			diag.ValidationNote = "DS records exist at parent, but could not be matched with active DNSKEY records"
			diag.Errors = append(diag.Errors, "DS and DNSKEY digest mismatch")
		}

	case diag.HasDNSKEY && !diag.HasDS:
		diag.Status = StatusUnsigned
		diag.Summary = "Incomplete DNSSEC (DNSKEY present, but no DS at parent)"
		diag.ValidationNote = "The apex contains DNSKEY records, but the parent TLD has no DS delegation."

	case diag.HasDS && !diag.HasDNSKEY:
		diag.Status = StatusBogus
		diag.Summary = "Bogus (DS present at parent, but no DNSKEY at zone apex)"
		diag.ValidationNote = "Parent zone asserts DNSSEC, but the zone apex returned no DNSKEY records."
		diag.Errors = append(diag.Errors, "Missing DNSKEY records at zone apex")

	default:
		diag.Status = StatusIndeterminate
		diag.Summary = "Indeterminate"
		diag.ValidationNote = "DNSSEC status could not be conclusively determined."
	}

	diag.Duration = time.Since(start)
	return diag
}
