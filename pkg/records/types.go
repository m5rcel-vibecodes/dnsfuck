package records

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// SupportedTypes lists all record types natively supported and queried by default or via --type.
var SupportedTypes = []string{
	"A",
	"AAAA",
	"CNAME",
	"MX",
	"NS",
	"TXT",
	"SOA",
	"SRV",
	"CAA",
	"PTR",
	"DNSKEY",
	"DS",
}

// DefaultDiagnosticTypes are the default record types queried during a standard diagnostic run.
var DefaultDiagnosticTypes = []string{
	"A",
	"AAAA",
	"CNAME",
	"MX",
	"NS",
	"TXT",
	"SOA",
}

// Record represents a normalized, human-friendly, and JSON-serializable DNS record.
type Record struct {
	Type  string         `json:"type"`
	Name  string         `json:"name"`
	TTL   uint32         `json:"ttl"`
	Class string         `json:"class,omitempty"`
	Value string         `json:"value"`
	Extra map[string]any `json:"extra,omitempty"`
}

// RecordSet represents a collection of DNS records of a specific type.
type RecordSet struct {
	Type    string   `json:"type"`
	Records []Record `json:"records"`
	Error   string   `json:"error,omitempty"`
}

// String returns a clean one-line representation of the record.
func (r Record) String() string {
	return r.Value
}

// TypeToUint16 maps a record type string (e.g. "A", "MX") to its dns uint16 type.
func TypeToUint16(t string) (uint16, error) {
	upper := strings.ToUpper(strings.TrimSpace(t))
	if qtype, ok := dns.StringToType[upper]; ok {
		return qtype, nil
	}
	return 0, fmt.Errorf("unsupported or unknown DNS record type: %s", t)
}

// Uint16ToType maps a dns uint16 type to its uppercase record type name.
func Uint16ToType(t uint16) string {
	if name, ok := dns.TypeToString[t]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", t)
}

// IsSupportedType checks if a given record type string is supported.
func IsSupportedType(t string) bool {
	upper := strings.ToUpper(strings.TrimSpace(t))
	for _, supported := range SupportedTypes {
		if supported == upper {
			return true
		}
	}
	return false
}

// NormalizeDomain ensures the domain is in lowercase and has any redundant spaces trimmed.
// Trailing dot is stripped for display unless root domain ".".
func NormalizeDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d != "." && strings.HasSuffix(d, ".") {
		d = strings.TrimSuffix(d, ".")
	}
	return d
}

// EnsureFQDN ensures the domain ends with a trailing dot for DNS wire format queries.
func EnsureFQDN(domain string) string {
	d := strings.TrimSpace(domain)
	if !strings.HasSuffix(d, ".") {
		return d + "."
	}
	return d
}
