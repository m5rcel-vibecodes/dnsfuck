package records

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// ParseRR converts a dns.RR into our structured Record format.
func ParseRR(rr dns.RR) Record {
	if rr == nil {
		return Record{}
	}

	header := rr.Header()
	typeName := dns.TypeToString[header.Rrtype]
	if typeName == "" {
		typeName = fmt.Sprintf("TYPE%d", header.Rrtype)
	}

	rec := Record{
		Type:  typeName,
		Name:  NormalizeDomain(header.Name),
		TTL:   header.Ttl,
		Class: dns.ClassToString[header.Class],
		Extra: make(map[string]any),
	}

	switch v := rr.(type) {
	case *dns.A:
		rec.Value = v.A.String()
	case *dns.AAAA:
		rec.Value = v.AAAA.String()
	case *dns.CNAME:
		rec.Value = NormalizeDomain(v.Target)
	case *dns.MX:
		exchange := NormalizeDomain(v.Mx)
		rec.Value = fmt.Sprintf("%d %s", v.Preference, exchange)
		rec.Extra["preference"] = v.Preference
		rec.Extra["exchange"] = exchange
	case *dns.NS:
		rec.Value = NormalizeDomain(v.Ns)
	case *dns.TXT:
		var escaped []string
		for _, s := range v.Txt {
			escaped = append(escaped, fmt.Sprintf("%q", s))
		}
		rec.Value = strings.Join(escaped, " ")
		rec.Extra["entries"] = v.Txt
	case *dns.SOA:
		ns := NormalizeDomain(v.Ns)
		mbox := NormalizeDomain(v.Mbox)
		rec.Value = fmt.Sprintf("%s %s (serial: %d, refresh: %ds, retry: %ds, expire: %ds, min: %ds)",
			ns, mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
		rec.Extra["primary_ns"] = ns
		rec.Extra["mailbox"] = mbox
		rec.Extra["serial"] = v.Serial
		rec.Extra["refresh"] = v.Refresh
		rec.Extra["retry"] = v.Retry
		rec.Extra["expire"] = v.Expire
		rec.Extra["minimum_ttl"] = v.Minttl
	case *dns.SRV:
		target := NormalizeDomain(v.Target)
		rec.Value = fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, target)
		rec.Extra["priority"] = v.Priority
		rec.Extra["weight"] = v.Weight
		rec.Extra["port"] = v.Port
		rec.Extra["target"] = target
	case *dns.CAA:
		rec.Value = fmt.Sprintf("%d %s %q", v.Flag, v.Tag, v.Value)
		rec.Extra["flag"] = v.Flag
		rec.Extra["tag"] = v.Tag
		rec.Extra["value"] = v.Value
	case *dns.PTR:
		rec.Value = NormalizeDomain(v.Ptr)
	case *dns.DNSKEY:
		keyTag := v.KeyTag()
		algo := AlgorithmToString(v.Algorithm)
		role := "ZSK"
		if v.Flags&257 == 257 {
			role = "KSK / SEP"
		}
		rec.Value = fmt.Sprintf("tag:%d [%s] algo:%s (flags:%d)", keyTag, role, algo, v.Flags)
		rec.Extra["key_tag"] = keyTag
		rec.Extra["algorithm"] = algo
		rec.Extra["flags"] = v.Flags
		rec.Extra["protocol"] = v.Protocol
		rec.Extra["public_key"] = v.PublicKey
	case *dns.DS:
		algo := AlgorithmToString(v.Algorithm)
		digestType := DigestTypeToString(v.DigestType)
		rec.Value = fmt.Sprintf("tag:%d algo:%s digest_type:%s %s", v.KeyTag, algo, digestType, v.Digest)
		rec.Extra["key_tag"] = v.KeyTag
		rec.Extra["algorithm"] = algo
		rec.Extra["digest_type"] = digestType
		rec.Extra["digest"] = v.Digest
	default:
		// Fallback to dns.RR String with header stripped
		raw := v.String()
		parts := strings.Fields(raw)
		if len(parts) >= 5 {
			rec.Value = strings.Join(parts[4:], " ")
		} else {
			rec.Value = raw
		}
	}

	return rec
}

// AlgorithmToString returns a human-readable DNSSEC algorithm description.
func AlgorithmToString(algo uint8) string {
	if name, ok := dns.AlgorithmToString[algo]; ok {
		return name
	}
	switch algo {
	case 1:
		return "RSAMD5"
	case 2:
		return "DH"
	case 3:
		return "DSA"
	case 5:
		return "RSASHA1"
	case 7:
		return "RSASHA1-NSEC3-SHA1"
	case 8:
		return "RSASHA256"
	case 10:
		return "RSASHA512"
	case 13:
		return "ECDSAP256SHA256"
	case 14:
		return "ECDSAP384SHA384"
	case 15:
		return "ED25519"
	case 16:
		return "ED448"
	default:
		return fmt.Sprintf("ALGO%d", algo)
	}
}

// DigestTypeToString returns a human-readable DNSSEC DS digest algorithm description.
func DigestTypeToString(dtype uint8) string {
	switch dtype {
	case 1:
		return "SHA-1"
	case 2:
		return "SHA-256"
	case 3:
		return "GOST-R-34.11-94"
	case 4:
		return "SHA-384"
	default:
		return fmt.Sprintf("DIGEST%d", dtype)
	}
}
