package records_test

import (
	"net"
	"testing"

	"github.com/m5rcel-vibecodes/dnsfuck/pkg/records"
	"github.com/miekg/dns"
)

func TestParseRR_AllTypes(t *testing.T) {
	tests := []struct {
		name     string
		rr       dns.RR
		wantType string
		wantVal  string
	}{
		{
			name: "A record",
			rr: &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("93.184.216.34"),
			},
			wantType: "A",
			wantVal:  "93.184.216.34",
		},
		{
			name: "AAAA record",
			rr: &dns.AAAA{
				Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
			},
			wantType: "AAAA",
			wantVal:  "2606:2800:220:1:248:1893:25c8:1946",
		},
		{
			name: "CNAME record",
			rr: &dns.CNAME{
				Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "example.com.",
			},
			wantType: "CNAME",
			wantVal:  "example.com",
		},
		{
			name: "MX record",
			rr: &dns.MX{
				Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
				Preference: 10,
				Mx:         "mail.example.com.",
			},
			wantType: "MX",
			wantVal:  "10 mail.example.com",
		},
		{
			name: "NS record",
			rr: &dns.NS{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 86400},
				Ns:  "ns1.example.com.",
			},
			wantType: "NS",
			wantVal:  "ns1.example.com",
		},
		{
			name: "TXT record",
			rr: &dns.TXT{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{"v=spf1 -all"},
			},
			wantType: "TXT",
			wantVal:  `"v=spf1 -all"`,
		},
		{
			name: "CAA record",
			rr: &dns.CAA{
				Hdr:   dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 3600},
				Flag:  0,
				Tag:   "issue",
				Value: "letsencrypt.org",
			},
			wantType: "CAA",
			wantVal:  `0 issue "letsencrypt.org"`,
		},
		{
			name: "PTR record",
			rr: &dns.PTR{
				Hdr: dns.RR_Header{Name: "34.216.184.93.in-addr.arpa.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 3600},
				Ptr: "example.com.",
			},
			wantType: "PTR",
			wantVal:  "example.com",
		},
		{
			name: "SRV record",
			rr: &dns.SRV{
				Hdr:      dns.RR_Header{Name: "_sip._tcp.example.com.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 3600},
				Priority: 10,
				Weight:   60,
				Port:     5060,
				Target:   "bigbox.example.com.",
			},
			wantType: "SRV",
			wantVal:  "10 60 5060 bigbox.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := records.ParseRR(tt.rr)
			if got.Type != tt.wantType {
				t.Errorf("ParseRR() Type = %v, want %v", got.Type, tt.wantType)
			}
			if got.Value != tt.wantVal {
				t.Errorf("ParseRR() Value = %v, want %v", got.Value, tt.wantVal)
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com.", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"  Sub.Domain.Org.  ", "sub.domain.org"},
		{".", "."},
	}
	for _, tt := range tests {
		if got := records.NormalizeDomain(tt.input); got != tt.want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestEnsureFQDN(t *testing.T) {
	if got := records.EnsureFQDN("example.com"); got != "example.com." {
		t.Errorf("EnsureFQDN() = %q, want example.com.", got)
	}
	if got := records.EnsureFQDN("example.com."); got != "example.com." {
		t.Errorf("EnsureFQDN() = %q, want example.com.", got)
	}
}

func TestTypeMapping(t *testing.T) {
	qtype, err := records.TypeToUint16("MX")
	if err != nil || qtype != dns.TypeMX {
		t.Fatalf("TypeToUint16(MX) failed: %v", err)
	}

	name := records.Uint16ToType(dns.TypeAAAA)
	if name != "AAAA" {
		t.Fatalf("Uint16ToType(AAAA) = %s, want AAAA", name)
	}

	if !records.IsSupportedType("dnskey") {
		t.Fatalf("IsSupportedType(dnskey) should be true")
	}
}
