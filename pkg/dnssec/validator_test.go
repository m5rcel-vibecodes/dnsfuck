package dnssec_test

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/dnssec"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/resolver"
	"github.com/m5rcel-vibecodes/dnsfuck/testutil"
)

func TestDNSSEC_Unsigned(t *testing.T) {
	mock, err := testutil.NewMockServer()
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer mock.Close()

	res := resolver.New("test-resolver", mock.Addr())
	ctx := context.Background()

	diag := dnssec.Diagnose(ctx, "plain-domain.com", res)
	if diag.Status != dnssec.StatusUnsigned {
		t.Fatalf("Expected status UNSIGNED, got %s", diag.Status)
	}
	if diag.HasDNSKEY || diag.HasDS {
		t.Fatalf("Expected no DNSSEC records, got HasDNSKEY=%v, HasDS=%v", diag.HasDNSKEY, diag.HasDS)
	}
}

func TestDNSSEC_Bogus_MissingKey(t *testing.T) {
	mock, err := testutil.NewMockServer()
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer mock.Close()

	// Provide DS record at parent, but no DNSKEY
	mock.SetRecord("broken.com.", dns.TypeDS, &dns.DS{
		Hdr:        dns.RR_Header{Name: "broken.com.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600},
		KeyTag:     12345,
		Algorithm:  13,
		DigestType: 2,
		Digest:     "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
	})

	res := resolver.New("test-resolver", mock.Addr())
	ctx := context.Background()

	diag := dnssec.Diagnose(ctx, "broken.com", res)
	if diag.Status != dnssec.StatusBogus {
		t.Fatalf("Expected status BOGUS, got %s", diag.Status)
	}
	if !diag.HasDS {
		t.Fatalf("Expected HasDS=true")
	}
}
