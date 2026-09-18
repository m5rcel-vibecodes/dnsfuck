package resolver_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/resolver"
	"github.com/m5rcel-vibecodes/dnsfuck/testutil"
)

func TestResolver_QuerySuccess(t *testing.T) {
	mock, err := testutil.NewMockServer()
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer mock.Close()

	mock.SetRecord("example.com.", dns.TypeA, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("93.184.216.34"),
	})
	mock.SetAuthenticatedData(true)

	res := resolver.New("test-resolver", mock.Addr())
	ctx := context.Background()

	qRes := res.Query(ctx, "example.com", dns.TypeA)
	if qRes.Rcode != dns.RcodeSuccess {
		t.Fatalf("Expected NOERROR, got %s (%d)", qRes.RcodeName, qRes.Rcode)
	}
	if len(qRes.Records) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(qRes.Records))
	}
	if qRes.Records[0].Value != "93.184.216.34" {
		t.Fatalf("Expected 93.184.216.34, got %s", qRes.Records[0].Value)
	}
	if !qRes.AuthenticatedData {
		t.Fatalf("Expected AuthenticatedData = true")
	}
	if qRes.Latency <= 0 {
		t.Fatalf("Expected positive latency, got %v", qRes.Latency)
	}
}

func TestResolver_PreserveRcodes(t *testing.T) {
	mock, err := testutil.NewMockServer()
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer mock.Close()

	res := resolver.New("test-resolver", mock.Addr())
	ctx := context.Background()

	// Test NXDOMAIN
	mock.SetRcode("nxdomain.test.", dns.RcodeNameError)
	nxRes := res.Query(ctx, "nxdomain.test", dns.TypeA)
	if nxRes.Rcode != dns.RcodeNameError || nxRes.RcodeName != "NXDOMAIN" {
		t.Fatalf("Expected NXDOMAIN, got %s (%d)", nxRes.RcodeName, nxRes.Rcode)
	}

	// Test SERVFAIL
	mock.SetRcode("servfail.test.", dns.RcodeServerFailure)
	sfRes := res.Query(ctx, "servfail.test", dns.TypeA)
	if sfRes.Rcode != dns.RcodeServerFailure || sfRes.RcodeName != "SERVFAIL" {
		t.Fatalf("Expected SERVFAIL, got %s (%d)", sfRes.RcodeName, sfRes.Rcode)
	}

	// Test REFUSED
	mock.SetRcode("refused.test.", dns.RcodeRefused)
	rfRes := res.Query(ctx, "refused.test", dns.TypeA)
	if rfRes.Rcode != dns.RcodeRefused || rfRes.RcodeName != "REFUSED" {
		t.Fatalf("Expected REFUSED, got %s (%d)", rfRes.RcodeName, rfRes.Rcode)
	}
}

func TestResolver_Timeout(t *testing.T) {
	// Point to a non-responsive IP in private space with immediate timeout
	res := resolver.New("timeout-resolver", "192.0.2.1:53")
	res.Timeout = 100 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	qRes := res.Query(ctx, "example.com", dns.TypeA)
	if qRes.Error == "" {
		t.Fatalf("Expected error for timeout query, got none")
	}
}

func TestNormalizeHostPort(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1.1.1.1", "1.1.1.1:53"},
		{"8.8.8.8:5353", "8.8.8.8:5353"},
		{"[2606:4700:4700::1111]", "[2606:4700:4700::1111]:53"},
		{"[::1]:5353", "[::1]:5353"},
		{"2606:4700:4700::1111", "[2606:4700:4700::1111]:53"},
	}
	for _, tt := range tests {
		got := resolver.NormalizeHostPort(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeHostPort(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseResolver(t *testing.T) {
	cf, err := resolver.ParseResolver("cloudflare")
	if err != nil || cf.Host != "1.1.1.1:53" {
		t.Fatalf("ParseResolver(cloudflare) failed: %v, host: %s", err, cf.Host)
	}

	custom, err := resolver.ParseResolver("10.0.0.1:5353")
	if err != nil || custom.Host != "10.0.0.1:5353" {
		t.Fatalf("ParseResolver(custom) failed: %v, host: %s", err, custom.Host)
	}
}
