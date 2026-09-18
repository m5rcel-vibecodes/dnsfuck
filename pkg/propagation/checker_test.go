package propagation_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/propagation"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/resolver"
	"github.com/m5rcel-vibecodes/dnsfuck/testutil"
)

func TestPropagation_Consensus(t *testing.T) {
	mock1, err := testutil.NewMockServer()
	if err != nil {
		t.Fatalf("mock1: %v", err)
	}
	defer mock1.Close()

	mock2, err := testutil.NewMockServer()
	if err != nil {
		t.Fatalf("mock2: %v", err)
	}
	defer mock2.Close()

	ip := net.ParseIP("1.2.3.4")
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   ip,
	}
	mock1.SetRecord("example.com.", dns.TypeA, rr)
	mock2.SetRecord("example.com.", dns.TypeA, rr)

	resList := []resolver.Resolver{
		resolver.New("Mock1", mock1.Addr()),
		resolver.New("Mock2", mock2.Addr()),
	}

	ctx := context.Background()
	res := propagation.Check(ctx, "example.com", dns.TypeA, 1*time.Second, resList)

	if res.DisagreementDetected {
		t.Fatalf("Expected consensus, but disagreement was flagged")
	}
	if res.ResponsiveResolvers != 2 {
		t.Fatalf("Expected 2 responsive resolvers, got %d", res.ResponsiveResolvers)
	}
}

func TestPropagation_Disagreement(t *testing.T) {
	mock1, err := testutil.NewMockServer()
	if err != nil {
		t.Fatalf("mock1: %v", err)
	}
	defer mock1.Close()

	mock2, err := testutil.NewMockServer()
	if err != nil {
		t.Fatalf("mock2: %v", err)
	}
	defer mock2.Close()

	// mock1 returns 1.2.3.4
	mock1.SetRecord("example.com.", dns.TypeA, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("1.2.3.4"),
	})

	// mock2 returns 5.6.7.8
	mock2.SetRecord("example.com.", dns.TypeA, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("5.6.7.8"),
	})

	resList := []resolver.Resolver{
		resolver.New("Mock1", mock1.Addr()),
		resolver.New("Mock2", mock2.Addr()),
	}

	ctx := context.Background()
	res := propagation.Check(ctx, "example.com", dns.TypeA, 1*time.Second, resList)

	if !res.DisagreementDetected {
		t.Fatalf("Expected disagreement to be detected, but was not")
	}
	if res.UniqueAnswerSets != 2 {
		t.Fatalf("Expected 2 unique answer sets, got %d", res.UniqueAnswerSets)
	}
}
