package trace_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/m5rcel-vibecodes/dnsfuck/pkg/trace"
	"github.com/m5rcel-vibecodes/dnsfuck/testutil"
	"github.com/miekg/dns"
)

func TestRootHints_Presence(t *testing.T) {
	if len(trace.RootHints) != 13 {
		t.Fatalf("Expected 13 root hints, got %d", len(trace.RootHints))
	}
	for _, hint := range trace.RootHints {
		if hint.Name == "" || hint.IPv4 == "" {
			t.Errorf("Invalid root hint: %+v", hint)
		}
	}
}

func TestTrace_DirectAnswer(t *testing.T) {
	mock, err := testutil.NewMockServer()
	if err != nil {
		t.Fatalf("mock server: %v", err)
	}
	defer mock.Close()

	mock.SetRecord("example.com.", dns.TypeA, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("93.184.216.34"),
	})

	// Temporarily point first root hint to mock server
	origIPv4 := trace.RootHints[0].IPv4
	origName := trace.RootHints[0].Name
	trace.RootHints[0].IPv4 = mock.Addr()
	trace.RootHints[0].Name = "mock-root"
	defer func() {
		trace.RootHints[0].IPv4 = origIPv4
		trace.RootHints[0].Name = origName
	}()

	ctx := context.Background()
	res := trace.Trace(ctx, "example.com", dns.TypeA, 1*time.Second)

	if len(res.FinalAnswers) != 1 {
		t.Fatalf("Expected 1 final answer, got %d", len(res.FinalAnswers))
	}
	if res.FinalAnswers[0].Value != "93.184.216.34" {
		t.Fatalf("Expected 93.184.216.34, got %s", res.FinalAnswers[0].Value)
	}
	if len(res.Hops) != 1 {
		t.Fatalf("Expected 1 hop, got %d", len(res.Hops))
	}
}
