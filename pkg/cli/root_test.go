package cli_test

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/cli"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/output"
	"github.com/m5rcel-vibecodes/dnsfuck/testutil"
)

func TestCLI_DiagnosticJSON(t *testing.T) {
	mock, err := testutil.NewMockServer()
	if err != nil {
		t.Fatalf("mock server: %v", err)
	}
	defer mock.Close()

	mock.SetRecord("test.org.", dns.TypeA, &dns.A{
		Hdr: dns.RR_Header{Name: "test.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
		A:   net.ParseIP("192.0.2.100"),
	})

	cmd := cli.NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"test.org",
		"--resolver", mock.Addr(),
		"--type", "A",
		"--json",
		"--no-color",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("CLI execution failed: %v", err)
	}

	var rep output.Report
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("Failed to parse JSON output: %v, raw: %s", err, buf.String())
	}

	if rep.Mode != "diagnostic" {
		t.Fatalf("Expected mode 'diagnostic', got %q", rep.Mode)
	}
	if rep.Target != "test.org" {
		t.Fatalf("Expected target 'test.org', got %q", rep.Target)
	}
	if rep.Diagnostic == nil || len(rep.Diagnostic.Records["A"]) != 1 {
		t.Fatalf("Expected 1 A record in report, got %+v", rep.Diagnostic)
	}
	if rep.Diagnostic.Records["A"][0].Value != "192.0.2.100" {
		t.Fatalf("Expected 192.0.2.100, got %s", rep.Diagnostic.Records["A"][0].Value)
	}
}

func TestCLI_ShortOutput(t *testing.T) {
	mock, err := testutil.NewMockServer()
	if err != nil {
		t.Fatalf("mock server: %v", err)
	}
	defer mock.Close()

	mock.SetRecord("example.net.", dns.TypeA, &dns.A{
		Hdr: dns.RR_Header{Name: "example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("198.51.100.1"),
	})

	cmd := cli.NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"example.net",
		"--resolver", mock.Addr(),
		"--type", "A",
		"--short",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("CLI execution failed: %v", err)
	}

	outputStr := strings.TrimSpace(buf.String())
	if outputStr != "198.51.100.1" {
		t.Fatalf("Expected short output '198.51.100.1', got %q", outputStr)
	}
}

func TestCLI_CompareJSON(t *testing.T) {
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

	mock1.SetRecord("compare.org.", dns.TypeA, &dns.A{
		Hdr: dns.RR_Header{Name: "compare.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("10.0.0.1"),
	})
	mock2.SetRecord("compare.org.", dns.TypeA, &dns.A{
		Hdr: dns.RR_Header{Name: "compare.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("10.0.0.2"),
	})

	cmd := cli.NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"compare.org",
		"--resolver", mock1.Addr(),
		"--resolver", mock2.Addr(),
		"--compare",
		"--json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("CLI execution failed: %v", err)
	}

	var rep output.Report
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("Failed to parse JSON output: %v, raw: %s", err, buf.String())
	}

	if rep.Mode != "compare" {
		t.Fatalf("Expected mode 'compare', got %s", rep.Mode)
	}
	if rep.Comparison == nil || !rep.Comparison.Discrepancy {
		t.Fatalf("Expected discrepancy=true in comparison JSON")
	}
}
