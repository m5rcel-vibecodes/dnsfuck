<div align="center">

```
     _             __            _    
  __| |_ __  ___  / _|_   _  ___| | __
 / _` | '_ \/ __|| |_| | | |/ __| |/ /
| (_| | | | \__ \|  _| |_| | (__|   < 
 \__,_|_| |_|___/|_|  \__,_|\___|_|\_\
```

# dnsfuck

**A production-ready, no-bullshit DNS diagnostic and troubleshooting CLI utility.**

[![CI](https://github.com/m5rcel-vibecodes/dnsfuck/actions/workflows/ci.yml/badge.svg)](https://github.com/m5rcel-vibecodes/dnsfuck/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/m5rcel-vibecodes/dnsfuck)](https://goreportcard.com/report/github.com/m5rcel-vibecodes/dnsfuck)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/m5rcel-vibecodes/dnsfuck)](https://github.com/m5rcel-vibecodes/dnsfuck/releases)

*Because nobody should have to run `dig` and `nslookup` nine hundred fucking times just to debug a broken record.*

</div>

---

## ⚡ Overview

**dnsfuck** is a high-performance DNS diagnostic utility written in pure Go. Despite the deliberately irreverent name, it is a serious, reliable, and production-grade engineering tool designed for site reliability engineers, system administrators, security teams, and developers.

It unifies what usually requires dozens of fragmented shell commands into an elegant, high-visibility terminal interface:
- **Instant Full Diagnostic**: Single-command assessment of all critical record types (A, AAAA, CNAME, MX, NS, TXT, SOA) with DNSSEC summary.
- **Multi-Resolver Comparison**: Compare resolutions across local system DNS, Cloudflare, Google, Quad9, and custom resolvers in a clear table, detecting discrepancies without bias.
- **Worldwide Propagation**: Query diverse public resolvers globally to verify propagation and immediately detect resolver disagreements with TTL inspection.
- **Deep DNSSEC Inspection**: Full chain verification (DS records, DNSKEY KSK/ZSK keys, RRSIG validity, AD flag verification) clearly distinguishing valid, unsigned, bogus, and locally unvalidated states.
- **Iterative Root-to-Leaf Trace**: Walk step-by-step from IANA root servers through TLDs to authoritative nameservers down to the final answer.
- **Real-Time Watch Mode**: Continuously monitor DNS records during cutovers and migrations with live updates.
- **Structured JSON Output**: Full machine-readable output for CI pipelines, scripts, and observability systems.
- **Honest Error Handling**: Clear RCODE reporting (NXDOMAIN, SERVFAIL, REFUSED, timeouts) with zero hidden failures.

---

## 📦 Installation

### Via `go install` (Recommended)
Requires Go 1.23 or newer:
```bash
go install github.com/m5rcel-vibecodes/dnsfuck/cmd/dnsfuck@latest
```

### Prebuilt Binaries
Download pre-compiled binaries for your architecture from the [GitHub Releases](https://github.com/m5rcel-vibecodes/dnsfuck/releases) page:

| OS | Architecture | Binary |
| :--- | :--- | :--- |
| **macOS** | Apple Silicon (`arm64`) | `dnsfuck-darwin-arm64` |
| **macOS** | Intel (`amd64`) | `dnsfuck-darwin-amd64` |
| **Linux** | 64-bit (`amd64`) | `dnsfuck-linux-amd64` |
| **Linux** | ARM64 (`arm64`) | `dnsfuck-linux-arm64` |
| **Windows** | 64-bit (`amd64`) | `dnsfuck-windows-amd64.exe` |
| **Windows** | ARM64 (`arm64`) | `dnsfuck-windows-arm64.exe` |

### Quick One-Liner (macOS / Linux)
```bash
curl -sSL https://raw.githubusercontent.com/m5rcel-vibecodes/dnsfuck/main/install.sh | bash
```

### Build From Source
```bash
git clone https://github.com/m5rcel-vibecodes/dnsfuck.git
cd dnsfuck
make build
# Binary available at bin/dnsfuck
```

---

## 🚀 Usage & Examples

### 1. Basic Diagnostic
Run a standard diagnostic on any domain:
```bash
dnsfuck example.com
```

```text
DNS DIAGNOSTIC — example.com

A
  93.184.216.34

AAAA
  2606:2800:220:1:248:1893:25c8:1946

MX
  10 mail.example.com

NS
  ns1.example.com
  ns2.example.com

TXT
  "v=spf1 -all"

SOA
  ns1.example.com hostmaster.example.com (serial: 2024010101, refresh: 7200s, retry: 3600s, expire: 1209600s, min: 3600s)

DNSSEC
  ✔ Supported (Chain of Trust intact)

Resolver: 192.168.1.1:53  Total diagnostic time: 42ms
```

---

### 2. Specific Record Types
Filter queries for specific record types:
```bash
# Query mail exchangers
dnsfuck google.com --type MX

# Query text and verification records
dnsfuck google.com --type TXT

# Query multiple record types
dnsfuck example.com --type A,AAAA,NS
```

**Supported Record Types:**
`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`, `SRV`, `CAA`, `PTR`, `DNSKEY`, `DS`

---

### 3. Resolver Comparison (`--compare`)
Compare resolution results across multiple recursive resolvers:
```bash
dnsfuck example.com --compare
```

```text
RESOLVER COMPARISON — example.com (A record)

Resolver     A Result          Time
system       93.184.216.34     12ms
Cloudflare   93.184.216.34     8ms
Google       93.184.216.34     10ms
Quad9        93.184.216.34     15ms

Comparison completed in: 18ms
```

When resolvers return differing records (e.g. Anycast routing, CDN geo-steering, or active propagation), `dnsfuck` clearly highlights discrepancies without bias:

```text
⚠ Resolver disagreement detected (answers differ across resolvers)
Note: Different results do not imply any single resolver is inherently correct (e.g. Anycast routing, CDN geolocation, or active propagation).
```

---

### 4. Global Propagation Check (`--propagation`)
Query an array of geographically diverse public resolvers worldwide to check record propagation:
```bash
dnsfuck example.com --propagation
```

```text
DNS PROPAGATION CHECK — example.com (A RECORD)

Resolver             Location                  A Result          TTL      Latency
Cloudflare           Global / Anycast          93.184.216.34     3600s    8ms
Google               Global / Anycast          93.184.216.34     3600s    12ms
Quad9                Global / Anycast          93.184.216.34     3592s    15ms
OpenDNS              Global / Anycast          93.184.216.34     3600s    10ms
Level3               North America             93.184.216.34     3580s    22ms
AdGuard              Europe / Anycast          93.184.216.34     3600s    24ms
AliDNS               Asia Pacific              93.184.216.34     3600s    142ms
Control D            North America / Anycast   93.184.216.34     3600s    9ms
Hurricane Electric   North America             93.184.216.34     3600s    14ms

✔ Full resolver consensus (all responsive resolvers agree)

Resolvers: 9/9 responsive  Check duration: 156ms
```

---

### 5. DNSSEC Chain Diagnostics (`--dnssec`)
Perform deep DNSSEC chain inspection:
```bash
dnsfuck cloudflare.com --dnssec
```

```text
DNSSEC DIAGNOSTIC — cloudflare.com

Overall Status: [SECURE] Supported & Validated (Chain of Trust intact)
Validation: Validated by resolver 1.1.1.1:53 (Authenticated Data flag set)

Component                               Status                    Details
Parent DS Delegation                    ✔ Present                 1 record(s) found at parent zone
Apex DNSKEY Keys                        ✔ Present                 2 key(s) published at apex
Cryptographic Signatures (RRSIG)        ✔ Present                 1 active signature(s) inspected
Resolver AD Flag (Authenticated Data)   ✔ Set (Local resolver)   Resolver cryptographic chain verification

DELEGATION SIGNER (DS) RECORDS
Key Tag   Algorithm         Digest Type   Digest                        Matches Apex DNSKEY
2371      ECDSAP256SHA256   SHA-256       32996839a6d808afe3eb4a79...   ✔ Match confirmed

DNSKEY RECORDS (ZONE KEYS)
Key Tag   Role        Algorithm         Flags   Public Key Preview
2371      KSK / SEP   ECDSAP256SHA256   257     mdsswUyr3DPW132mOi8V...
34505     ZSK         ECDSAP256SHA256   256     oJMRESz5E4gYzS/q6XDr...

RESOURCE RECORD SIGNATURES (RRSIG)
Type Covered   Algorithm         Key Tag   Expiration                  Status
DNSKEY         ECDSAP256SHA256   2371      2026-10-26T05:55:37+01:00   Valid

Inspected via: 1.1.1.1:53  Diagnostic time: 82ms
```

**Honest Validation:** `dnsfuck` distinguishes:
- `SECURE`: Cryptographic chain of trust verified and validated.
- `UNSIGNED`: Domain does not implement DNSSEC (normal, unadulterated state).
- `BOGUS`: DS / DNSKEY mismatch, expired signatures, or broken chain.
- `INDETERMINATE`: Validation unavailable on the local resolver, with public validating fallback check.

---

### 6. Iterative Root-to-Leaf Trace (`--trace`)
Trace iterative resolution directly from the 13 IANA root nameservers (`[a-m].root-servers.net`) down through TLDs to authoritative nameservers:
```bash
dnsfuck cloudflare.com --trace
```

```text
ITERATIVE RESOLUTION TRACE — cloudflare.com (A record)

. (Root: a.root-servers.net [198.41.0.4]) 24ms
  Delegation to: l.gtld-servers.net, j.gtld-servers.net, h.gtld-servers.net, ...
↓
com (TLD: l.gtld-servers.net [192.41.162.30]) 31ms
  Delegation to: ns3.cloudflare.com, ns5.cloudflare.com, ns4.cloudflare.com, ...
↓
cloudflare.com (Authoritative: ns3.cloudflare.com [162.159.0.33]) 18ms
↓
final answer:
  A: 104.16.133.229 (TTL: 300)
  A: 104.16.132.229 (TTL: 300)

Trace resolved in: 73ms (3 hops)
```

---

### 7. Custom Resolvers & Ports
Specify custom resolvers by IP, hostname, or port:
```bash
# Custom public IP
dnsfuck example.com --resolver 1.1.1.1

# Custom internal resolver on specific port
dnsfuck example.com --resolver 10.0.0.1:5353

# Multiple custom resolvers for comparison
dnsfuck example.com --resolver 1.1.1.1 --resolver 8.8.8.8 --compare

# IPv6 resolver
dnsfuck example.com --resolver "[2606:4700:4700::1111]:53"
```

---

### 8. Watch Mode (`--watch`)
Live monitor records during DNS migrations, TTL expirations, or cutovers:
```bash
# Re-run diagnostic every 5 seconds
dnsfuck example.com --watch 5

# Monitor propagation changes every 10 seconds
dnsfuck example.com --propagation --watch 10
```

---

### 9. JSON Output & Scripting (`--json` & `--short`)
Format results for automation and shell piping:

```bash
# Full JSON report
dnsfuck example.com --json | jq .

# Inspect specific record values in JSON
dnsfuck example.com --type MX --json | jq '.diagnostic.records.MX[].value'

# Raw record values only (ideal for bash scripts)
dnsfuck example.com --type A --short
# Output:
# 93.184.216.34
```

---

## 🛠 Command Line Flags Reference

```text
Usage:
  dnsfuck <domain> [flags]

Flags:
  -c, --compare            Compare resolution across multiple resolvers
  -d, --dnssec             Inspect DNSSEC keys, DS records, signatures, and validation status
  -j, --json               Output results as structured JSON
      --no-color           Disable colored output
  -p, --propagation        Check worldwide propagation across public resolvers
  -r, --resolver strings   Custom resolver(s) (e.g. 1.1.1.1, 8.8.8.8:5353, [::1]:53, or alias)
  -s, --short              Output record values only (ideal for scripts)
      --tcp                Force TCP for DNS queries
      --timeout duration   Query timeout duration (default 3s)
      --trace              Trace iterative resolution from root servers down to authoritative
  -t, --type strings       DNS record type(s) to query (A, AAAA, MX, NS, TXT, SOA, SRV, CAA, PTR, DNSKEY, DS)
  -v, --version            Display version and build information
  -w, --watch int          Re-run diagnostic every N seconds
```

---

## 🏛 Architecture

The codebase adheres strictly to clean separation of concerns:

```text
dnsfuck/
├── cmd/
│   └── dnsfuck/                 # Application entry point
├── pkg/
│   ├── cli/                     # Cobra CLI command logic, flags, and watch loop
│   ├── records/                 # Record types, data structures, and parser
│   ├── resolver/                # Resolver client, EDNS0, TCP retries, and system detection
│   ├── dnssec/                  # DNSSEC chain validator, key inspection, and digest matching
│   ├── trace/                   # Iterative root-to-leaf trace engine and IANA root hints
│   ├── propagation/             # Multi-resolver propagation checker and consensus engine
│   ├── formatting/              # Terminal UX, tables, status indicators, and NO_COLOR
│   └── output/                  # Structured JSON models and serialization
├── testutil/                    # Hermetic in-memory mock DNS server for unit tests
├── .github/workflows/           # GitHub Actions CI and release automation
├── .goreleaser.yaml             # Multi-architecture release configuration
└── Makefile                     # Build, test, cross-compile, and linting recipes
```

---

## 🧪 Testing

All unit tests run hermetically using an in-memory mock DNS server without requiring external network access or running daemons:

```bash
# Run unit tests
make test

# Run tests with race condition detector
make test-race

# Run static checks and formatting
make lint
```

---

## 📄 License

MIT License © 2026 Marcel ([@m5rcel-vibecodes](https://github.com/m5rcel-vibecodes))
