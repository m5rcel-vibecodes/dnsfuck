package testutil

import (
	"fmt"
	"net"
	"sync"

	"github.com/miekg/dns"
)

// MockServer provides a local, in-memory DNS server for hermetic testing.
type MockServer struct {
	server   *dns.Server
	addr     string
	records  map[string][]dns.RR // key: "domain:type" e.g. "example.com.:A"
	rcodes   map[string]int      // key: domain
	adFlag   bool                // Authenticated Data flag
	tcFlag   bool                // Truncation flag
	mu       sync.RWMutex
	notifyCh chan struct{}
}

// NewMockServer starts a new in-memory DNS server on an available localhost port.
func NewMockServer() (*MockServer, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	ms := &MockServer{
		addr:     pc.LocalAddr().String(),
		records:  make(map[string][]dns.RR),
		rcodes:   make(map[string]int),
		notifyCh: make(chan struct{}),
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", ms.handleDNS)

	ms.server = &dns.Server{
		PacketConn: pc,
		Handler:    mux,
		NotifyStartedFunc: func() {
			close(ms.notifyCh)
		},
	}

	go func() {
		_ = ms.server.ActivateAndServe()
	}()

	<-ms.notifyCh
	return ms, nil
}

// Addr returns the server's host:port address.
func (ms *MockServer) Addr() string {
	return ms.addr
}

// Close stops the mock DNS server.
func (ms *MockServer) Close() {
	if ms.server != nil {
		_ = ms.server.Shutdown()
	}
}

// SetRecord registers a slice of dns.RR records for a given domain and qtype.
func (ms *MockServer) SetRecord(name string, qtype uint16, rrs ...dns.RR) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	key := fmt.Sprintf("%s:%d", dns.Fqdn(name), qtype)
	ms.records[key] = rrs
}

// SetRcode configures a specific response code for a domain (e.g. dns.RcodeNameError for NXDOMAIN).
func (ms *MockServer) SetRcode(name string, rcode int) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.rcodes[dns.Fqdn(name)] = rcode
}

// SetAuthenticatedData toggles the AD bit in responses.
func (ms *MockServer) SetAuthenticatedData(ad bool) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.adFlag = ad
}

// SetTruncated toggles the TC bit in responses.
func (ms *MockServer) SetTruncated(tc bool) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.tcFlag = tc
}

func (ms *MockServer) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	ms.mu.RLock()
	m.AuthenticatedData = ms.adFlag
	m.Truncated = ms.tcFlag

	if len(r.Question) > 0 {
		q := r.Question[0]
		name := q.Name

		if rcode, ok := ms.rcodes[name]; ok {
			m.Rcode = rcode
		} else {
			key := fmt.Sprintf("%s:%d", name, q.Qtype)
			if rrs, ok := ms.records[key]; ok {
				m.Answer = append(m.Answer, rrs...)
			}
		}
	}
	ms.mu.RUnlock()

	_ = w.WriteMsg(m)
}
