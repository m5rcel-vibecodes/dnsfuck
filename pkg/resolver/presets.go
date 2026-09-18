package resolver

import (
	"fmt"
	"strings"
)

// Standard public resolvers
var (
	Cloudflare = Resolver{Name: "Cloudflare", Host: "1.1.1.1:53", Timeout: DefaultTimeout, EDNS0Size: DefaultEDNS0Size, DNSSECOk: true}
	Google     = Resolver{Name: "Google", Host: "8.8.8.8:53", Timeout: DefaultTimeout, EDNS0Size: DefaultEDNS0Size, DNSSECOk: true}
	Quad9      = Resolver{Name: "Quad9", Host: "9.9.9.9:53", Timeout: DefaultTimeout, EDNS0Size: DefaultEDNS0Size, DNSSECOk: true}
	OpenDNS    = Resolver{Name: "OpenDNS", Host: "208.67.222.222:53", Timeout: DefaultTimeout, EDNS0Size: DefaultEDNS0Size, DNSSECOk: true}
)

// DefaultComparisonResolvers returns the 4 primary resolvers used in comparison mode:
// System resolver, Cloudflare, Google, Quad9.
func DefaultComparisonResolvers() []Resolver {
	return []Resolver{
		GetPrimarySystemResolver(),
		Cloudflare,
		Google,
		Quad9,
	}
}

// ParseResolver parses a user-supplied resolver string, which can be an alias (e.g. "cloudflare", "google", "system")
// or an IP address / IP:port / hostname:port.
func ParseResolver(input string) (Resolver, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return Resolver{}, fmt.Errorf("empty resolver specified")
	}

	lower := strings.ToLower(s)
	switch lower {
	case "system":
		return GetPrimarySystemResolver(), nil
	case "cloudflare":
		return Cloudflare, nil
	case "google":
		return Google, nil
	case "quad9":
		return Quad9, nil
	case "opendns":
		return OpenDNS, nil
	}

	// Custom resolver IP / host / port
	hostPort := NormalizeHostPort(s)
	name := s
	return Resolver{
		Name:      name,
		Host:      hostPort,
		Timeout:   DefaultTimeout,
		EDNS0Size: DefaultEDNS0Size,
		DNSSECOk:  true,
	}, nil
}
