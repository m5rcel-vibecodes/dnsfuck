package propagation

import (
	"time"

	"github.com/m5rcel-vibecodes/dnsfuck/pkg/resolver"
)

// PublicResolver describes a known public resolver for global propagation testing.
type PublicResolver struct {
	Name     string
	Provider string
	Host     string
	Location string
}

// GlobalResolvers returns a diverse list of public DNS resolvers worldwide.
var GlobalResolvers = []PublicResolver{
	{Name: "Cloudflare", Provider: "Cloudflare", Host: "1.1.1.1:53", Location: "Global / Anycast"},
	{Name: "Google", Provider: "Google Public DNS", Host: "8.8.8.8:53", Location: "Global / Anycast"},
	{Name: "Quad9", Provider: "Quad9", Host: "9.9.9.9:53", Location: "Global / Anycast"},
	{Name: "OpenDNS", Provider: "Cisco OpenDNS", Host: "208.67.222.222:53", Location: "Global / Anycast"},
	{Name: "Level3", Provider: "Lumen / Level3", Host: "4.2.2.1:53", Location: "North America"},
	{Name: "AdGuard", Provider: "AdGuard DNS", Host: "94.140.14.14:53", Location: "Europe / Anycast"},
	{Name: "AliDNS", Provider: "Alibaba Cloud", Host: "223.5.5.5:53", Location: "Asia Pacific"},
	{Name: "DNS.WATCH", Provider: "DNS.WATCH", Host: "84.200.69.80:53", Location: "Germany"},
	{Name: "Control D", Provider: "Control D", Host: "76.76.2.0:53", Location: "North America / Anycast"},
	{Name: "Hurricane Electric", Provider: "Hurricane Electric", Host: "74.82.42.42:53", Location: "North America"},
}

// ToResolver converts a PublicResolver into a resolver.Resolver instance.
func (p PublicResolver) ToResolver(timeout time.Duration) resolver.Resolver {
	if timeout <= 0 {
		timeout = resolver.DefaultTimeout
	}
	return resolver.Resolver{
		Name:      p.Name,
		Host:      p.Host,
		Timeout:   timeout,
		EDNS0Size: resolver.DefaultEDNS0Size,
		DNSSECOk:  true,
	}
}
