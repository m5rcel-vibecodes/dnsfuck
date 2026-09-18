package resolver

import (
	"bufio"
	"os/exec"
	"runtime"
	"strings"

	"github.com/miekg/dns"
)

// DetectSystemResolvers finds the local system nameservers from scutil (on macOS) or /etc/resolv.conf.
func DetectSystemResolvers() []Resolver {
	var resolvers []Resolver
	seen := make(map[string]bool)

	// On macOS, try parsing scutil --dns to handle split-horizon VPNs / Tailscale correctly
	if runtime.GOOS == "darwin" {
		scutilResolvers := detectDarwinResolvers()
		for _, r := range scutilResolvers {
			if !seen[r.Host] {
				seen[r.Host] = true
				resolvers = append(resolvers, r)
			}
		}
	}

	if runtime.GOOS != "windows" {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err == nil && conf != nil && len(conf.Servers) > 0 {
			port := conf.Port
			if port == "" {
				port = "53"
			}
			for _, s := range conf.Servers {
				hostPort := NormalizeHostPort(s + ":" + port)
				if !seen[hostPort] {
					seen[hostPort] = true
					resolvers = append(resolvers, Resolver{
						Name:      "system",
						Host:      hostPort,
						Timeout:   DefaultTimeout,
						EDNS0Size: DefaultEDNS0Size,
						DNSSECOk:  true,
					})
				}
			}
		}
	}

	// If no resolv.conf found or empty, provide standard loopback
	if len(resolvers) == 0 {
		resolvers = append(resolvers, Resolver{
			Name:      "system",
			Host:      "127.0.0.1:53",
			Timeout:   DefaultTimeout,
			EDNS0Size: DefaultEDNS0Size,
			DNSSECOk:  true,
		})
	}

	return resolvers
}

// detectDarwinResolvers executes scutil --dns and separates primary resolvers from supplemental ones.
func detectDarwinResolvers() []Resolver {
	out, err := exec.Command("scutil", "--dns").Output()
	if err != nil {
		return nil
	}

	var primaryIPs []string
	var supplementalIPs []string

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	var currentNameservers []string
	var isSupplemental bool
	var isScoped bool

	flushSection := func() {
		if len(currentNameservers) > 0 {
			for _, ns := range currentNameservers {
				if isSupplemental || isScoped {
					supplementalIPs = append(supplementalIPs, ns)
				} else {
					primaryIPs = append(primaryIPs, ns)
				}
			}
		}
		currentNameservers = nil
		isSupplemental = false
		isScoped = false
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "resolver #") {
			flushSection()
			continue
		}
		if strings.HasPrefix(line, "nameserver[") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				ip := strings.TrimSpace(strings.Join(parts[1:], ":"))
				if ip != "" {
					currentNameservers = append(currentNameservers, ip)
				}
			}
		} else if strings.HasPrefix(line, "flags") {
			if strings.Contains(line, "Supplemental") {
				isSupplemental = true
			}
			if strings.Contains(line, "Scoped") {
				isScoped = true
			}
		}
	}
	flushSection()

	var result []Resolver
	// Put primary (non-supplemental) internet resolvers first
	for _, ip := range primaryIPs {
		result = append(result, Resolver{
			Name:      "system",
			Host:      NormalizeHostPort(ip),
			Timeout:   DefaultTimeout,
			EDNS0Size: DefaultEDNS0Size,
			DNSSECOk:  true,
		})
	}
	for _, ip := range supplementalIPs {
		result = append(result, Resolver{
			Name:      "system (vpn/supplemental)",
			Host:      NormalizeHostPort(ip),
			Timeout:   DefaultTimeout,
			EDNS0Size: DefaultEDNS0Size,
			DNSSECOk:  true,
		})
	}

	return result
}

// GetPrimarySystemResolver returns the primary detected system resolver.
func GetPrimarySystemResolver() Resolver {
	sys := DetectSystemResolvers()
	if len(sys) > 0 {
		return sys[0]
	}
	return New("system", "127.0.0.1:53")
}
