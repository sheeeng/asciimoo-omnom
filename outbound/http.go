// Package outbound enforces the network policy for URLs supplied by users and
// remote content. Configuration is installed once, before starting workers.
package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"
)

// ErrDestinationDenied identifies requests rejected by the outbound policy.
var ErrDestinationDenied = errors.New("outbound destination denied")

const defaultTimeout = 30 * time.Second

// Special-purpose networks are not public feed destinations. IPv6 transition
// mechanisms are excluded because they can embed a prohibited IPv4 destination.
// See the IANA IPv4 and IPv6 Special-Purpose Address Registries.
var deniedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	// Azure's virtual platform address can expose host-local services.
	netip.MustParsePrefix("168.63.129.16/32"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

var publicIPv6 = netip.MustParsePrefix("2000::/3")

type transport struct {
	http    *http.Transport
	allowed map[netip.AddrPort]struct{}
	lookup  func(context.Context, string, string) ([]netip.Addr, error)
	dial    func(context.Context, string, string) (net.Conn, error)
}

var current atomic.Pointer[transport]

func init() {
	t, _ := newTransport(nil)
	current.Store(t)
}

// Configure installs exact IP:port exceptions for intentional internal services.
// Call it before serving requests or starting background feed updates. A failed
// configuration leaves the previous policy in place.
func Configure(allowedPrivateDestinations []string) error {
	t, err := newTransport(allowedPrivateDestinations)
	if err != nil {
		return err
	}
	current.Swap(t).http.CloseIdleConnections()
	return nil
}

// Client returns an HTTP client using the configured destination policy. Clients
// share connection pools, use direct connections (no environment proxies), and
// retain normal TLS certificate and hostname verification. A nonpositive timeout
// selects the default rather than allowing unbounded requests.
func Client(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &http.Client{Transport: current.Load(), Timeout: timeout}
}

func newTransport(exceptions []string) (*transport, error) {
	allowed, err := parseExceptions(exceptions)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	t := &transport{allowed: allowed, lookup: net.DefaultResolver.LookupNetIP, dial: d.DialContext}
	t.http = &http.Transport{
		// A proxy could resolve the original hostname to an unchecked address.
		Proxy:                 nil,
		DialContext:           t.dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return t, nil
}

// ValidateExceptions checks configuration without installing a policy.
func ValidateExceptions(exceptions []string) error {
	_, err := parseExceptions(exceptions)
	return err
}

func parseExceptions(exceptions []string) (map[netip.AddrPort]struct{}, error) {
	allowed := make(map[netip.AddrPort]struct{}, len(exceptions))
	for _, value := range exceptions {
		addr, err := netip.ParseAddrPort(value)
		if err != nil || addr.Port() == 0 || addr.Addr().Zone() != "" {
			return nil, fmt.Errorf("invalid outbound.allowed_private_destinations entry %q: expected an IP address and nonzero port", value)
		}
		ip := addr.Addr().Unmap()
		if !ip.IsPrivate() && !ip.IsLoopback() {
			return nil, fmt.Errorf("invalid outbound exception %q: only private or loopback addresses can be allowed", value)
		}
		if ip == netip.MustParseAddr("fd00:ec2::254") || ip == netip.MustParseAddr("fd20:ce::254") {
			return nil, fmt.Errorf("invalid outbound exception %q: metadata destinations cannot be allowed", value)
		}
		allowed[netip.AddrPortFrom(ip, addr.Port())] = struct{}{}
	}
	return allowed, nil
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return nil, fmt.Errorf("%w: only HTTP and HTTPS are supported", ErrDestinationDenied)
	}
	return t.http.RoundTrip(req)
}

func (t *transport) CloseIdleConnections() {
	t.http.CloseIdleConnections()
}

func (t *transport) permits(ip netip.Addr, port uint16) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if _, ok := t.allowed[netip.AddrPortFrom(ip, port)]; ok {
		return true
	}
	if !ip.IsGlobalUnicast() || (ip.Is6() && !publicIPv6.Contains(ip)) {
		return false
	}
	for _, prefix := range deniedNetworks {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func (t *transport) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("%w: invalid port", ErrDestinationDenied)
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		ips, err = t.lookup(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: hostname has no addresses", ErrDestinationDenied)
	}
	// Reject mixed public/private answers, then dial only those exact addresses.
	// Passing the hostname to DialContext would introduce a second DNS lookup.
	for _, ip := range ips {
		if !t.permits(ip, uint16(port)) {
			return nil, fmt.Errorf("%w: %s", ErrDestinationDenied, net.JoinHostPort(ip.String(), portString))
		}
	}
	var dialErr error
	for _, ip := range ips {
		conn, err := t.dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), portString))
		if err == nil {
			return conn, nil
		}
		dialErr = err
	}
	return nil, dialErr
}
