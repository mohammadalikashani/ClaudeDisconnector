package core

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type VerdictKind string

const (
	VerdictAllowed VerdictKind = "allowed"
	VerdictIran    VerdictKind = "iran"
	VerdictUnknown VerdictKind = "unknown"
)

type Verdict struct {
	Kind    VerdictKind
	IPv4    string
	IPv6    string
	Country string
	Detail  string
}

var (
	v4Endpoints = []string{"https://api4.ipify.org", "https://ipv4.icanhazip.com"}
	v6Endpoints = []string{"https://api6.ipify.org", "https://ipv6.icanhazip.com"}
)

// Checker finds the public IPv4/IPv6 addresses (and their countries) that a
// given route exits from: the direct route, or through a proxy. Fail-closed:
//   - no public IP found                 -> unknown (block)
//   - ANY address geolocates to IR       -> iran    (block)
//   - any address with unknown country   -> unknown (block)
//   - otherwise                          -> allowed
//
// Three geo services are queried in parallel; if any says IR, it's IR.
type Checker struct {
	mu      sync.Mutex
	cache   map[string]string // ip -> country
	clients map[string]*http.Client
}

func NewChecker() *Checker {
	return &Checker{cache: map[string]string{}, clients: map[string]*http.Client{}}
}

func (c *Checker) ClearCache() {
	c.mu.Lock()
	c.cache = map[string]string{}
	c.mu.Unlock()
}

// client returns an HTTP client for the route: proxyURL "" = direct (never the
// system proxy), otherwise http://host:port or socks5://host:port.
func (c *Checker) client(proxyURL string) *http.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl, ok := c.clients[proxyURL]; ok {
		return cl
	}
	tr := &http.Transport{
		Proxy:               nil,  // direct: deliberately ignore system / env proxies
		DisableKeepAlives:   true, // fresh connection every time (routes change with VPNs)
		TLSHandshakeTimeout: 5 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}
	if proxyURL != "" {
		if u, err := url.Parse(NormalizeProxyURL(proxyURL)); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	cl := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	c.clients[proxyURL] = cl
	return cl
}

// boundClient pins connections (and DNS lookups, so TUN "fake-ip" DNS can't interfere)
// to the local address local, i.e. to the interface that owns it. Windows uses the
// strong host model, so this also forces the outgoing interface.
func (c *Checker) boundClient(local net.IP) *http.Client {
	key := "bind:" + local.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl, ok := c.clients[key]; ok {
		return cl
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.UDPAddr{IP: local}}
			conn, err := d.DialContext(ctx, "udp", "1.1.1.1:53")
			if err != nil {
				conn, err = d.DialContext(ctx, "udp", "8.8.8.8:53")
			}
			return conn, err
		},
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: local}, Resolver: resolver}
	tr := &http.Transport{
		Proxy:               nil,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 5 * time.Second,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
	}
	cl := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	c.clients[key] = cl
	return cl
}

// Check checks the direct route.
func (c *Checker) Check(ctx context.Context) Verdict { return c.CheckVia(ctx, "") }

// CheckBound checks the direct route out of the interface that owns local (IPv4 only).
func (c *Checker) CheckBound(ctx context.Context, local net.IP) Verdict {
	return c.checkWith(ctx, c.boundClient(local), "")
}

// CheckVia checks the route through proxyURL ("" = direct).
func (c *Checker) CheckVia(ctx context.Context, proxyURL string) Verdict {
	return c.checkWith(ctx, c.client(proxyURL), proxyURL)
}

func (c *Checker) checkWith(ctx context.Context, cl *http.Client, proxyURL string) Verdict {
	var ip4, ip6 string
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); ip4 = firstIP(ctx, cl, v4Endpoints, false) }()
	go func() { defer wg.Done(); ip6 = firstIP(ctx, cl, v6Endpoints, true) }()
	wg.Wait()

	if ip4 == "" && ip6 == "" {
		if proxyURL != "" {
			return Verdict{Kind: VerdictUnknown,
				Detail: "Couldn't reach the internet through the proxy " + proxyURL + " (is v2ray connected?)."}
		}
		return Verdict{Kind: VerdictUnknown,
			Detail: "Couldn't determine your public IP (offline, or IP-check services unreachable)."}
	}

	var c4, c6 string
	wg.Add(2)
	go func() {
		defer wg.Done()
		if ip4 != "" {
			c4 = c.country(ctx, cl, ip4)
		}
	}()
	go func() {
		defer wg.Done()
		if ip6 != "" {
			c6 = c.country(ctx, cl, ip6)
		}
	}()
	wg.Wait()
	return decide(ip4, c4, ip6, c6)
}

func decide(ip4, c4, ip6, c6 string) Verdict {
	v := Verdict{IPv4: ip4, IPv6: ip6}
	switch {
	case c4 == "IR" || c6 == "IR":
		ip := ip4
		if c4 != "IR" {
			ip = ip6
		}
		v.Kind, v.Country = VerdictIran, "IR"
		v.Detail = "Your public IP " + ip + " is located in Iran."
	case ip4 != "" && c4 == "":
		v.Kind, v.Country = VerdictUnknown, c6
		v.Detail = "Couldn't determine which country your IP " + ip4 + " is in."
	case ip6 != "" && c6 == "":
		v.Kind, v.Country = VerdictUnknown, c4
		v.Detail = "Couldn't determine which country your IPv6 " + ip6 + " is in."
	default:
		v.Kind = VerdictAllowed
		v.Country = c4
		if v.Country == "" {
			v.Country = c6
		}
		v.Detail = "Your public IP is in " + CountryName(v.Country) + "."
	}
	return v
}

func firstIP(ctx context.Context, cl *http.Client, urls []string, v6 bool) string {
	for _, u := range urls {
		ip := net.ParseIP(get(ctx, cl, u))
		if ip == nil {
			continue
		}
		if (ip.To4() != nil) != v6 {
			return ip.String()
		}
	}
	return ""
}

// Country returns the ISO code for ip (looked up directly), or "" if no service answered.
func (c *Checker) Country(ctx context.Context, ip string) string {
	return c.country(ctx, c.client(""), ip)
}

func (c *Checker) country(ctx context.Context, cl *http.Client, ip string) string {
	c.mu.Lock()
	cached, ok := c.cache[ip]
	c.mu.Unlock()
	if ok {
		return cached
	}
	esc := url.PathEscape(ip)
	answers := make([]string, 3)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); answers[0] = ParseCode(get(ctx, cl, "https://ipinfo.io/"+esc+"/country")) }()
	go func() { defer wg.Done(); answers[1] = ParseCode(get(ctx, cl, "https://ipapi.co/"+esc+"/country/")) }()
	go func() { defer wg.Done(); answers[2] = ParseCountryIs(get(ctx, cl, "https://api.country.is/"+esc)) }()
	wg.Wait()

	result := ""
	for _, a := range answers {
		if a == "IR" {
			result = "IR"
			break
		}
		if result == "" {
			result = a
		}
	}
	if result != "" {
		c.mu.Lock()
		c.cache[ip] = result
		c.mu.Unlock()
	}
	return result
}

func ParseCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) != 2 || s[0] < 'A' || s[0] > 'Z' || s[1] < 'A' || s[1] > 'Z' {
		return ""
	}
	return s
}

func ParseCountryIs(s string) string {
	var obj struct {
		Country string `json:"country"`
	}
	if json.Unmarshal([]byte(s), &obj) != nil {
		return ""
	}
	return ParseCode(obj.Country)
}

func get(ctx context.Context, cl *http.Client, u string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "ClaudeGuard/1.0")
	resp, err := cl.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(b))
}
