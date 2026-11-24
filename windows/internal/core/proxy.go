package core

import (
	"net"
	"net/url"
	"strings"
)

// SystemProxy is the OS "system proxy" (what v2rayN / v2rayU / V2Box set in
// system-proxy mode). Claude Desktop (Chromium) follows it; Claude Code does NOT -
// Claude Code only uses the https_proxy/HTTPS_PROXY/http_proxy/HTTP_PROXY env vars.
type SystemProxy struct {
	HTTP  string `json:"http,omitempty"`  // http://host:port (usable by Claude Code)
	SOCKS string `json:"socks,omitempty"` // socks5://host:port (Claude Desktop only)
	PAC   string `json:"pac,omitempty"`   // PAC URL (not evaluated)
}

func (p SystemProxy) Enabled() bool { return p.HTTP != "" || p.SOCKS != "" }

// CheckURL is the proxy whose exit IP decides whether Claude Desktop is safe.
func (p SystemProxy) CheckURL() string {
	if p.HTTP != "" {
		return p.HTTP
	}
	return p.SOCKS
}

// ProxyRoute is the result of checking Claude Desktop's system-proxy route.
// SystemProxy.HTTP holds an HTTP proxy usable by Claude Code (in PAC mode: the
// PAC's PROXY entry for Anthropic).
type ProxyRoute struct {
	SystemProxy
	Mode      string      `json:"mode,omitempty"`      // "manual" or "pac"
	Checked   string      `json:"checked,omitempty"`   // proxy whose exit was checked ("" = DIRECT)
	PACResult string      `json:"pacResult,omitempty"` // raw FindProxyForURL answer for claude.ai
	Kind      VerdictKind `json:"kind,omitempty"`
	OK        bool        `json:"ok"`
	IPv4      string      `json:"ipv4,omitempty"`
	IPv6      string      `json:"ipv6,omitempty"`
	Country   string      `json:"country,omitempty"`
	Detail    string      `json:"detail,omitempty"`
}

// NormalizeProxyURL adds http:// when the scheme is missing and maps socks -> socks5.
func NormalizeProxyURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	if strings.HasPrefix(strings.ToLower(s), "socks://") {
		s = "socks5://" + s[len("socks://"):]
	}
	return strings.TrimRight(s, "/")
}

// ParseWinProxyServer parses the Windows ProxyServer registry value:
// "127.0.0.1:10809" (all protocols) or "http=h:p;https=h:p;socks=h:p".
func ParseWinProxyServer(s string) SystemProxy {
	s = strings.TrimSpace(s)
	if s == "" {
		return SystemProxy{}
	}
	if !strings.Contains(s, "=") {
		return SystemProxy{HTTP: NormalizeProxyURL(s)}
	}
	var http, https, socks string
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "http":
			http = v
		case "https":
			https = v
		case "socks":
			socks = v
		}
	}
	p := SystemProxy{}
	if https != "" {
		p.HTTP = NormalizeProxyURL(https)
	} else if http != "" {
		p.HTTP = NormalizeProxyURL(http)
	}
	if socks != "" {
		if !strings.Contains(socks, "://") {
			socks = "socks5://" + socks
		}
		p.SOCKS = NormalizeProxyURL(socks)
	}
	return p
}

// ClaudeCodeProxy returns the proxy Claude Code itself will use, given its environment
// (same precedence as Claude Code: https_proxy, HTTPS_PROXY, http_proxy, HTTP_PROXY),
// or "" if it connects to Anthropic directly (none set, or NO_PROXY covers anthropic.com).
func ClaudeCodeProxy(getenv func(string) string) string {
	p := ""
	for _, k := range []string{"https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"} {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			p = v
			break
		}
	}
	if p == "" {
		return ""
	}
	noProxy := getenv("no_proxy")
	if noProxy == "" {
		noProxy = getenv("NO_PROXY")
	}
	if strings.TrimSpace(noProxy) == "*" {
		return ""
	}
	for _, e := range strings.FieldsFunc(noProxy, func(r rune) bool { return r == ',' || r == ' ' }) {
		e = strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(e, "*"), "."))
		if e == "" {
			continue
		}
		for _, h := range []string{"api.anthropic.com", "anthropic.com", "claude.ai"} {
			if h == e || strings.HasSuffix(h, "."+e) {
				return ""
			}
		}
	}
	return NormalizeProxyURL(p)
}

// SameEndpoint reports whether two proxy URLs point at the same host:port.
func SameEndpoint(a, b string) bool {
	ua, err1 := url.Parse(NormalizeProxyURL(a))
	ub, err2 := url.Parse(NormalizeProxyURL(b))
	if err1 != nil || err2 != nil || a == "" || b == "" {
		return false
	}
	host := func(u *url.URL) string {
		h := strings.ToLower(u.Hostname())
		if h == "localhost" || h == "::1" {
			h = "127.0.0.1"
		}
		port := u.Port()
		if port == "" {
			port = "80"
		}
		return net.JoinHostPort(h, port)
	}
	return host(ua) == host(ub)
}

// Describe is a short human label, e.g. "http://127.0.0.1:10809" or "PAC -> DIRECT".
func (r ProxyRoute) Describe() string {
	via := r.Checked
	if via == "" {
		via = "DIRECT"
	}
	if r.Mode == "pac" {
		return "PAC -> " + via
	}
	return via
}
