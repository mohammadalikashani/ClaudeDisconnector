package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dop251/goja"
)

// AnthropicPACTargets are the URLs whose PAC answer decides Claude Desktop's route.
// (Chromium hands PAC scripts https URLs stripped to scheme://host/.)
var AnthropicPACTargets = []string{"https://claude.ai/", "https://api.anthropic.com/"}

// DesktopRoute is the route Claude Desktop (Chromium) takes to Anthropic.
type DesktopRoute struct {
	Mode      string // "manual" or "pac"
	Proxy     string // proxy to check ("" = DIRECT)
	HTTP      string // an HTTP proxy usable by Claude Code ("" if none)
	PACResult string // raw FindProxyForURL answer
	Note      string // e.g. PAC load/eval error (Chromium then goes DIRECT)
}

// ResolveDesktopRoute works out Claude Desktop's route from the system proxy settings.
// PAC takes precedence over the manual proxy (as on Windows and macOS).
func ResolveDesktopRoute(ctx context.Context, sp SystemProxy) DesktopRoute {
	if sp.PAC == "" {
		return DesktopRoute{Mode: "manual", Proxy: sp.CheckURL(), HTTP: sp.HTTP}
	}
	r := DesktopRoute{Mode: "pac"}
	script, err := FetchPAC(ctx, sp.PAC)
	if err != nil {
		r.Note = "couldn't load the PAC file (" + err.Error() + "), so Claude Desktop connects DIRECT"
		return r
	}
	var answers []string
	for _, target := range AnthropicPACTargets {
		u, _ := url.Parse(target)
		res, err := EvalPAC(script, target, u.Hostname())
		if err != nil {
			r.Note = "PAC script failed (" + err.Error() + "), so Claude Desktop connects DIRECT"
			return r
		}
		answers = append(answers, res)
	}
	r.PACResult = answers[0]
	first := ParsePACResult(answers[0])
	for _, a := range answers[1:] {
		if other := ParsePACResult(a); other[0] != first[0] {
			// Anthropic hosts get different routes: if either goes DIRECT, use DIRECT,
			// so the stricter direct verdict applies to Claude Desktop.
			if other[0] == "" {
				first = other
				r.PACResult = a
			}
		}
	}
	if len(first) > 0 {
		r.Proxy = first[0]
	}
	for _, p := range first {
		if strings.HasPrefix(p, "http://") {
			r.HTTP = p
			break
		}
	}
	return r
}

// ParsePACResult turns "PROXY a:1; SOCKS5 b:2; DIRECT" into
// ["http://a:1", "socks5://b:2", ""] ("" = DIRECT). Unknown entries are skipped.
func ParsePACResult(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ";") {
		f := strings.Fields(part)
		if len(f) == 0 {
			continue
		}
		switch strings.ToUpper(f[0]) {
		case "DIRECT":
			out = append(out, "")
		case "PROXY", "HTTP", "HTTPS":
			if len(f) > 1 {
				out = append(out, "http://"+f[1])
			}
		case "SOCKS", "SOCKS5", "SOCKS4":
			if len(f) > 1 {
				out = append(out, "socks5://"+f[1])
			}
		}
	}
	if len(out) == 0 {
		out = []string{""} // empty/garbage answer -> DIRECT (Chromium behaviour)
	}
	return out
}

// FetchPAC downloads a PAC file directly (never through a proxy). file:// is supported.
func FetchPAC(ctx context.Context, pacURL string) (string, error) {
	u, err := url.Parse(pacURL)
	if err != nil {
		return "", err
	}
	if u.Scheme == "file" {
		p := u.Path
		if u.Host != "" {
			p = u.Host + p
		}
		p = strings.TrimPrefix(p, "/")
		if len(p) < 2 || p[1] != ':' { // not a Windows drive path -> absolute unix path
			p = "/" + p
		}
		b, err := os.ReadFile(p)
		return string(b), err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", pacURL, nil)
	if err != nil {
		return "", err
	}
	cl := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return string(b), err
}

// EvalPAC runs FindProxyForURL(url, host) from a PAC script (2s time limit).
func EvalPAC(script, target, host string) (string, error) {
	vm := goja.New()
	installPACBuiltins(vm)
	timer := time.AfterFunc(2*time.Second, func() { vm.Interrupt("PAC script timed out") })
	defer timer.Stop()

	if _, err := vm.RunString(pacUtilsJS); err != nil {
		return "", err
	}
	if _, err := vm.RunString(script); err != nil {
		return "", err
	}
	fn, ok := goja.AssertFunction(vm.Get("FindProxyForURL"))
	if !ok {
		// Microsoft's IPv6-aware variant.
		if fn, ok = goja.AssertFunction(vm.Get("FindProxyForURLEx")); !ok {
			return "", errors.New("no FindProxyForURL function")
		}
	}
	v, err := fn(goja.Undefined(), vm.ToValue(target), vm.ToValue(host))
	if err != nil {
		return "", err
	}
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return "DIRECT", nil
	}
	return v.String(), nil
}

// Builtins that need the network stack; the rest are plain JS (pacUtilsJS).
func installPACBuiltins(vm *goja.Runtime) {
	resolve := func(host string, v6ok bool) []string {
		if ip := net.ParseIP(host); ip != nil {
			return []string{ip.String()}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil
		}
		var out []string
		for _, ip := range ips {
			if ip.IP.To4() != nil || v6ok {
				out = append(out, ip.IP.String())
			}
		}
		return out
	}
	myIP := func() string {
		c, err := net.Dial("udp", "8.8.8.8:53") // no packets are sent
		if err != nil {
			return "127.0.0.1"
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).IP.String()
	}
	_ = vm.Set("dnsResolve", func(host string) any {
		if ips := resolve(host, false); len(ips) > 0 {
			return ips[0]
		}
		return nil
	})
	_ = vm.Set("dnsResolveEx", func(host string) string { return strings.Join(resolve(host, true), ";") })
	_ = vm.Set("myIpAddress", myIP)
	_ = vm.Set("myIpAddressEx", myIP)
	_ = vm.Set("isResolvable", func(host string) bool { return len(resolve(host, false)) > 0 })
	_ = vm.Set("isResolvableEx", func(host string) bool { return len(resolve(host, true)) > 0 })
	_ = vm.Set("alert", func(string) {})
}

// Standard PAC helpers (after Mozilla's ascii_pac_utils).
const pacUtilsJS = `
function isPlainHostName(host) { return host.indexOf('.') < 0; }
function dnsDomainIs(host, domain) {
  return host.length >= domain.length && host.substring(host.length - domain.length) == domain;
}
function localHostOrDomainIs(host, hostdom) {
  return host == hostdom || hostdom.lastIndexOf(host + '.', 0) == 0;
}
function dnsDomainLevels(host) { return host.split('.').length - 1; }
function convert_addr(ipchars) {
  var b = ipchars.split('.');
  return ((b[0] & 0xff) << 24) | ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff);
}
function isInNet(ipaddr, pattern, maskstr) {
  var re = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  if (!re.test(ipaddr)) { ipaddr = dnsResolve(ipaddr); if (ipaddr == null) return false; }
  if (!re.test(pattern) || !re.test(maskstr)) return false;
  var host = convert_addr(ipaddr), pat = convert_addr(pattern), mask = convert_addr(maskstr);
  return (host & mask) == (pat & mask);
}
function isInNetEx(ipaddr, prefix) {
  var p = prefix.split('/'); var bits = parseInt(p[1], 10);
  if (p[0].indexOf(':') >= 0 || ipaddr.indexOf(':') >= 0) return false;
  var m = bits == 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  var mask = [(m>>>24)&255,(m>>>16)&255,(m>>>8)&255,m&255].join('.');
  return isInNet(ipaddr, p[0], mask);
}
function shExpMatch(url, pattern) {
  pattern = pattern.replace(/\./g, '\\.').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp('^' + pattern + '$').test(url);
}
var wdays = {SUN: 0, MON: 1, TUE: 2, WED: 3, THU: 4, FRI: 5, SAT: 6};
var months = {JAN: 0, FEB: 1, MAR: 2, APR: 3, MAY: 4, JUN: 5, JUL: 6, AUG: 7, SEP: 8, OCT: 9, NOV: 10, DEC: 11};
function weekdayRange() {
  var a = Array.prototype.slice.call(arguments); var gmt = a[a.length-1] == 'GMT'; if (gmt) a.pop();
  var d = new Date(); var day = gmt ? d.getUTCDay() : d.getDay();
  var w1 = wdays[a[0]], w2 = a.length > 1 ? wdays[a[1]] : w1;
  if (w1 === undefined || w2 === undefined) return false;
  return w1 <= w2 ? (day >= w1 && day <= w2) : (day >= w1 || day <= w2);
}
function timeRange() {
  var a = Array.prototype.slice.call(arguments); var gmt = a[a.length-1] == 'GMT'; if (gmt) a.pop();
  var d = new Date(); var h = gmt ? d.getUTCHours() : d.getHours();
  if (a.length == 1) return h == a[0];
  if (a.length == 2) return a[0] <= a[1] ? (h >= a[0] && h < a[1]) : (h >= a[0] || h < a[1]);
  return true;
}
function dateRange() { return true; }
function sortIpAddressList(list) { return list; }
function getClientVersion() { return '1.0'; }
`
