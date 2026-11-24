package core

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// HookDeps are the side effects the Claude Code hook needs (injectable for tests).
type HookDeps struct {
	Load      func() *Status
	Refresh   func() error
	CheckVia  func(proxyURL string) Verdict // live check of Claude Code's own proxy
	Getenv    func(string) string           // Claude Code's environment (hooks inherit it)
	Wait      time.Duration                 // how long to wait for a refreshed status
	CachePath string                        // caches successful proxy checks for 60s
	Where     string                        // "tray icon" / "menu bar icon"
	CLI       string                        // how to invoke the CLI, for messages
}

const proxyCacheTTL = 60 * time.Second

// RunHook decides whether Claude Code may send a prompt. It returns allow=false
// with a message for the user when the prompt must be blocked.
//
// Claude Code ignores the OS system proxy; it only uses https_proxy/HTTPS_PROXY/
// http_proxy/HTTP_PROXY. So the route that matters is decided by its environment:
//   - proxy env set  -> the prompt goes through that proxy: allowed if the proxy exits abroad;
//   - no proxy env   -> the prompt goes direct: allowed only if the direct route is verified.
func RunHook(d HookDeps) (bool, string) {
	s := d.Load()
	if s == nil || s.IsStale() {
		return false, "⛔ ClaudeGuard: the protection service is not running, so your location can't be verified.\n" +
			"Prompt blocked to avoid leaking an Iranian IP. Start the ClaudeGuard service or reinstall.\n"
	}

	note := ""
	if proxy := ClaudeCodeProxy(d.Getenv); proxy != "" {
		direct := false
		for _, a := range s.Apps {
			if a.ServesPort(proxy) && a.SendsClaudeDirect() {
				// Claude Code's proxy is Clash/sing-box, whose rules send Claude DIRECT:
				// the prompt really leaves through the direct route.
				direct = true
				note = "Claude Code's proxy " + proxy + " is " + a.Name() + ", which sends Claude DIRECT (" +
					a.Anthropic.Rule + "). Route anthropic.com and claude.ai through your proxy (group / outbound).\n"
			}
		}
		if !direct {
			return hookViaProxy(d, s, proxy)
		}
	}
	allow, msg := hookDirect(d, s)
	if !allow && note != "" {
		msg = strings.TrimRight(msg, "\n") + "\n" + note
	}
	return allow, msg
}

func hookDirect(d HookDeps, s *Status) (bool, string) {

	// Direct route.
	if !s.Enforcing && s.State != StateBlocked {
		return true, ""
	}
	asked := Now()
	_ = d.Refresh() // maybe the VPN was just turned on
	for deadline := time.Now().Add(d.Wait); time.Now().Before(deadline); {
		time.Sleep(250 * time.Millisecond)
		if cur := d.Load(); cur != nil && cur.State != StateChecking &&
			cur.CheckedAt != nil && !cur.CheckedAt.Before(asked) {
			s = cur
			if !s.Enforcing {
				return true, ""
			}
			break
		}
	}

	ip := s.IPv4
	if ip == "" {
		ip = s.IPv6
	}
	where := "Click Refresh on the ClaudeGuard " + d.Where + " (or just send your prompt again)."
	for _, a := range s.Apps {
		if a.SendsClaudeDirect() {
			return false, fmt.Sprintf("⛔ ClaudeGuard: Claude is blocked - %s sends Claude traffic DIRECT (%s), so your real IP %s would be used.\n"+
				"Route anthropic.com and claude.ai through your proxy (group / outbound) in %s, then %s\n",
				a.Name(), a.Anthropic.Rule, orDashStr(ip), a.Name(), strings.ToLower(where[:1])+where[1:])
		}
	}
	switch {
	case s.State == StateProxyOnly && s.Proxy != nil && s.Proxy.HTTP != "":
		return false, fmt.Sprintf("⛔ ClaudeGuard: your direct connection is in %s (IP %s) and this Claude Code session is NOT using your v2ray proxy.\n"+
			"Claude Code ignores the system proxy. Route it through v2ray:\n"+
			"    %s claude-proxy on      (then restart Claude Code)\n"+
			"or start Claude Code with  HTTPS_PROXY=%s\n",
			placeName(s), orDashStr(ip), d.CLI, s.Proxy.HTTP)
	case s.State == StateProxyOnly:
		return false, fmt.Sprintf("⛔ ClaudeGuard: your direct connection is in %s (IP %s). Your system proxy is SOCKS-only, "+
			"which Claude Code can't use. Enable v2ray's HTTP proxy port and set HTTPS_PROXY to it, or use TUN mode.\n",
			placeName(s), orDashStr(ip))
	case s.InIran && s.Network != nil && s.Network.Bound:
		return false, fmt.Sprintf("⛔ ClaudeGuard: You are in IRAN (IP %s): your VPN is on, but Anthropic traffic BYPASSES it (goes via %s).\n"+
			"Claude is blocked so your Iranian IP is not sent to Anthropic. Fix your VPN's split-tunnel/bypass rules, then %s\n",
			orDashStr(ip), s.Network.AnthropicIface, strings.ToLower(where[:1])+where[1:])
	case s.InIran && s.Network != nil && s.Network.TunnelActive():
		return false, fmt.Sprintf("⛔ ClaudeGuard: You are in IRAN (IP %s), even though a TUN VPN (%s) is up - is it connected?\n"+
			"Claude is blocked so your Iranian IP is not sent to Anthropic. %s\n", orDashStr(ip), s.Network.TunnelName, where)
	case s.InIran:
		return false, fmt.Sprintf("⛔ ClaudeGuard: You are in IRAN (IP %s).\n"+
			"Claude is blocked so your Iranian IP is not sent to Anthropic.\n"+
			"Turn on your VPN (TUN mode, or system-proxy mode + `%s claude-proxy on`). %s\n",
			orDashStr(ip), d.CLI, where)
	default:
		return false, "⛔ ClaudeGuard: Claude is blocked - " + s.Message + "\n" + where + "\n"
	}
}

func hookViaProxy(d HookDeps, s *Status, proxy string) (bool, string) {
	if strings.HasPrefix(strings.ToLower(proxy), "socks") {
		return false, "⛔ ClaudeGuard: Claude Code's proxy is " + proxy + ", but Claude Code doesn't support SOCKS proxies.\n" +
			"Set HTTPS_PROXY to v2ray's HTTP port instead (e.g. http://127.0.0.1:10809).\n"
	}
	// Same proxy the service already verified?
	if s.Proxy != nil && s.Proxy.OK && SameEndpoint(proxy, s.Proxy.Checked) {
		return true, ""
	}
	if readProxyCache(d.CachePath, proxy) {
		return true, ""
	}
	v := d.CheckVia(proxy)
	if v.Kind == VerdictAllowed {
		writeProxyCache(d.CachePath, proxy)
		return true, ""
	}
	if v.Kind == VerdictIran {
		return false, "⛔ ClaudeGuard: Claude Code's proxy " + proxy + " exits in IRAN. " + v.Detail + "\n" +
			"Prompt blocked so your Iranian IP is not sent to Anthropic. Check your v2ray server/routing.\n"
	}
	return false, "⛔ ClaudeGuard: couldn't verify Claude Code's proxy " + proxy + ": " + v.Detail + "\n" +
		"Make sure v2ray is running and connected, then send your prompt again.\n"
}

func placeName(s *Status) string {
	if s.InIran {
		return "IRAN"
	}
	return "an unverified location"
}

func orDashStr(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

type proxyCache struct {
	Proxy     string    `json:"proxy"`
	CheckedAt time.Time `json:"checkedAt"`
}

func readProxyCache(path, proxy string) bool {
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var c proxyCache
	return json.Unmarshal(data, &c) == nil && SameEndpoint(c.Proxy, proxy) && time.Since(c.CheckedAt) < proxyCacheTTL
}

func writeProxyCache(path, proxy string) {
	if path == "" {
		return
	}
	b, _ := json.Marshal(proxyCache{Proxy: proxy, CheckedAt: time.Now()})
	_ = os.WriteFile(path, b, 0o600)
}
