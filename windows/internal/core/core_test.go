package core

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestDecide(t *testing.T) {
	cases := []struct {
		ip4, c4, ip6, c6 string
		want             VerdictKind
	}{
		{"1.2.3.4", "DE", "", "", VerdictAllowed},
		{"1.2.3.4", "IR", "", "", VerdictIran},
		{"1.2.3.4", "DE", "2001::1", "IR", VerdictIran}, // Iranian IPv6 leaks too
		{"1.2.3.4", "", "", "", VerdictUnknown},
		{"1.2.3.4", "DE", "2001::1", "", VerdictUnknown},
		{"", "", "2001::1", "NL", VerdictAllowed},
	}
	for _, c := range cases {
		if got := decide(c.ip4, c.c4, c.ip6, c.c6).Kind; got != c.want {
			t.Errorf("decide(%v) = %s, want %s", c, got, c.want)
		}
	}
}

func TestParse(t *testing.T) {
	if ParseCode("IR\n") != "IR" || ParseCode("ir") != "IR" || ParseCode("Undefined") != "" || ParseCode("") != "" {
		t.Error("ParseCode")
	}
	if ParseCountryIs(`{"ip":"1.1.1.1","country":"IR"}`) != "IR" || ParseCountryIs("rate limited") != "" {
		t.Error("ParseCountryIs")
	}
}

func TestRenderHosts(t *testing.T) {
	orig := "# Copyright\r\n127.0.0.1 localhost\r\n"
	blocked := RenderHosts(orig, true)
	if !strings.Contains(blocked, "0.0.0.0 api.anthropic.com\r\n") || !strings.HasPrefix(blocked, orig) {
		t.Fatalf("block render wrong:\n%s", blocked)
	}
	if RenderHosts(blocked, true) != blocked {
		t.Error("block not idempotent")
	}
	if got := RenderHosts(blocked, false); got != orig {
		t.Errorf("unblock didn't restore original: %q", got)
	}
	// LF-only input + existing user entries after our section survive
	mixed := "127.0.0.1 localhost\n" + HostsBegin + "\n0.0.0.0 claude.ai\n" + HostsEnd + "\n10.0.0.1 nas\n"
	if got := RenderHosts(mixed, false); got != "127.0.0.1 localhost\r\n10.0.0.1 nas\r\n" {
		t.Errorf("mixed: %q", got)
	}
}

func TestHookEditPreservesOrderAndIsIdempotent(t *testing.T) {
	in := []byte(`{
  "model": "opus",
  "hooks": {
    "Stop": [{"hooks": [{"type": "command", "command": "notify"}]}],
    "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "other"}]}]
  },
  "zeta": 1
}`)
	out, unchanged, err := AddHook(in, HookCommand)
	if err != nil || unchanged {
		t.Fatal(err, unchanged)
	}
	s := string(out)
	if !(strings.Index(s, `"model"`) < strings.Index(s, `"hooks"`) && strings.Index(s, `"hooks"`) < strings.Index(s, `"zeta"`)) {
		t.Errorf("key order changed:\n%s", s)
	}
	if !strings.Contains(s, `"other"`) || !strings.Contains(s, `claudeguard.exe`) {
		t.Errorf("hook missing:\n%s", s)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	if _, unchanged, _ := AddHook(out, HookCommand); !unchanged {
		t.Error("second AddHook should be a no-op")
	}
	back, unchanged, err := RemoveHook(out, HookCommand)
	if err != nil || unchanged || strings.Contains(string(back), "claudeguard") || !strings.Contains(string(back), `"other"`) {
		t.Errorf("remove failed: %v %v\n%s", err, unchanged, back)
	}
	// empty / missing file
	if out, _, err := AddHook(nil, HookCommand); err != nil || !strings.Contains(string(out), "UserPromptSubmit") {
		t.Error("AddHook on empty settings", err)
	}
}

// Live network test: CLAUDEGUARD_NET=1 go test ./internal/core -run Live -v
func TestLiveLookup(t *testing.T) {
	if os.Getenv("CLAUDEGUARD_NET") == "" {
		t.Skip("set CLAUDEGUARD_NET=1")
	}
	c := NewChecker()
	ctx := context.Background()
	for ip, want := range map[string]string{"2.144.1.1": "IR", "5.160.0.1": "IR", "8.8.8.8": "US"} {
		if got := c.Country(ctx, ip); got != want {
			t.Errorf("%s = %q, want %s", ip, got, want)
		}
	}
	v := c.Check(ctx)
	t.Logf("this machine: %+v", v)
}

func TestIsClaudeDesktop(t *testing.T) {
	cases := map[string]bool{
		`C:\Users\me\AppData\Local\AnthropicClaude\app-0.14.1\claude.exe`:                       true,
		`C:\Program Files\WindowsApps\Claude_1.0.0.0_x64__pzs8sxrjxfjjc\app\claude.exe`:         true,
		`C:\Users\me\.local\bin\claude.exe`:                                                     false, // Claude Code CLI
		`C:\Users\me\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe`: false,
		`C:\Users\me\AppData\Local\AnthropicClaude\Update.exe`:                                  false,
	}
	for path, want := range cases {
		name := path[strings.LastIndex(path, `\`)+1:]
		if got := IsClaudeDesktop(name, path); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}
}

func TestProxyParsing(t *testing.T) {
	if p := ParseWinProxyServer("127.0.0.1:10809"); p.HTTP != "http://127.0.0.1:10809" || p.SOCKS != "" {
		t.Errorf("plain: %+v", p)
	}
	p := ParseWinProxyServer("http=127.0.0.1:10809;https=127.0.0.1:10809;socks=127.0.0.1:10808")
	if p.HTTP != "http://127.0.0.1:10809" || p.SOCKS != "socks5://127.0.0.1:10808" {
		t.Errorf("multi: %+v", p)
	}
	if p := ParseWinProxyServer("socks=127.0.0.1:10808"); p.HTTP != "" || p.CheckURL() != "socks5://127.0.0.1:10808" {
		t.Errorf("socks only: %+v", p)
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if got := ClaudeCodeProxy(env(map[string]string{"HTTPS_PROXY": "127.0.0.1:10809"})); got != "http://127.0.0.1:10809" {
		t.Errorf("env: %q", got)
	}
	if got := ClaudeCodeProxy(env(map[string]string{"https_proxy": "http://a:1", "HTTPS_PROXY": "http://b:2"})); got != "http://a:1" {
		t.Errorf("precedence: %q", got)
	}
	if got := ClaudeCodeProxy(env(map[string]string{"HTTPS_PROXY": "http://a:1", "NO_PROXY": "localhost,.anthropic.com"})); got != "" {
		t.Errorf("no_proxy: %q", got)
	}
	if got := ClaudeCodeProxy(env(map[string]string{"HTTPS_PROXY": "http://a:1", "NO_PROXY": "*"})); got != "" {
		t.Errorf("no_proxy *: %q", got)
	}
	if got := ClaudeCodeProxy(env(map[string]string{"HTTPS_PROXY": "http://a:1", "NO_PROXY": "example.com"})); got != "http://a:1" {
		t.Errorf("no_proxy other: %q", got)
	}
	if !SameEndpoint("http://localhost:10809", "127.0.0.1:10809") || SameEndpoint("http://127.0.0.1:1", "http://127.0.0.1:2") {
		t.Error("SameEndpoint")
	}
}

func TestEnvEdit(t *testing.T) {
	in := []byte(`{"model":"opus","env":{"FOO":"1"},"hooks":{}}`)
	out, err := SetEnv(in, "HTTPS_PROXY", "http://127.0.0.1:10809")
	if err != nil || !strings.Contains(string(out), `"HTTPS_PROXY": "http://127.0.0.1:10809"`) || !strings.Contains(string(out), `"FOO"`) {
		t.Fatalf("%v\n%s", err, out)
	}
	back, unchanged, err := UnsetEnv(out, "HTTPS_PROXY")
	if err != nil || unchanged || strings.Contains(string(back), "HTTPS_PROXY") || !strings.Contains(string(back), "FOO") {
		t.Errorf("unset: %v %s", err, back)
	}
	only, _ := SetEnv([]byte(`{}`), "HTTPS_PROXY", "x")
	empty, _, _ := UnsetEnv(only, "HTTPS_PROXY")
	if strings.Contains(string(empty), "env") {
		t.Errorf("empty env should be removed: %s", empty)
	}
}

func TestNetInfo(t *testing.T) {
	if !IsTunnelAdapter("v2rayN", "Wintun Userspace Tunnel", 53) || !IsTunnelAdapter("singbox_tun", "sing-tun", 6) ||
		!IsTunnelAdapter("WireGuard", "WireGuard Tunnel", 6) || IsTunnelAdapter("Wi-Fi", "Intel(R) Wi-Fi 6 AX201", 71) ||
		IsTunnelAdapter("Ethernet", "Realtek PCIe GbE", 6) {
		t.Error("IsTunnelAdapter")
	}
	if !IsTunnelIfaceName("utun4") || !IsTunnelIfaceName("ipsec0") || IsTunnelIfaceName("en0") {
		t.Error("IsTunnelIfaceName")
	}
	tun := NetInfo{CheckIface: "utun4", CheckIsTunnel: true, AnthropicIface: "utun4", AnthropicIsTunnel: true, TunnelName: "utun4"}
	if !tun.TunnelActive() || tun.AnthropicBypassesCheck() || !strings.Contains(tun.Summary(), "TUN VPN on") {
		t.Errorf("tun: %s", tun.Summary())
	}
	bypass := NetInfo{CheckIface: "utun4", CheckIsTunnel: true, AnthropicIface: "en0", TunnelName: "utun4"}
	if !bypass.AnthropicBypassesCheck() || !strings.Contains(bypass.Summary(), "BYPASSES") {
		t.Errorf("bypass: %s", bypass.Summary())
	}
	none := NetInfo{CheckIface: "en0", AnthropicIface: "en0"}
	if none.TunnelActive() || none.AnthropicBypassesCheck() {
		t.Error("none")
	}
}
