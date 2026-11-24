package core

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func st(state State, enforcing, iran bool, proxy *ProxyRoute) *Status {
	now := Now()
	return &Status{State: state, Enforcing: enforcing, InIran: iran, IPv4: "2.144.1.1",
		Proxy: proxy, CheckedAt: &now, UpdatedAt: time.Now()}
}

func deps(t *testing.T, s *Status, env map[string]string, proxyVerdict VerdictKind) (HookDeps, *int) {
	checks := 0
	return HookDeps{
		Load:      func() *Status { return s },
		Refresh:   func() error { return nil },
		CheckVia:  func(string) Verdict { checks++; return Verdict{Kind: proxyVerdict, Detail: "x"} },
		Getenv:    func(k string) string { return env[k] },
		Wait:      300 * time.Millisecond,
		CachePath: filepath.Join(t.TempDir(), "cache.json"),
		Where:     "tray icon",
		CLI:       "claudeguard",
	}, &checks
}

func TestHook(t *testing.T) {
	v2ray := &ProxyRoute{SystemProxy: SystemProxy{HTTP: "http://127.0.0.1:10809"}, Checked: "http://127.0.0.1:10809", OK: true, Kind: VerdictAllowed, Country: "DE"}
	proxyEnv := map[string]string{"HTTPS_PROXY": "http://localhost:10809"}

	cases := []struct {
		name    string
		s       *Status
		env     map[string]string
		pv      VerdictKind
		allow   bool
		msgHas  string
		checked int
	}{
		{"service down", nil, nil, VerdictAllowed, false, "not running", 0},
		{"direct allowed", st(StateAllowed, false, false, nil), nil, VerdictAllowed, true, "", 0},
		{"direct iran, no proxy", st(StateBlocked, true, true, nil), nil, VerdictAllowed, false, "IRAN", 0},
		{"v2ray system proxy, Claude Code direct", st(StateProxyOnly, true, true, v2ray), nil, VerdictAllowed, false, "claude-proxy on", 0},
		{"v2ray system proxy, Claude Code via same proxy", st(StateProxyOnly, true, true, v2ray), proxyEnv, VerdictIran, true, "", 0},
		{"own proxy, verified live", st(StateBlocked, true, true, nil), map[string]string{"HTTPS_PROXY": "http://10.0.0.5:3128"}, VerdictAllowed, true, "", 1},
		{"own proxy exits in Iran", st(StateAllowed, false, false, nil), map[string]string{"HTTPS_PROXY": "http://10.0.0.5:3128"}, VerdictIran, false, "exits in IRAN", 1},
		{"socks env", st(StateProxyOnly, true, true, v2ray), map[string]string{"HTTPS_PROXY": "socks5://127.0.0.1:10808"}, VerdictAllowed, false, "SOCKS", 0},
		{"TUN bypassed", func() *Status {
			x := st(StateBlocked, true, true, nil)
			x.Network = &NetInfo{CheckIface: "v2rayN", CheckIsTunnel: true, AnthropicIface: "Wi-Fi", Bound: true}
			return x
		}(), nil, VerdictAllowed, false, "BYPASSES", 0},
		{"TUN up but Iran", func() *Status {
			x := st(StateBlocked, true, true, nil)
			x.Network = &NetInfo{CheckIface: "v2rayN", CheckIsTunnel: true, AnthropicIface: "v2rayN", AnthropicIsTunnel: true, TunnelName: "v2rayN"}
			return x
		}(), nil, VerdictAllowed, false, "is it connected", 0},
		{"HTTPS_PROXY is Clash sending Claude DIRECT", func() *Status {
			x := st(StateBlocked, true, true, nil)
			x.Apps = []ProxyApp{{Kind: "clash", Ports: []int{7890}, Anthropic: HostRoute{Outcome: OutDirect, Rule: "MATCH,DIRECT"}}}
			return x
		}(), map[string]string{"HTTPS_PROXY": "http://127.0.0.1:7890"}, VerdictAllowed, false, "MATCH,DIRECT", 0},
		{"HTTPS_PROXY is Clash proxying Claude", func() *Status {
			x := st(StateBlocked, true, true, nil)
			x.Apps = []ProxyApp{{Kind: "clash", Ports: []int{7890}, Anthropic: HostRoute{Outcome: OutProxy}}}
			return x
		}(), map[string]string{"HTTPS_PROXY": "http://127.0.0.1:7890"}, VerdictAllowed, true, "", 1},
		{"NO_PROXY anthropic -> direct", st(StateBlocked, true, true, nil), map[string]string{"HTTPS_PROXY": "http://a:1", "NO_PROXY": ".anthropic.com"}, VerdictAllowed, false, "IRAN", 0},
	}
	for _, c := range cases {
		d, checks := deps(t, c.s, c.env, c.pv)
		if c.s == nil {
			d.Load = func() *Status { return nil }
		}
		allow, msg := RunHook(d)
		if allow != c.allow || !strings.Contains(msg, c.msgHas) || *checks != c.checked {
			t.Errorf("%s: allow=%v checks=%d msg=%q", c.name, allow, *checks, msg)
		}
	}
}

func TestHookProxyCache(t *testing.T) {
	d, checks := deps(t, st(StateBlocked, true, true, nil), map[string]string{"HTTPS_PROXY": "http://10.0.0.5:3128"}, VerdictAllowed)
	RunHook(d)
	RunHook(d)
	if *checks != 1 {
		t.Errorf("second run should use cache, checks=%d", *checks)
	}
}
