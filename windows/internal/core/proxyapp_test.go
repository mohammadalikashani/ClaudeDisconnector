package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func detect(t *testing.T, kind, path string) ProxyApp {
	apps := DetectProxyApps(context.Background(), []ConfigCandidate{{kind, path}}, func(string) bool { return true })
	for _, a := range apps {
		if strings.Contains(a.Source, path) {
			return a
		}
	}
	t.Fatalf("no app detected from %s (got %+v)", path, apps)
	return ProxyApp{}
}

// Typical "proxy only blocked sites, everything else DIRECT" config - Claude isn't listed.
const clashBypassAll = `
mixed-port: 7890
mode: rule
proxies:
  - {name: de-1, type: vless, server: 1.2.3.4, port: 443, uuid: x}
proxy-groups:
  - name: Proxy
    type: select
    proxies: [de-1]
rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN-SUFFIX,youtube.com,Proxy
  - GEOIP,IR,DIRECT
  - MATCH,DIRECT
`

// Claude proxied, but the IP-check sites fall through to DIRECT.
const clashClaudeOnly = `
rules:
  - DOMAIN-SUFFIX,anthropic.com,Proxy
  - DOMAIN-SUFFIX,claude.ai,Proxy
  - GEOSITE,category-ir,DIRECT
  - MATCH,DIRECT
proxy-groups:
  - {name: Proxy, type: select, proxies: [de-1]}
`

// The usual "bypass Iran, proxy the rest".
const clashBypassIran = `
rules:
  - GEOSITE,category-ir,DIRECT
  - GEOIP,IR,DIRECT,no-resolve
  - GEOIP,private,DIRECT
  - DOMAIN-SUFFIX,ir,DIRECT
  - MATCH,Proxy
proxy-groups:
  - name: Proxy
    type: url-test
    proxies: [de-1, nl-2]
`

const clashGroupWithDirect = `
rules:
  - MATCH,Proxy
proxy-groups:
  - {name: Proxy, type: select, proxies: [de-1, DIRECT]}
`

func TestClashFiles(t *testing.T) {
	a := detect(t, "clash", writeTemp(t, "a.yaml", clashBypassAll))
	if !a.SendsClaudeDirect() || a.Anthropic.Rule != "MATCH,DIRECT" {
		t.Errorf("bypass-all: %+v", a.Anthropic)
	}
	b := detect(t, "clash", writeTemp(t, "b.yaml", clashClaudeOnly))
	if b.SendsClaudeDirect() || b.Anthropic.Outcome != OutProxy || !b.CheckMisrouted() {
		t.Errorf("claude-only: anth=%+v check=%+v", b.Anthropic, b.Check)
	}
	c := detect(t, "clash", writeTemp(t, "c.yaml", clashBypassIran))
	if c.Anthropic.Outcome != OutProxy || c.Check.Outcome != OutProxy || c.CheckMisrouted() {
		t.Errorf("bypass-iran: anth=%+v check=%+v", c.Anthropic, c.Check)
	}
	d := detect(t, "clash", writeTemp(t, "d.yaml", clashGroupWithDirect))
	if d.SendsClaudeDirect() || d.Anthropic.Outcome != OutUnknown {
		t.Errorf("group with DIRECT (no API) should be uncertain: %+v", d.Anthropic)
	}
	g := detect(t, "clash", writeTemp(t, "g.yaml", "mode: direct\nrules:\n  - MATCH,Proxy\n"))
	if !g.SendsClaudeDirect() {
		t.Errorf("mode direct: %+v", g.Anthropic)
	}
}

func TestClashRuleParsing(t *testing.T) {
	for line, host := range map[string]string{
		"DOMAIN-KEYWORD,anthropic,P":                      "api.anthropic.com",
		"DOMAIN-REGEX,^claude\\.ai$,P":                    "claude.ai",
		"IP-CIDR,160.79.104.0/23,P,no-resolve":            "api.anthropic.com",
		"GEOIP,US,P":                                      "claude.ai",
		"AND,((DOMAIN-SUFFIX,claude.ai),(NETWORK,tcp)),P": "claude.ai",
	} {
		r, ok := ParseClashRuleLine(line)
		if !ok || r.Target != "P" {
			t.Errorf("parse %q: %+v", line, r)
			continue
		}
		m := r.match(targetFor(host), "rule")
		if strings.HasPrefix(line, "AND") {
			if m != maybe {
				t.Errorf("%q should be maybe", line)
			}
		} else if m != yes {
			t.Errorf("%q should match %s", line, host)
		}
	}
	r, _ := ParseClashRuleLine("GEOIP,IR,DIRECT")
	if r.match(targetFor("claude.ai"), "rule") != no || r.match(targetFor("api4.ipify.org"), "rule") != no {
		t.Error("GEOIP,IR must not match Anthropic or the check sites")
	}
}

func TestSingBoxFile(t *testing.T) {
	cfg := map[string]any{
		"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in"}},
		"outbounds": []any{
			map[string]any{"type": "selector", "tag": "proxy", "outbounds": []any{"vless-de"}, "default": "vless-de"},
			map[string]any{"type": "vless", "tag": "vless-de"},
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "block", "tag": "block"},
		},
		"route": map[string]any{
			"rules": []any{
				map[string]any{"action": "sniff"},
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				map[string]any{"rule_set": []any{"geosite-ir", "geoip-ir"}, "outbound": "direct"},
				map[string]any{"domain_suffix": []any{"anthropic.com", "claude.ai"}, "outbound": "direct"},
			},
			"final": "proxy",
		},
	}
	b, _ := json.Marshal(cfg)
	a := detect(t, "sing-box", writeTemp(t, "sb.json", string(b)))
	if !a.TUN || !a.SendsClaudeDirect() || a.Check.Outcome != OutProxy {
		t.Errorf("sing-box claude->direct: anth=%+v check=%+v", a.Anthropic, a.Check)
	}

	// Same config, Claude goes to "proxy" instead.
	cfg["route"].(map[string]any)["rules"].([]any)[3].(map[string]any)["outbound"] = "proxy"
	b, _ = json.Marshal(cfg)
	a = detect(t, "sing-box", writeTemp(t, "sb2.json", string(b)))
	if a.Anthropic.Outcome != OutProxy || strings.Join(a.Anthropic.Chain, ">") != "proxy>vless-de" {
		t.Errorf("sing-box claude->proxy: %+v", a.Anthropic)
	}

	// clash_mode rules + reject action.
	cfg["route"].(map[string]any)["rules"] = []any{
		map[string]any{"clash_mode": "Direct", "outbound": "direct"},
		map[string]any{"domain": []any{"claude.ai"}, "action": "reject"},
	}
	cfg["experimental"] = map[string]any{"clash_api": map[string]any{"default_mode": "Direct"}}
	b, _ = json.Marshal(cfg)
	a = detect(t, "sing-box", writeTemp(t, "sb3.json", string(b)))
	if !a.SendsClaudeDirect() {
		t.Errorf("clash_mode Direct: %+v", a.Anthropic)
	}
}

// Fake mihomo API: selector "Proxy" currently set to DIRECT, a live Claude connection DIRECT.
func TestClashAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3cret" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/version":
			w.Write([]byte(`{"meta":true,"version":"v1.19.0"}`))
		case "/configs":
			w.Write([]byte(`{"mode":"rule","mixed-port":7897,"tun":{"enable":true}}`))
		case "/proxies":
			w.Write([]byte(`{"proxies":{"DIRECT":{"type":"Direct"},"REJECT":{"type":"Reject"},
			  "Proxy":{"type":"Selector","now":"DIRECT","all":["de-1","DIRECT"]},
			  "de-1":{"type":"Vless"},"GLOBAL":{"type":"Selector","now":"Proxy"}}}`))
		case "/rules":
			w.Write([]byte(`{"rules":[{"type":"GeoIP","payload":"IR","proxy":"DIRECT"},{"type":"Match","payload":"","proxy":"Proxy"}]}`))
		case "/connections":
			w.Write([]byte(`{"connections":[{"metadata":{"host":"api.anthropic.com","destinationIP":"160.79.104.10"},"chains":["DIRECT","Proxy"]}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	cfg := "external-controller: " + addr + "\nsecret: s3cret\nrules:\n  - MATCH,Proxy\nproxy-groups:\n  - {name: Proxy, type: select, proxies: [de-1, DIRECT]}\n"
	a := detect(t, "clash", writeTemp(t, "verge.yaml", cfg))
	if !a.Live || !a.TUN || a.MixedPort != 7897 {
		t.Errorf("api state: %+v", a)
	}
	if !a.SendsClaudeDirect() || strings.Join(a.Anthropic.Chain, ">") != "Proxy>DIRECT" || len(a.LiveDirect) != 1 {
		t.Errorf("selector now=DIRECT should be detected: %+v live=%v", a.Anthropic, a.LiveDirect)
	}
	if !strings.Contains(a.Describe(), "DIRECT") {
		t.Errorf("describe: %s", a.Describe())
	}

	// Wrong secret -> falls back to the file, notes the API problem.
	bad := detect(t, "clash", writeTemp(t, "bad.yaml", strings.Replace(cfg, "s3cret", "nope", 1)))
	if bad.Live || !strings.Contains(bad.Note, "secret") || bad.Anthropic.Outcome != OutUnknown {
		t.Errorf("bad secret: %+v", bad)
	}
}

func TestStaleConfigIgnored(t *testing.T) {
	p := writeTemp(t, "old.yaml", clashBypassAll)
	apps := DetectProxyApps(context.Background(), []ConfigCandidate{{"clash", p}}, func(string) bool { return false })
	for _, a := range apps {
		if strings.Contains(a.Source, p) {
			t.Error("config of a non-running app should be ignored")
		}
	}
}

func TestDecideApps(t *testing.T) {
	direct := ProxyApp{Kind: "clash", TUN: true, Ports: []int{7890}, Anthropic: HostRoute{Outcome: OutDirect}, Check: HostRoute{Outcome: OutProxy}}
	if d := DecideApps([]ProxyApp{direct}, true, ""); d.TUNDirect == nil || d.ProxyDirect != nil {
		t.Errorf("TUN app sending Claude direct: %+v", d)
	}
	if d := DecideApps([]ProxyApp{direct}, false, ""); d.TUNDirect != nil {
		t.Error("app's TUN not carrying Anthropic (other VPN) -> irrelevant")
	}
	noTun := direct
	noTun.TUN = false
	if d := DecideApps([]ProxyApp{noTun}, false, "http://127.0.0.1:7890"); d.ProxyDirect == nil {
		t.Error("system proxy -> app port -> Claude direct should be flagged")
	}
	if d := DecideApps([]ProxyApp{noTun}, false, "http://127.0.0.1:10809"); d.ProxyDirect != nil {
		t.Error("system proxy points at another app -> irrelevant")
	}
	mis := ProxyApp{Kind: "sing-box", TUN: true, Anthropic: HostRoute{Outcome: OutProxy}, Check: HostRoute{Outcome: OutDirect}}
	if d := DecideApps([]ProxyApp{mis}, true, ""); d.Misrouted == nil {
		t.Error("misrouted checks should be flagged")
	}
}

func TestClashBlockStyleGroups(t *testing.T) {
	cfg := `
proxy-groups:
  - name: Auto
    type: url-test
    proxies:
      - de-1
      - nl-2
  - name: Proxy
    type: select
    proxies:
      - Auto
      - DIRECT
rules:
  - DOMAIN-SUFFIX,claude.ai,Auto
  - DOMAIN-SUFFIX,anthropic.com,Auto
  - MATCH,Proxy
`
	a := detect(t, "clash", writeTemp(t, "e.yaml", cfg))
	if a.Anthropic.Outcome != OutProxy || a.Check.Outcome != OutUnknown {
		t.Errorf("block-style groups: anth=%+v check=%+v", a.Anthropic, a.Check)
	}
}
