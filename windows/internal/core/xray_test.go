package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v2rayN-style "bypass Iran": Iranian sites/IPs DIRECT, everything else via the proxy.
const xrayBypassIran = `{
  // comments are allowed in xray configs
  "inbounds": [
    {"tag": "socks", "port": 10808, "listen": "127.0.0.1", "protocol": "socks"},
    {"tag": "http", "port": "10809", "listen": "127.0.0.1", "protocol": "http"},
    {"tag": "api", "port": 10813, "listen": "127.0.0.1", "protocol": "dokodemo-door"}
  ],
  "outbounds": [
    {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": "1.2.3.4", "port": 443}]}},
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
      {"type": "field", "outboundTag": "block", "domain": ["geosite:category-ads-all"]},
      {"type": "field", "outboundTag": "direct", "domain": ["domain:ir", "geosite:category-ir"]},
      {"type": "field", "outboundTag": "direct", "ip": ["geoip:private", "geoip:ir"]},
      {"type": "field", "port": "0-65535", "outboundTag": "proxy"}
    ]
  }
}`

// Only listed sites via the proxy; the default (first) outbound is DIRECT.
const xrayDirectFirst = `{
  "inbounds": [{"tag": "socks", "port": 10808, "protocol": "socks"}],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom", "settings": {"fragment": {"packets": "tlshello"}}},
    {"tag": "proxy", "protocol": "trojan"}
  ],
  "routing": {"rules": [{"type": "field", "domain": ["geosite:google", "youtube.com"], "outboundTag": "proxy"}]}
}`

// Claude proxied, IP-check sites direct.
const xrayClaudeOnly = `{
  "inbounds": [{"tag": "socks", "port": 10808, "protocol": "socks"}],
  "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "proxy", "protocol": "vmess"}],
  "routing": {"rules": [
    {"type": "field", "domain": ["domain:anthropic.com", "full:claude.ai"], "outboundTag": "proxy"}
  ]}
}`

// Balancer that may pick DIRECT.
const xrayBalancer = `{
  "inbounds": [{"tag": "socks", "port": 10808, "protocol": "socks"}],
  "outbounds": [{"tag": "proxy-a", "protocol": "vless"}, {"tag": "proxy-direct", "protocol": "freedom"}],
  "routing": {"balancers": [{"tag": "b", "selector": ["proxy-"]}],
    "rules": [{"type": "field", "network": "tcp,udp", "balancerTag": "b"}]}
}`

// v2rayN TUN mode: sing-box TUN hands everything to xray's SOCKS port.
const sbTunToXray = `{
  "inbounds": [{"type": "tun", "tag": "tun-in"}],
  "outbounds": [{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 10808}, {"type": "direct", "tag": "direct"}],
  "route": {"rules": [{"ip_is_private": true, "outbound": "direct"}], "final": "proxy"}
}`

func TestXrayConfigs(t *testing.T) {
	cases := []struct {
		name, cfg      string
		claude, checks Outcome
		direct         bool
	}{
		{"bypass-iran", xrayBypassIran, OutProxy, OutProxy, false},
		{"direct-first", xrayDirectFirst, OutDirect, OutDirect, true},
		{"claude-only", xrayClaudeOnly, OutProxy, OutDirect, false},
		{"balancer", xrayBalancer, OutUnknown, OutUnknown, false},
	}
	for _, c := range cases {
		p := writeTemp(t, "config.json", c.cfg)
		if k := JSONKind([]byte(c.cfg)); k != "xray" {
			t.Fatalf("%s: JSONKind=%q", c.name, k)
		}
		a := detect(t, "json", p)
		if a.Kind != "xray" || a.Anthropic.Outcome != c.claude || a.Check.Outcome != c.checks || a.SendsClaudeDirect() != c.direct {
			t.Errorf("%s: got claude=%+v check=%+v", c.name, a.Anthropic, a.Check)
		}
		if !a.servesPortNum(10808) {
			t.Errorf("%s: ports %v", c.name, a.Ports)
		}
		t.Logf("%s: %s", c.name, a.Describe())
	}
}

func TestXrayIPStrategies(t *testing.T) {
	// geoip:us -> direct only matches when xray resolves the domain.
	mk := func(strategy string) string {
		return `{"inbounds":[{"tag":"s","port":1080,"protocol":"socks"}],
		"outbounds":[{"tag":"proxy","protocol":"vless"},{"tag":"direct","protocol":"freedom"}],
		"routing":{"domainStrategy":"` + strategy + `","rules":[{"ip":["160.79.104.0/23"],"outboundTag":"direct"}]}}`
	}
	for strategy, want := range map[string]Outcome{"AsIs": OutProxy, "IPIfNonMatch": OutDirect, "IPOnDemand": OutDirect} {
		a := detect(t, "json", writeTemp(t, "c.json", mk(strategy)))
		if a.Anthropic.Outcome != want {
			t.Errorf("%s: got %+v", strategy, a.Anthropic)
		}
	}
	// geoip:!ir -> proxy matches Anthropic (US) when resolved.
	neg := `{"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"proxy","protocol":"vless"}],
	"routing":{"domainStrategy":"IPOnDemand","rules":[{"ip":["geoip:!ir"],"outboundTag":"proxy"}]}}`
	if a := detect(t, "json", writeTemp(t, "n.json", neg)); a.Anthropic.Outcome != OutProxy {
		t.Errorf("geoip:!ir: %+v", a.Anthropic)
	}
}

func TestLinkTunToXray(t *testing.T) {
	dir := t.TempDir()
	sb := filepath.Join(dir, "configPre.json")
	xr := filepath.Join(dir, "config.json")
	os.WriteFile(sb, []byte(sbTunToXray), 0o644)
	os.WriteFile(xr, []byte(xrayDirectFirst), 0o644)
	apps := DetectProxyApps(nil, []ConfigCandidate{{"json", sb}, {"json", xr}}, func(string) bool { return true })
	if len(apps) != 2 {
		t.Fatalf("apps: %+v", apps)
	}
	tun := apps[0]
	if tun.Kind != "sing-box" || !tun.SendsClaudeDirect() || !strings.Contains(tun.Anthropic.Rule, "Xray/V2Ray") {
		t.Fatalf("TUN app not linked to xray: %+v", tun.Anthropic)
	}
	if d := DecideApps(apps, true, ""); d.TUNDirect == nil {
		t.Fatal("TUN -> xray DIRECT not detected")
	}
	t.Log(tun.Describe())
}

func TestXrayConfdirAndArgs(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "01_in.json"), []byte(`{"inbounds":[{"tag":"s","port":2080,"protocol":"socks"}]}`), 0o644)
	os.WriteFile(filepath.Join(dir, "02_out.json"), []byte(`{"outbounds":[{"tag":"direct","protocol":"freedom"}]}`), 0o644)
	a := detect(t, "xray", dir)
	if !a.SendsClaudeDirect() || !a.servesPortNum(2080) {
		t.Errorf("confdir: %+v", a)
	}

	got := ConfigArgs("xray", []string{"xray.exe", "run", "-c", "config.json", "-confdir=/etc/x"}, []string{"/a", "/b"})
	want := []string{"/a/config.json", "/b/config.json", "/etc/x"}
	if len(got) != 3 {
		t.Fatalf("ConfigArgs: %+v", got)
	}
	for i, w := range want {
		if filepath.ToSlash(got[i].Path) != w {
			t.Errorf("ConfigArgs[%d] = %+v want %s", i, got[i], w)
		}
	}
	if ConfigArgs("xray", []string{"xray", "run", "-c", "stdin:"}, nil) != nil {
		t.Error("stdin config should be skipped")
	}
	if c := ConfigArgs("clash", []string{"mihomo", "-f", "/x/c.yaml", "-d", "/y"}, nil); len(c) != 2 || c[0].Kind != "clash" || c[1].Path != "/y/config.yaml" {
		t.Errorf("clash args: %+v", c)
	}
	for exe, k := range map[string]string{`C:\v2rayN\bin\xray\xray.exe`: "xray", "v2ray": "xray", "mihomo-darwin-arm64": "clash", "sing-box": "sing-box", "v2rayN.exe": ""} {
		if ProcKind(exe) != k {
			t.Errorf("ProcKind(%s)=%q want %q", exe, ProcKind(exe), k)
		}
	}
}

// V2Ray v5 ("jsonv5") configs.
const v5BypassIran = `{
  "router": {
    "domainStrategy": "IpIfNonMatch",
    "rule": [
      {"tag": "direct", "geoDomain": [{"code": "category-ir"}], "domain": [{"type": "RootDomain", "value": "ir"}]},
      {"tag": "direct", "geoip": [{"code": "private"}, {"code": "ir"}]},
      {"tag": "proxy", "portList": "0-65535"}
    ]
  },
  "inbounds": [{"protocol": "socks", "port": 10808, "listen": "127.0.0.1", "tag": "socks"}],
  "outbounds": [{"protocol": "vmess", "tag": "proxy", "settings": {"address": "1.2.3.4", "port": 443}},
                {"protocol": "freedom", "tag": "direct"}]
}`

const v5DirectDefault = `{
  "router": {"domain_strategy": "AsIs", "rule": [
    {"tag": "proxy", "domain": [{"type": "Full", "value": "www.google.com"}, {"type": "Regex", "value": "^.*youtube\\.com$"}]}
  ]},
  "inbounds": [{"protocol": "http", "port": "10809", "tag": "http"}],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "trojan", "tag": "proxy"}]
}`

const v5ClaudeDirect = `{
  "router": {"domainStrategy": 3, "rule": [
    {"tag": "direct", "geoip": [{"cidr": [{"ipAddr": "160.79.104.0", "prefix": 23}]}]},
    {"tag": "direct", "geoip": [{"code": "ir", "inverseMatch": true}], "networks": "udp"}
  ]},
  "inbounds": [{"protocol": "socks", "port": 1080}],
  "outbounds": [{"protocol": "shadowsocks", "tag": "proxy"}, {"protocol": "freedom", "tag": "direct"}]
}`

const v5Balancer = `{
  "router": {"rule": [{"balancingTag": "b", "networks": "tcp,udp"}],
             "balancingRule": [{"tag": "b", "outboundSelector": ["node-"]}]},
  "inbounds": [{"protocol": "socks", "port": 1080}],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "vless", "tag": "node-a"}, {"protocol": "vless", "tag": "node-b"}]
}`

func TestV2RayV5(t *testing.T) {
	cases := []struct {
		name, cfg      string
		claude, checks Outcome
	}{
		{"v5-bypass-iran", v5BypassIran, OutProxy, OutProxy},
		{"v5-direct-default", v5DirectDefault, OutDirect, OutDirect},
		{"v5-claude-cidr-direct", v5ClaudeDirect, OutDirect, OutUnknown},
		{"v5-balancer", v5Balancer, OutProxy, OutProxy},
	}
	for _, c := range cases {
		a := detect(t, "json", writeTemp(t, "config.json", c.cfg))
		if a.Kind != "xray" || a.Anthropic.Outcome != c.claude || a.Check.Outcome != c.checks {
			t.Errorf("%s: claude=%+v check=%+v note=%s", c.name, a.Anthropic, a.Check, a.Note)
		}
		if len(a.Ports) != 1 {
			t.Errorf("%s: ports %v", c.name, a.Ports)
		}
		t.Logf("%s: %s", c.name, a.Describe())
	}
	r := V5Rule(map[string]any{"tag": "x", "geo_domain": []any{map[string]any{"country_code": "CN"}},
		"geoip": []any{map[string]any{"cidr": []any{map[string]any{"ip": "oE9oAA==", "prefix": 23.0}}}}})
	if d := strList(r["domain"]); len(d) != 1 || d[0] != "geosite:cn" {
		t.Errorf("snake_case geo_domain: %+v", r)
	}
	if ip := strList(r["ip"]); len(ip) != 1 || ip[0] != "160.79.104.0/23" {
		t.Errorf("base64 cidr: %+v", r)
	}
}
