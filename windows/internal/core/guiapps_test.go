package core

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mkfile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func detectAll(cands []ConfigCandidate) []ProxyApp {
	return DetectProxyApps(context.Background(), cands, func(string) bool { return true })
}

// NekoBox with the usual "bypass Iran" route profile: Claude goes via the proxy.
func TestNekoBoxRoutes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nekobox", "config")
	mkfile(t, filepath.Join(dir, "groups", "nekobox.json"), `{"inbound_socks_port": 2080, "active_routing": "Iran"}`)
	mkfile(t, filepath.Join(dir, "routes_box", "Iran"), `{
	  "block_domain": "geosite:category-ads-all\ndomain:appcenter.ms",
	  "direct_domain": "geosite:category-ir\ndomain:ir\n# comment",
	  "direct_ip": "geoip:ir\ngeoip:private",
	  "def_outbound": "proxy", "domain_strategy": "AsIs",
	  "custom": "{\"rules\": []}"}`)
	apps := detectAll(NekorayDirs("", []string{filepath.Dir(dir)}))
	if len(apps) != 1 {
		t.Fatalf("apps: %+v", apps)
	}
	a := apps[0]
	if a.Name() != "NekoBox" || a.Anthropic.Outcome != OutProxy || a.Check.Outcome != OutProxy || !a.servesPortNum(2080) {
		t.Errorf("nekobox iran: %+v", a)
	}
	t.Log(a.Describe())

	// Default outbound "bypass" (= DIRECT), only some sites proxied.
	mkfile(t, filepath.Join(dir, "routes_box", "Iran"), `{"proxy_domain": "geosite:google\ndomain:youtube.com", "def_outbound": "bypass"}`)
	a = detectAll(NekorayDirs("", []string{filepath.Dir(dir)}))[0]
	if !a.SendsClaudeDirect() || a.Anthropic.Rule != "final: bypass" {
		t.Errorf("nekobox bypass default: %+v", a.Anthropic)
	}

	// Custom sing-box rule sends Anthropic DIRECT even though the default is proxy.
	mkfile(t, filepath.Join(dir, "routes_box", "Iran"), `{"def_outbound": "proxy",
	  "custom": "{\"rules\": [{\"domain_suffix\": [\"anthropic.com\", \"claude.ai\"], \"outbound\": \"bypass\"}]}"}`)
	a = detectAll(NekorayDirs("", []string{filepath.Dir(dir)}))[0]
	if !a.SendsClaudeDirect() || a.Check.Outcome != OutProxy {
		t.Errorf("nekobox custom rule: %+v", a.Anthropic)
	}

	// Missing route profile -> uncertain, not a crash.
	os.Remove(filepath.Join(dir, "routes_box", "Iran"))
	a = detectAll(NekorayDirs("", []string{filepath.Dir(dir)}))[0]
	if a.Anthropic.Outcome != OutUnknown || !strings.Contains(a.Note, "Iran") {
		t.Errorf("missing profile: %+v", a)
	}
}

// NekoRay (Xray core): routes/ folder, Xray-style custom rules, IP rules with UseIP.
func TestNekoRayXrayCore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "config")
	mkfile(t, filepath.Join(dir, "groups", "nekoray.json"), `{"inbound_socks_port": 2081}`)
	mkfile(t, filepath.Join(dir, "routes", "Default"), `{"direct_ip": "160.79.104.0/23", "def_outbound": "proxy", "domain_strategy": "UseIP",
	  "custom": "{\"rules\": [{\"type\": \"field\", \"domain\": [\"geosite:google\"], \"outboundTag\": \"proxy\"}]}"}`)
	apps := detectAll([]ConfigCandidate{{Kind: "nekoray", Path: dir}})
	if len(apps) != 1 || apps[0].Name() != "NekoRay" || !apps[0].SendsClaudeDirect() || !apps[0].servesPortNum(2081) {
		t.Fatalf("nekoray: %+v", apps)
	}
}

// NekoBox TUN mode: a separate sing-box core runs the TUN and forwards to the GUI's port.
func TestNekoBoxTunLinked(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "config")
	mkfile(t, filepath.Join(dir, "groups", "nekobox.json"), `{}`)
	mkfile(t, filepath.Join(dir, "routes_box", "Default"), `{"def_outbound": "bypass"}`)
	vpn := filepath.Join(dir, "vpn", "sing-box-vpn.json")
	mkfile(t, vpn, `{"inbounds":[{"type":"tun","tag":"tun-in"}],
	  "outbounds":[{"type":"socks","tag":"nekoray-socks","server":"127.0.0.1","server_port":2080},{"type":"direct","tag":"direct"}],
	  "route":{"final":"nekoray-socks"}}`)
	args := []string{"nekobox_core", "run", "-c", vpn}
	cands := append(ConfigArgs(ProcKind(args[0]), args, nil), ConfigCandidate{Kind: "nekoray", Path: dir})
	apps := detectAll(cands)
	if len(apps) != 2 || !apps[0].TUN || !apps[0].SendsClaudeDirect() || !strings.Contains(apps[0].Anthropic.Rule, "NekoBox") {
		t.Fatalf("TUN not linked to NekoBox: %+v", apps)
	}
	if DecideApps(apps, true, "").TUNDirect == nil {
		t.Error("decide")
	}
	t.Log(apps[0].Describe())
}

// Hiddify: config + preferences found by searching its data folder; preferences point at a live API.
func TestHiddify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			w.Write([]byte(`{"version":"sing-box 1.10.1","premium":true}`))
		case "/configs":
			w.Write([]byte(`{"mode":"rule","mixed-port":12334}`))
		case "/proxies":
			w.Write([]byte(`{"proxies":{"select":{"type":"Selector","now":"direct"},"direct":{"type":"Direct"}}}`))
		case "/connections":
			w.Write([]byte(`{"connections":[{"metadata":{"host":"claude.ai"},"chains":["direct","select"]}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]

	root := t.TempDir()
	data := filepath.Join(root, "Hiddify", "hiddify", "data")
	mkfile(t, filepath.Join(data, "current-config.json"), `{
	  "outbounds":[{"type":"selector","tag":"select","outbounds":["auto","direct"]},{"type":"urltest","tag":"auto","outbounds":["vless-1"]},
	               {"type":"vless","tag":"vless-1"},{"type":"direct","tag":"direct"}],
	  "route":{"rules":[{"rule_set":["geosite-ir","geoip-ir"],"outbound":"direct"}],"final":"select"}}`)
	mkfile(t, filepath.Join(root, "Hiddify", "hiddify", "shared_preferences.json"),
		`{"flutter.clash-api-port": `+port+`, "flutter.mixed-port": 12334, "flutter.service-mode": "tun"}`)
	mkfile(t, filepath.Join(root, "Other", "current-config.json"), `{}`) // not a Hiddify folder

	info := FindHiddify([]string{root})
	if len(info.Configs) != 2 || info.MixedPort != 12334 || !info.TUN {
		t.Fatalf("FindHiddify: %+v", info)
	}
	apps := detectAll(info.Configs)
	var file, api *ProxyApp
	for i := range apps {
		if apps[i].Live {
			api = &apps[i]
		} else {
			file = &apps[i]
		}
	}
	if file == nil || file.Name() != "Hiddify" || !file.TUN || !file.servesPortNum(12334) || file.Anthropic.Outcome != OutUnknown {
		t.Errorf("hiddify file: %+v", file)
	}
	if api == nil || api.Name() != "Hiddify" || !api.SendsClaudeDirect() {
		t.Errorf("hiddify API (live connection DIRECT): %+v", api)
	}
}

func TestGUIProcKinds(t *testing.T) {
	for exe, k := range map[string]string{`C:\nekoray\nekobox.exe`: "nekoray", "nekoray": "nekoray", "Throne.exe": "nekoray",
		"nekobox_core.exe": "sing-box", "nekoray_core": "xray", "Hiddify.exe": "sing-box", "HiddifyCli": "sing-box",
		"FlClash.exe": "clash", "FlClashCore": "clash", "karing.exe": "sing-box", "karingService": "sing-box"} {
		if ProcKind(exe) != k {
			t.Errorf("ProcKind(%s)=%q want %q", exe, ProcKind(exe), k)
		}
	}
}

const flProfile = `
mixed-port: 7890
mode: global
external-controller: 127.0.0.1:1
proxies:
  - {name: de-1, type: vless, server: 1.2.3.4, port: 443}
proxy-groups:
  - {name: Proxy, type: select, proxies: [de-1]}
rules:
  - GEOSITE,category-ir,DIRECT
  - MATCH,Proxy
`

// FlClash: profile + FlClash's own settings (mode/ports/TUN/controller) + rule overrides.
func TestFlClash(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "com.follow", "clash") // Windows layout
	mkfile(t, filepath.Join(dir, "profiles", "1712.yaml"), flProfile)
	mkfile(t, filepath.Join(dir, "profiles", "999.yaml"), "rules:\n  - MATCH,DIRECT\n") // not the current profile
	mkfile(t, filepath.Join(dir, "config.json"), `{"currentProfileId": "1712",
	  "profiles": [{"id": "1712", "label": "sub"}],
	  "patchClashConfig": {"mixed-port": 7897, "mode": "rule", "tun": {"enable": true}, "external-controller": ""}}`)
	cands := FlClashCandidates([]string{root})
	apps := detectAll(cands)
	if len(apps) != 1 {
		t.Fatalf("apps: %+v (cands %+v)", apps, cands)
	}
	a := apps[0]
	if a.Name() != "FlClash" || a.Mode != "rule" || !a.TUN || !a.servesPortNum(7897) || a.Anthropic.Outcome != OutProxy || a.Note != "" {
		t.Errorf("flclash: %+v", a)
	}
	t.Log(a.Describe())

	// Profile override adds a rule sending Anthropic DIRECT.
	mkfile(t, filepath.Join(dir, "config.json"), `{"currentProfileId": "1712",
	  "profiles": [{"id": "1712", "overrideData": {"enable": true, "rule": {"type": "added", "addedRules": ["DOMAIN-SUFFIX,anthropic.com,DIRECT", "DOMAIN,claude.ai,DIRECT"]}}}],
	  "patchClashConfig": {"mode": "rule", "external-controller": ""}}`)
	a = detectAll(FlClashCandidates([]string{root}))[0]
	if !a.SendsClaudeDirect() || !strings.Contains(a.Anthropic.Rule, "DIRECT") {
		t.Errorf("flclash added rules: %+v", a.Anthropic)
	}

	// Older FlClash: settings in shared_preferences.json as JSON strings; mode direct.
	os.Remove(filepath.Join(dir, "config.json"))
	mkfile(t, filepath.Join(dir, "shared_preferences.json"), `{"flutter.config": "{\"currentProfileId\":\"1712\"}",
	  "flutter.clashConfig": "{\"mode\":\"direct\",\"mixed-port\":7890,\"external-controller\":\"\"}"}`)
	a = detectAll(FlClashCandidates([]string{root}))[0]
	if !a.SendsClaudeDirect() || a.Anthropic.Rule != "mode: direct" {
		t.Errorf("flclash prefs mode direct: %+v", a.Anthropic)
	}
}

// Karing: newest runnable sing-box config in its folder; subscription files ignored.
func TestKaring(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "karing", "karing")
	mkfile(t, filepath.Join(dir, "profiles", "sub1.json"), `{"outbounds":[{"type":"vless","tag":"a"}]}`) // outbound list only
	mkfile(t, filepath.Join(dir, "service_core_config.json"), `{
	  "inbounds":[{"type":"mixed","tag":"in","listen_port":3067},{"type":"tun","tag":"tun-in"}],
	  "outbounds":[{"type":"selector","tag":"select","outbounds":["a"]},{"type":"vless","tag":"a"},{"type":"direct","tag":"direct"}],
	  "route":{"rules":[{"rule_set":["geosite-ir"],"outbound":"direct"},{"domain_suffix":["anthropic.com","claude.ai"],"outbound":"direct"}],"final":"select"}}`)
	cands := KaringCandidates([]string{root})
	if len(cands) != 1 || !strings.HasSuffix(cands[0].Path, "service_core_config.json") {
		t.Fatalf("karing candidates: %+v", cands)
	}
	a := detectAll(cands)[0]
	if a.Name() != "Karing" || !a.TUN || !a.servesPortNum(3067) || !a.SendsClaudeDirect() || a.Check.Outcome != OutProxy {
		t.Errorf("karing: %+v", a)
	}
	t.Log(a.Describe())
}

// Surge / Shadowrocket-style FINAL with options; DOMAIN-SET and the SYSTEM rule set.
func TestSurgeStyleRules(t *testing.T) {
	r, ok := ParseClashRuleLine("FINAL,PROXY,dns-failed")
	if !ok || r.Target != "PROXY" || r.Raw != "MATCH,PROXY" {
		t.Errorf("FINAL options: %+v", r)
	}
	for _, line := range []string{"RULE-SET,SYSTEM,DIRECT", "DOMAIN-SET,https://x/iran-domains.txt,DIRECT"} {
		r, _ := ParseClashRuleLine(line)
		if m := r.match(targetFor("claude.ai"), ""); m != no {
			t.Errorf("%s should not match Claude: %v", line, m)
		}
	}
}

// Mihomo Party: runtime config in work/, API on a unix socket (relative path) with a secret.
func TestMihomoPartyUnixAPI(t *testing.T) {
	root, err := os.MkdirTemp("", "mp") // short path: unix socket paths are limited to ~100 chars
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	work := filepath.Join(root, "mihomo-party", "work")
	mkfile(t, filepath.Join(work, "config.yaml"), "mixed-port: 7890\nexternal-controller: ''\nexternal-controller-unix: mp.sock\nsecret: s3\n"+
		"proxy-groups:\n  - {name: Proxy, type: select, proxies: [de-1, DIRECT]}\nrules:\n  - MATCH,Proxy\n")
	mkfile(t, filepath.Join(root, "mihomo-party", "profiles", "abc.yaml"), "rules:\n  - MATCH,DIRECT\n") // not the runtime file
	ln, err := net.Listen("unix", filepath.Join(work, "mp.sock"))
	if err != nil {
		t.Skip("unix sockets unavailable:", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/version":
			w.Write([]byte(`{"meta":true,"version":"v1.19.2"}`))
		case "/configs":
			w.Write([]byte(`{"mode":"rule","mixed-port":7890,"tun":{"enable":true}}`))
		case "/proxies":
			w.Write([]byte(`{"proxies":{"Proxy":{"type":"Selector","now":"de-1"},"de-1":{"type":"Vless"},"DIRECT":{"type":"Direct"}}}`))
		case "/rules":
			w.Write([]byte(`{"rules":[{"type":"Match","payload":"","proxy":"Proxy"}]}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	cands := MihomoGUICandidates([]string{root})
	if len(cands) != 1 || !strings.HasSuffix(cands[0].Path, filepath.Join("work", "config.yaml")) {
		t.Fatalf("candidates: %+v", cands)
	}
	apps := detectAll(cands)
	if len(apps) != 1 || apps[0].Name() != "Mihomo Party" || !apps[0].Live || !apps[0].TUN ||
		apps[0].Anthropic.Outcome != OutProxy || strings.Join(apps[0].Anthropic.Chain, ">") != "Proxy>de-1" {
		t.Fatalf("mihomo party: %+v", apps)
	}
	if !strings.Contains(apps[0].Source, "unix:") {
		t.Errorf("source: %s", apps[0].Source)
	}
	t.Log(apps[0].Describe(), " | ", apps[0].Source)
}

// Clash Nyanpasu: clash-config.yaml; socket not running -> file rules, uncertain group.
func TestNyanpasu(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "Clash Nyanpasu", "config")
	mkfile(t, filepath.Join(dir, "clash-config.yaml"), "mixed-port: 7899\nexternal-controller-unix: /nonexistent/n.sock\n"+
		"proxy-groups:\n  - {name: Proxy, type: select, proxies: [de-1]}\nrules:\n  - GEOIP,IR,DIRECT\n  - DOMAIN-SUFFIX,anthropic.com,DIRECT\n  - MATCH,Proxy\n")
	apps := detectAll(MihomoGUICandidates([]string{root}))
	if len(apps) != 1 || apps[0].Name() != "Clash Nyanpasu" || !apps[0].SendsClaudeDirect() || !strings.Contains(apps[0].Note, "unix:") {
		t.Fatalf("nyanpasu: %+v", apps)
	}
	if AppLabel(`C:\Users\x\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev\clash-verge.yaml`) != "Clash Verge" {
		t.Error("label")
	}
}

// Clash Verge Rev: clash-verge.yaml is the runtime file (config.yaml is a partial
// override); the API comes from the core's command line.
func TestClashVergeRev(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer vsecret" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/version":
			w.Write([]byte(`{"meta":true,"version":"v1.19.3"}`))
		case "/proxies":
			w.Write([]byte(`{"proxies":{"Proxy":{"type":"Selector","now":"DIRECT"},"DIRECT":{"type":"Direct"}}}`))
		case "/rules":
			w.Write([]byte(`{"rules":[{"type":"Match","payload":"","proxy":"Proxy"}]}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	root := t.TempDir()
	dir := filepath.Join(root, "io.github.clash-verge-rev.clash-verge-rev")
	mkfile(t, filepath.Join(dir, "config.yaml"), "mixed-port: 7897\nexternal-controller: 127.0.0.1:1\n") // partial: no rules
	mkfile(t, filepath.Join(dir, "clash-verge.yaml"), "mixed-port: 7897\ntun:\n  enable: true\n"+
		"proxy-groups:\n  - {name: Proxy, type: select, proxies: [de-1, DIRECT]}\nrules:\n  - GEOIP,IR,DIRECT\n  - MATCH,Proxy\n")
	cands := MihomoGUICandidates([]string{root})
	if len(cands) != 1 || filepath.Base(cands[0].Path) != "clash-verge.yaml" || cands[0].App != "Clash Verge" {
		t.Fatalf("verge candidates: %+v", cands)
	}
	a := detectAll(cands)[0]
	if !a.TUN || a.Anthropic.Outcome != OutUnknown || a.Live {
		t.Errorf("verge without API: %+v", a)
	}

	// The running core: verge-mihomo -d <dir> -f <dir>/clash-verge.yaml -ext-ctl <addr> -secret vsecret
	args := []string{"verge-mihomo", "-d", dir, "-f", filepath.Join(dir, "clash-verge.yaml"),
		"-ext-ctl", strings.TrimPrefix(srv.URL, "http://"), "-secret", "vsecret"}
	apps := detectAll(ConfigArgs(ProcKind(args[0]), args, nil))
	if len(apps) != 1 || apps[0].Name() != "Clash Verge" || !apps[0].Live || !apps[0].SendsClaudeDirect() {
		t.Fatalf("verge with CLI API: %+v", apps)
	}
	t.Log(apps[0].Describe())
}

// Clash for Windows: list.yml picks the profile and stores group selections; config.yaml
// holds the general settings; the core's command-line API is used when present.
func TestClashForWindows(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".config", "clash")
	mkfile(t, filepath.Join(dir, "config.yaml"), "mixed-port: 7890\nmode: rule\nexternal-controller: 127.0.0.1:1\nsecret: ''\n") // partial: no rules
	mkfile(t, filepath.Join(dir, "profiles", "1690000000001.yml"), "rules:\n  - MATCH,DIRECT\n")                                 // not selected
	mkfile(t, filepath.Join(dir, "profiles", "1690000000002.yml"), "mixed-port: 1234\n"+
		"proxy-groups:\n  - {name: Proxy, type: select, proxies: [de-1, DIRECT]}\nrules:\n  - GEOIP,IR,DIRECT\n  - MATCH,Proxy\n")
	list := func(now string) string {
		return "files:\n  - time: 1690000000001.yml\n    name: old\n  - time: 1690000000002.yml\n    name: sub\n    selected:\n      - name: Proxy\n        now: " + now + "\nindex: 1\n"
	}
	mkfile(t, filepath.Join(dir, "profiles", "list.yml"), list("de-1"))

	cands := AllCandidates(home, "", "", ProcInfo{})
	var cfw []ConfigCandidate
	for _, c := range cands {
		if strings.EqualFold(filepath.Dir(c.Path), dir) || c.Path == dir {
			cfw = append(cfw, c)
		}
	}
	if len(cfw) != 1 || cfw[0].Kind != "cfw" {
		t.Fatalf("CFW folder should give one candidate (generic config.yaml suppressed): %+v", cfw)
	}
	a := detectAll(cfw)[0]
	if a.Name() != "Clash for Windows" || !a.servesPortNum(7890) || a.Anthropic.Outcome != OutProxy ||
		strings.Join(a.Anthropic.Chain, ">") != "Proxy>de-1" {
		t.Errorf("cfw saved selection de-1: %+v", a)
	}
	mkfile(t, filepath.Join(dir, "profiles", "list.yml"), list("DIRECT"))
	a = detectAll(cfw)[0]
	if !a.SendsClaudeDirect() {
		t.Errorf("cfw saved selection DIRECT: %+v", a.Anthropic)
	}

	// The running core with a random controller + secret on its command line.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer rnd" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/version":
			w.Write([]byte(`{"version":"2023.08.17-premium"}`))
		case "/proxies":
			w.Write([]byte(`{"proxies":{"Proxy":{"type":"Selector","now":"de-1"},"de-1":{"type":"Vmess"}}}`))
		case "/rules":
			w.Write([]byte(`{"rules":[{"type":"Match","payload":"","proxy":"Proxy"}]}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	args := []string{`clash-win64.exe`, "-d", dir, "-ext-ctl", strings.TrimPrefix(srv.URL, "http://"), "-secret", "rnd"}
	procs := ProcInfo{Configs: ConfigArgs(ProcKind(args[0]), args, nil)}
	cands = AllCandidates(home, "", "", procs)
	if cands[0].Kind != "cfw" || cands[0].API.Secret != "rnd" {
		t.Fatalf("command-line API not handed to CFW: %+v", cands[0])
	}
	a = detectAll(cands[:1])[0]
	if !a.Live || a.Anthropic.Outcome != OutProxy {
		t.Errorf("cfw live: %+v", a)
	}

	// A rule-less config on its own is uncertain, not DIRECT.
	p := detectAll([]ConfigCandidate{{Kind: "clash", Path: filepath.Join(dir, "config.yaml")}})
	if len(p) != 1 || p[0].SendsClaudeDirect() || p[0].Anthropic.Outcome != OutUnknown {
		t.Errorf("rule-less config: %+v", p)
	}
}
