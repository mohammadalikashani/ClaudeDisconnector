package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ProxyApp is a detected Clash (mihomo), sing-box or Xray/V2Ray instance and how it routes Claude.
type ProxyApp struct {
	Kind       string    `json:"kind"`           // "clash", "sing-box", "xray" or "nekoray"
	App        string    `json:"app,omitempty"`  // client name when known (Hiddify, NekoBox, ...)
	Source     string    `json:"source"`         // config path and/or API address
	Live       bool      `json:"live"`           // API answered (app is running)
	Mode       string    `json:"mode,omitempty"` // rule / global / direct
	TUN        bool      `json:"tun,omitempty"`  // TUN inbound enabled
	MixedPort  int       `json:"mixedPort,omitempty"`
	Ports      []int     `json:"ports,omitempty"`      // local proxy ports (mixed/http/socks)
	Anthropic  HostRoute `json:"anthropic"`            // worst route of claude.ai / api.anthropic.com
	Check      HostRoute `json:"check"`                // worst route of the IP-check sites
	LiveDirect []string  `json:"liveDirect,omitempty"` // live Claude connections going DIRECT
	Note       string    `json:"note,omitempty"`
	// Remote: host of another device running the app (e.g. Clash Meta for Android used
	// as this computer's proxy). Its DIRECT exit is that device's connection.
	Remote string `json:"remote,omitempty"`
}

// SendsClaudeDirect: the app definitely routes Claude DIRECT (or a live connection shows it).
func (a ProxyApp) SendsClaudeDirect() bool {
	return (a.Anthropic.Outcome == OutDirect && !a.Anthropic.Uncertain) || len(a.LiveDirect) > 0
}

// CheckMisrouted: Claude goes through the proxy but the IP-check sites go DIRECT, so
// the exit-IP check can't see Claude's real exit (it would see the physical IP).
func (a ProxyApp) CheckMisrouted() bool {
	return a.Anthropic.Outcome == OutProxy && a.Check.Outcome == OutDirect
}

// ServesPort reports whether proxyURL (http://127.0.0.1:7890) is one of this app's ports.
func (a ProxyApp) ServesPort(proxyURL string) bool {
	host, port := ProxyHostPort(proxyURL)
	if port == "" {
		return false
	}
	if a.Remote != "" {
		if !strings.EqualFold(host, a.Remote) {
			return false
		}
	} else if !isLocalAddr(host) {
		return false // a local app doesn't serve another machine's proxy
	}
	for _, p := range a.Ports {
		if fmt.Sprint(p) == port {
			return true
		}
	}
	return false
}

func (a ProxyApp) Name() string {
	if a.App != "" {
		return a.App
	}
	switch a.Kind {
	case "clash":
		return "Clash"
	case "xray":
		return "Xray/V2Ray"
	}
	return "sing-box"
}

// Describe is one line for the UI.
func (a ProxyApp) Describe() string {
	r := a.Anthropic
	s := a.Name() + ": Claude -> "
	switch {
	case len(a.LiveDirect) > 0:
		s += "DIRECT (live connection to " + a.LiveDirect[0] + ")"
	case r.Outcome == OutUnknown:
		s += "uncertain (might be DIRECT)"
	default:
		s += strings.ToUpper(string(r.Outcome))
		if len(r.Chain) > 0 {
			s += " [" + strings.Join(r.Chain, " > ") + "]"
		}
	}
	if r.Rule != "" {
		s += " via rule " + r.Rule
	}
	return s
}

// ---------------------------------------------------------------- Clash API

type clashAPI struct {
	base, secret string // base: "http://127.0.0.1:9090" or "unix:/path" / "pipe:\\.\pipe\x" (also the display name)
	url          string // request URL prefix
	client       *http.Client
}

func newAPI(addr, secret string) *clashAPI {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	addr = strings.Replace(addr, "0.0.0.0", "127.0.0.1", 1)
	addr = strings.Replace(addr, "[::]", "127.0.0.1", 1)
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	base := strings.TrimRight(addr, "/")
	return &clashAPI{base: base, url: base, secret: secret,
		client: &http.Client{Timeout: 1500 * time.Millisecond, Transport: &http.Transport{Proxy: nil}}}
}

// newSocketAPI talks to a mihomo API on a unix socket or Windows named pipe
// (external-controller-unix / external-controller-pipe), as Mihomo Party and Clash
// Nyanpasu configure it.
func newSocketAPI(path, secret string) *clashAPI {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	kind := "unix:"
	if strings.HasPrefix(path, `\\.\pipe\`) || strings.HasPrefix(path, `//./pipe/`) {
		kind = "pipe:"
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, path) }}
	return &clashAPI{base: kind + path, url: "http://localhost", secret: secret,
		client: &http.Client{Timeout: 1500 * time.Millisecond, Transport: tr}}
}

// controllerAPIs lists the APIs a Clash config exposes: TCP, unix socket (relative
// paths are relative to the config's folder) and named pipe.
func controllerAPIs(f *clashFile, cfgPath string) []*clashAPI {
	var out []*clashAPI
	if a := newAPI(f.ExternalController, f.Secret); a != nil {
		out = append(out, a)
	}
	if u := strings.TrimSpace(f.ExternalControllerUnix); u != "" {
		if !filepath.IsAbs(u) && !strings.HasPrefix(u, "/") {
			u = filepath.Join(filepath.Dir(cfgPath), u)
		}
		out = append(out, newSocketAPI(u, f.Secret))
	}
	if p := newSocketAPI(f.ExternalControllerPipe, f.Secret); p != nil {
		out = append(out, p)
	}
	return out
}

func (c *clashAPI) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.url+path, nil)
	if err != nil {
		return err
	}
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return fmt.Errorf("API needs the secret")
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(v)
}

type apiProxy struct {
	Type string   `json:"type"`
	Now  string   `json:"now"`
	All  []string `json:"all"`
}

type apiConn struct {
	Metadata struct {
		Host          string `json:"host"`
		SniffHost     string `json:"sniffHost"`
		DestinationIP string `json:"destinationIP"`
	} `json:"metadata"`
	Chains []string `json:"chains"`
}

type apiState struct {
	version string
	mode    string
	tun     bool
	mixed   int
	proxies map[string]apiProxy
	rules   []Rule
	conns   []apiConn
	ports   []int
}

func nonZero(ps ...int) []int {
	var out []int
	for _, p := range ps {
		if p != 0 {
			out = append(out, p)
		}
	}
	return out
}

func (c *clashAPI) fetch(ctx context.Context) (*apiState, error) {
	st := &apiState{}
	var ver struct {
		Version string `json:"version"`
	}
	if err := c.get(ctx, "/version", &ver); err != nil {
		return nil, err
	}
	st.version = ver.Version
	var cfg struct {
		Mode      string `json:"mode"`
		MixedPort int    `json:"mixed-port"`
		Port      int    `json:"port"`
		SocksPort int    `json:"socks-port"`
		Tun       struct {
			Enable bool `json:"enable"`
		} `json:"tun"`
	}
	if c.get(ctx, "/configs", &cfg) == nil {
		st.mode, st.tun, st.mixed = strings.ToLower(cfg.Mode), cfg.Tun.Enable, cfg.MixedPort
		st.ports = nonZero(cfg.MixedPort, cfg.Port, cfg.SocksPort)
	}
	var px struct {
		Proxies map[string]apiProxy `json:"proxies"`
	}
	if c.get(ctx, "/proxies", &px) == nil {
		st.proxies = px.Proxies
	}
	var rules struct {
		Rules []struct {
			Type    string `json:"type"`
			Payload string `json:"payload"`
			Proxy   string `json:"proxy"`
		} `json:"rules"`
	}
	if c.get(ctx, "/rules", &rules) == nil {
		for _, r := range rules.Rules {
			st.rules = append(st.rules, ClashRule(r.Type, r.Payload, r.Proxy, nil))
		}
	}
	var conns struct {
		Connections []apiConn `json:"connections"`
	}
	if c.get(ctx, "/connections", &conns) == nil {
		st.conns = conns.Connections
	}
	return st, nil
}

// apiResolver follows selectors via the API's "now" selections.
func apiResolver(proxies map[string]apiProxy) Resolver {
	return func(name string) (Outcome, []string, bool) {
		var chain []string
		for i := 0; i < 16; i++ {
			chain = append(chain, name)
			switch strings.ToUpper(name) {
			case "DIRECT":
				return OutDirect, chain, false
			case "REJECT", "REJECT-DROP", "BLOCK":
				return OutReject, chain, false
			}
			p, ok := proxies[name]
			if !ok {
				return OutProxy, chain, true
			}
			switch strings.ToLower(p.Type) {
			case "direct":
				return OutDirect, chain, false
			case "reject", "rejectdrop", "block":
				return OutReject, chain, false
			case "selector", "urltest", "fallback", "loadbalance", "smart":
				if p.Now == "" {
					return OutUnknown, chain, true
				}
				name = p.Now
			case "pass":
				return OutUnknown, chain, true
			default:
				return OutProxy, chain, false
			}
		}
		return OutUnknown, chain, true
	}
}

func liveDirect(st *apiState) []string {
	var out []string
	for _, c := range st.conns {
		host := c.Metadata.Host
		if host == "" {
			host = c.Metadata.SniffHost
		}
		isClaude := c.Metadata.DestinationIP == AnthropicProbeIP
		for _, h := range []string{"anthropic.com", "claude.ai", "claude.com"} {
			if domainSuffix(strings.ToLower(host), h) {
				isClaude = true
			}
		}
		if isClaude && len(c.Chains) > 0 && (strings.EqualFold(c.Chains[0], "DIRECT") || c.Chains[0] == "bypass") {
			out = append(out, host)
		}
	}
	return out
}

// ---------------------------------------------------------------- Clash config file

type clashFile struct {
	ExternalController     string                `yaml:"external-controller"`
	ExternalControllerUnix string                `yaml:"external-controller-unix"`
	ExternalControllerPipe string                `yaml:"external-controller-pipe"`
	Secret                 string                `yaml:"secret"`
	Mode                   string                `yaml:"mode"`
	MixedPort              int                   `yaml:"mixed-port"`
	Port                   int                   `yaml:"port"`
	SocksPort              int                   `yaml:"socks-port"`
	Tun                    struct{ Enable bool } `yaml:"tun"`
	Rules                  []string              `yaml:"rules"`
	ProxyGroups            []struct {
		Name    string   `yaml:"name"`
		Type    string   `yaml:"type"`
		Proxies []string `yaml:"proxies"`
	} `yaml:"proxy-groups"`
	// Selections saved by the GUI (Clash for Windows' list.yml), used without an API.
	selected map[string]string
}

// fileResolver resolves without the API: a group's current selection is unknown, so a
// group that contains DIRECT (directly or via sub-groups) is uncertain.
func (f *clashFile) resolver() Resolver {
	groups := map[string][]string{}
	for _, g := range f.ProxyGroups {
		groups[g.Name] = g.Proxies
	}
	var hasDirect func(name string, depth int) bool
	hasDirect = func(name string, depth int) bool {
		if strings.EqualFold(name, "DIRECT") {
			return true
		}
		if depth > 8 {
			return false
		}
		for _, m := range groups[name] {
			if hasDirect(m, depth+1) {
				return true
			}
		}
		return false
	}
	return func(name string) (Outcome, []string, bool) {
		var chain []string
		for i := 0; i < 12; i++ {
			chain = append(chain, name)
			switch strings.ToUpper(name) {
			case "DIRECT":
				return OutDirect, chain, false
			case "REJECT", "REJECT-DROP":
				return OutReject, chain, false
			}
			members, ok := groups[name]
			if !ok {
				return OutProxy, chain, false
			}
			if now := f.selected[name]; now != "" {
				name = now // saved selection
				continue
			}
			if hasDirect(name, 0) {
				return OutUnknown, chain, true
			}
			if len(members) > 0 {
				return OutProxy, append(chain, members[0]+"?"), false
			}
			return OutProxy, chain, false
		}
		return OutUnknown, chain, true
	}
}

func parseClashFile(data []byte) (*clashFile, error) {
	var f clashFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

// ---------------------------------------------------------------- sing-box config file

type sbFile struct {
	Inbounds []struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		ListenPort int    `json:"listen_port"`
	} `json:"inbounds"`
	Outbounds []struct {
		Type       string   `json:"type"`
		Tag        string   `json:"tag"`
		Outbounds  []string `json:"outbounds"`
		Default    string   `json:"default"`
		Server     string   `json:"server"`
		ServerPort int      `json:"server_port"`
	} `json:"outbounds"`
	Route struct {
		Rules []map[string]any `json:"rules"`
		Final string           `json:"final"`
	} `json:"route"`
	Experimental struct {
		ClashAPI struct {
			ExternalController string `json:"external_controller"`
			Secret             string `json:"secret"`
			DefaultMode        string `json:"default_mode"`
		} `json:"clash_api"`
	} `json:"experimental"`
}

func strList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// sbRule converts one sing-box route rule.
func sbRule(r map[string]any) Rule {
	raw, _ := json.Marshal(r)
	rule := Rule{Raw: string(raw)}
	action, _ := r["action"].(string)
	switch action {
	case "", "route":
		rule.Target, _ = r["outbound"].(string)
	case "reject":
		rule.Reject = true
	default: // sniff, resolve, route-options, hijack-dns: not a routing decision for us
		return rule
	}
	if t, _ := r["type"].(string); t == "logical" {
		rule.match = func(target, string) tri { return maybe }
		return rule
	}
	invert, _ := r["invert"].(bool)
	rule.match = func(t target, mode string) tri {
		// destination address fields are ORed together
		dest := []tri{}
		for _, d := range strList(r["domain"]) {
			dest = append(dest, boolTri(t.host == strings.ToLower(d)))
		}
		for _, d := range strList(r["domain_suffix"]) {
			if strings.HasPrefix(d, ".") {
				dest = append(dest, boolTri(strings.HasSuffix(t.host, strings.ToLower(d))))
			} else {
				dest = append(dest, boolTri(domainSuffix(t.host, d)))
			}
		}
		for _, d := range strList(r["domain_keyword"]) {
			dest = append(dest, boolTri(strings.Contains(t.host, strings.ToLower(d))))
		}
		for _, d := range strList(r["domain_regex"]) {
			if re, err := regexp.Compile(d); err == nil {
				dest = append(dest, boolTri(re.MatchString(t.host)))
			} else {
				dest = append(dest, maybe)
			}
		}
		for _, d := range append(strList(r["geosite"]), strList(r["rule_set"])...) {
			dest = append(dest, nameHint(d, t))
		}
		for _, d := range strList(r["geoip"]) {
			dest = append(dest, geoipTri(d, t, false))
		}
		for _, d := range strList(r["ip_cidr"]) {
			dest = append(dest, ipTri(d, t, false))
		}
		if p, ok := r["ip_is_private"].(bool); ok && p {
			dest = append(dest, no)
		}
		res := yes
		if len(dest) > 0 {
			res = no
			for _, d := range dest {
				if d > res {
					res = d
				}
			}
		}
		and := func(x tri) {
			if x < res {
				res = x
			}
		}
		for k, v := range r {
			switch k {
			case "domain", "domain_suffix", "domain_keyword", "domain_regex", "geosite", "rule_set", "geoip",
				"ip_cidr", "ip_is_private", "outbound", "action", "invert", "type", "rule_set_ip_cidr_match_source":
			case "port":
				ok := no
				for _, p := range toInts(v) {
					if p == 443 {
						ok = yes
					}
				}
				and(ok)
			case "port_range":
				ok := no
				for _, s := range strList(v) {
					if portTri(strings.ReplaceAll(s, ":", "-"), 443) == yes {
						ok = yes
					}
				}
				and(ok)
			case "network":
				and(boolTri(contains(strList(v), "tcp")))
			case "protocol":
				and(boolTri(contains(strList(v), "tls") || contains(strList(v), "http")))
			case "clash_mode":
				if mode == "" {
					and(maybe)
				} else {
					and(boolTri(strings.EqualFold(fmt.Sprint(v), mode)))
				}
			case "ip_version":
				and(boolTri(fmt.Sprint(v) == "4"))
			case "process_name", "process_path", "process_path_regex":
				ok := no
				for _, s := range strList(v) {
					if processTri(s, t) == yes {
						ok = yes
					}
				}
				and(ok)
			default: // inbound, source_*, user, package_name, wifi_*, ...
				and(maybe)
			}
		}
		if invert && res != maybe {
			if res == yes {
				res = no
			} else {
				res = yes
			}
		}
		return res
	}
	return rule
}

func toInts(v any) []int {
	switch x := v.(type) {
	case float64:
		return []int{int(x)}
	case []any:
		var out []int
		for _, e := range x {
			if f, ok := e.(float64); ok {
				out = append(out, int(f))
			}
		}
		return out
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func (f *sbFile) resolver(api map[string]apiProxy) Resolver {
	type ob struct {
		typ     string
		members []string
		def     string
		local   string // "127.0.0.1:PORT" for a socks/http outbound to a local app
	}
	obs := map[string]ob{}
	for _, o := range f.Outbounds {
		local := ""
		if (o.Type == "socks" || o.Type == "http") && o.ServerPort != 0 && isLocalAddr(o.Server) {
			local = fmt.Sprintf("127.0.0.1:%d", o.ServerPort)
		}
		obs[o.Tag] = ob{o.Type, o.Outbounds, o.Default, local}
	}
	return func(name string) (Outcome, []string, bool) {
		var chain []string
		uncertain := false
		for i := 0; i < 16; i++ {
			chain = append(chain, name)
			o, ok := obs[name]
			if !ok {
				return OutUnknown, chain, true
			}
			switch o.typ {
			case "direct":
				return OutDirect, chain, uncertain
			case "block":
				return OutReject, chain, uncertain
			case "dns":
				return OutUnknown, chain, true
			case "selector", "urltest":
				if p, ok := api[name]; ok && p.Now != "" {
					name = p.Now
					continue
				}
				// No API: selection unknown. Default / first member, uncertain if DIRECT is an option.
				for _, m := range o.members {
					if mo, ok := obs[m]; ok && mo.typ == "direct" {
						return OutUnknown, chain, true // DIRECT is selectable and we can't see the choice
					}
				}
				next := o.def
				if next == "" && len(o.members) > 0 {
					next = o.members[0]
				}
				if next == "" {
					return OutUnknown, chain, true
				}
				name = next
			default:
				if o.local != "" {
					chain = append(chain, o.local)
				}
				return OutProxy, chain, uncertain
			}
		}
		return OutUnknown, chain, true
	}
}

// ---------------------------------------------------------------- detection

// ConfigCandidate is a config file worth looking at.
type ConfigCandidate struct {
	Kind string // "clash", "json" (sing-box or xray), "xray", "nekoray" (settings folder) or "api" (Clash API address)
	Path string
	App  string // client name for messages ("Hiddify"), optional
	// Hints from the client's own settings, used when the core config lacks them.
	Ports []int
	TUN   bool
	API   APIOverride // API given on the core's command line (overrides the config)
}

// APIOverride is a mihomo API set on the command line (-ext-ctl*, -secret).
type APIOverride struct {
	Addr, Unix, Pipe, Secret string
}

// CandidateConfigs lists well-known config locations under a user's home / AppData,
// plus extra directories (e.g. next to a running v2rayN.exe / mihomo binary).
// "json" files are sing-box or Xray/V2Ray, decided by their content.
func CandidateConfigs(home, appData string, extraDirs []string) []ConfigCandidate {
	var c []ConfigCandidate
	addC := func(p string) { c = append(c, ConfigCandidate{Kind: "clash", Path: p}) }
	addJ := func(p string) { c = append(c, ConfigCandidate{Kind: "json", Path: p}) }
	if home != "" {
		for _, d := range []string{".config/mihomo", ".config/clash.meta", ".config/clash"} {
			addC(filepath.Join(home, d, "config.yaml"))
		}
		addJ(filepath.Join(home, ".config/sing-box/config.json"))
		addJ(filepath.Join(home, ".config/xray/config.json"))
		addJ(filepath.Join(home, ".config/v2ray/config.json"))
		addJ(filepath.Join(home, ".config/qv2ray/vcore/config.gen.json"))
		addJ(filepath.Join(home, ".V2rayU/config.json"))
		mac := filepath.Join(home, "Library/Application Support")
		addJ(filepath.Join(mac, "app.hiddify.com/data/current-config.json"))
		for _, v := range []string{"v2rayN/binConfigs", "v2rayN/guiConfigs"} {
			addJ(filepath.Join(mac, v, "config.json"))
			addJ(filepath.Join(mac, v, "configPre.json"))
		}
		addC(filepath.Join(mac, "v2rayN/binConfigs/config.yaml"))
		addJ(filepath.Join(mac, "V2RayXS/config.json"))
		addJ(filepath.Join(mac, "qv2ray/vcore/config.gen.json"))
		addJ(filepath.Join(home, ".local/share/v2rayN/binConfigs/config.json"))
	}
	if appData != "" {
		addJ(filepath.Join(appData, "Hiddify", "data", "current-config.json"))
		addJ(filepath.Join(appData, "app.hiddify.com", "data", "current-config.json"))
		addJ(filepath.Join(appData, "qv2ray", "vcore", "config.gen.json"))
	}
	for _, d := range extraDirs {
		for _, p := range []string{d, filepath.Join(d, "binConfigs"), filepath.Join(d, "guiConfigs")} {
			addJ(filepath.Join(p, "config.json"))
			addJ(filepath.Join(p, "configPre.json"))
			addC(filepath.Join(p, "config.yaml"))
		}
	}
	for _, p := range []string{"/etc", "/usr/local/etc", "/opt/homebrew/etc"} {
		for _, app := range []string{"sing-box", "xray", "v2ray"} {
			addJ(filepath.Join(p, app, "config.json"))
		}
	}
	return c
}

// DefaultAPIPorts are probed even without a config (Clash default, Clash Verge Rev, Hiddify).
var DefaultAPIPorts = []string{"127.0.0.1:9090", "127.0.0.1:9097", "127.0.0.1:16756"}

// DetectProxyApps finds Clash/sing-box instances and evaluates how they route Claude.
// running reports whether a matching process exists (used for config files whose API
// isn't reachable, so stale configs of apps that aren't running are ignored).
func DetectProxyApps(ctx context.Context, candidates []ConfigCandidate, running func(kind string) bool) []ProxyApp {
	var apps []ProxyApp
	seenAPI := map[string]bool{}
	seenPath := map[string]bool{}

	for _, cand := range candidates {
		if cand.Kind == "api" {
			if app := probeAPI(ctx, cand.Path, cand.App, cand.API.Secret, seenAPI); app != nil {
				apps = append(apps, *app)
			}
			continue
		}
		path := filepath.Clean(cand.Path)
		if seenPath[strings.ToLower(path)] {
			continue
		}
		seenPath[strings.ToLower(path)] = true
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		kind := cand.Kind
		var data []byte
		if st.IsDir() && kind != "nekoray" && kind != "flclash" && kind != "cfw" {
			kind = "xray" // xray -confdir
		} else if !st.IsDir() {
			if data, err = os.ReadFile(path); err != nil || len(data) == 0 {
				continue
			}
			if kind != "clash" { // JSON: sing-box or xray/v2ray, decided by content
				kind = JSONKind(data)
			}
		}
		var app *ProxyApp
		switch kind {
		case "clash":
			f, err := parseClashFile(data)
			if err != nil || (len(f.Rules) == 0 && f.ExternalController == "" && f.ExternalControllerUnix == "" && f.ExternalControllerPipe == "") {
				continue
			}
			if o := cand.API; o != (APIOverride{}) {
				if o.Addr != "" {
					f.ExternalController = o.Addr
				}
				if o.Unix != "" {
					f.ExternalControllerUnix = o.Unix
				}
				if o.Pipe != "" {
					f.ExternalControllerPipe = o.Pipe
				}
				if o.Secret != "" {
					f.Secret = o.Secret
				}
			}
			app = evalClash(ctx, cand.Path, f, seenAPI)
		case "sing-box":
			var f sbFile
			if json.Unmarshal(StripJSONComments(data), &f) != nil || len(f.Outbounds) == 0 {
				continue
			}
			app = evalSingBox(ctx, cand.Path, &f, seenAPI)
		case "nekoray":
			app = evalNekoray(ctx, path, seenAPI)
		case "flclash":
			app = evalFlClash(ctx, path, seenAPI, nil)
		case "cfw":
			app = evalCFW(ctx, path, cand.API, seenAPI)
		case "xray":
			f, err := loadXray(path)
			if err != nil || len(f.Outbounds) == 0 {
				continue
			}
			app = evalXray(cand.Path, f)
		}
		if app == nil {
			continue
		}
		if cand.App != "" {
			app.App = cand.App
		} else if app.App == "" {
			app.App = AppLabel(path)
		}
		if len(app.Ports) == 0 {
			app.Ports = cand.Ports
		}
		app.TUN = app.TUN || cand.TUN
		if !app.Live && (running == nil || !running(app.Kind)) {
			continue // config of an app that isn't running
		}
		apps = append(apps, *app)
	}

	// Running instances we found no config for: ask the API directly.
	for _, addr := range DefaultAPIPorts {
		if app := probeAPI(ctx, addr, "", "", seenAPI); app != nil {
			apps = append(apps, *app)
		}
	}
	LinkLocalForwards(apps)
	return apps
}

// probeAPI asks a Clash-compatible API with no config file known (nil if it doesn't answer).
func probeAPI(ctx context.Context, addr, appName, secret string, seenAPI map[string]bool) *ProxyApp {
	api := newAPI(addr, secret)
	if api == nil || seenAPI[strings.TrimPrefix(api.base, "http://")] {
		return nil
	}
	st, err := api.fetch(ctx)
	if err != nil {
		return nil
	}
	seenAPI[strings.TrimPrefix(api.base, "http://")] = true
	kind := "clash"
	if strings.Contains(strings.ToLower(st.version), "sing-box") {
		kind = "sing-box"
	}
	app := ProxyApp{Kind: kind, App: appName, Source: "API " + api.base, Live: true, Mode: st.mode, TUN: st.tun, MixedPort: st.mixed, Ports: st.ports}
	if len(st.rules) == 0 && st.mode != "global" && st.mode != "direct" {
		app.Note = "rules not available from the API (no config file found)"
		app.Anthropic = HostRoute{Outcome: OutUnknown, Uncertain: true}
		app.Check = app.Anthropic
	} else {
		app.Anthropic, app.Check = evalHosts(st.rules, "MATCH-DEFAULT", st.mode, apiResolver(st.proxies))
	}
	app.LiveDirect = liveDirect(st)
	if host, _, err := net.SplitHostPort(strings.TrimPrefix(api.base, "http://")); err == nil && !isLocalAddr(host) {
		app.Remote = host
		app.TUN = false // its TUN is on the other device
	}
	return &app
}

func evalClash(ctx context.Context, path string, f *clashFile, seenAPI map[string]bool) *ProxyApp {
	app := &ProxyApp{Kind: "clash", Source: path, Mode: strings.ToLower(f.Mode), TUN: f.Tun.Enable, MixedPort: f.MixedPort,
		Ports: nonZero(f.MixedPort, f.Port, f.SocksPort)}
	if app.Mode == "" {
		app.Mode = "rule"
	}
	rules := []Rule{}
	for _, line := range f.Rules {
		if r, ok := ParseClashRuleLine(line); ok {
			rules = append(rules, r)
		}
	}
	resolve := f.resolver()
	var notes []string
	for _, api := range controllerAPIs(f, path) {
		if app.Live {
			break
		}
		st, err := api.fetch(ctx)
		if err == nil {
			app.Note = ""
			seenAPI[strings.TrimPrefix(api.base, "http://")] = true
			app.Live, app.Source = true, path+" + API "+api.base
			if st.mode != "" {
				app.Mode = st.mode
			}
			app.TUN = app.TUN || st.tun
			if st.mixed != 0 {
				app.MixedPort = st.mixed
			}
			if len(st.ports) > 0 {
				app.Ports = st.ports
			}
			if len(st.rules) > 0 {
				rules = st.rules // the rules actually loaded (incl. rule-providers order)
			}
			if st.proxies != nil {
				resolve = apiResolver(st.proxies)
			}
			app.LiveDirect = liveDirect(st)
		} else {
			notes = append(notes, "API "+api.base+": "+err.Error())
		}
	}
	if !app.Live && len(notes) > 0 {
		app.Note = strings.Join(notes, "; ")
	}
	if len(rules) == 0 && app.Mode != "direct" && app.Mode != "global" {
		// A config without rules is usually a GUI's partial settings file (the rules live
		// elsewhere), not what the core runs: don't conclude DIRECT from it.
		app.Anthropic = HostRoute{Outcome: OutUnknown, Uncertain: true, Rule: "no rules in this file"}
		app.Check = app.Anthropic
		return app
	}
	app.Anthropic, app.Check = evalHosts(rules, "", app.Mode, resolve)
	return app
}

func evalSingBox(ctx context.Context, path string, f *sbFile, seenAPI map[string]bool) *ProxyApp {
	app := &ProxyApp{Kind: "sing-box", Source: path, Mode: strings.ToLower(f.Experimental.ClashAPI.DefaultMode)}
	for _, in := range f.Inbounds {
		switch in.Type {
		case "tun":
			app.TUN = true
		case "mixed", "http", "socks":
			if in.ListenPort != 0 {
				app.Ports = append(app.Ports, in.ListenPort)
			}
		}
	}
	var api map[string]apiProxy
	if c := newAPI(f.Experimental.ClashAPI.ExternalController, f.Experimental.ClashAPI.Secret); c != nil {
		if st, err := c.fetch(ctx); err == nil {
			seenAPI[strings.TrimPrefix(c.base, "http://")] = true
			app.Live, app.Source = true, path+" + API "+c.base
			if st.mode != "" {
				app.Mode = st.mode
			}
			api = st.proxies
			app.LiveDirect = liveDirect(st)
		} else {
			app.Note = "API " + c.base + ": " + err.Error()
		}
	}
	var rules []Rule
	for _, r := range f.Route.Rules {
		rules = append(rules, sbRule(r))
	}
	final := f.Route.Final
	if final == "" && len(f.Outbounds) > 0 {
		final = f.Outbounds[0].Tag
	}
	resolve := f.resolver(api)
	// sing-box has no global/direct mode of its own; clash_mode rules handle it.
	app.Anthropic, app.Check = evalRules(rules, final, app.Mode, resolve)
	return app
}

// evalHosts handles Clash modes, then evaluates rules.
func evalHosts(rules []Rule, final, mode string, resolve Resolver) (HostRoute, HostRoute) {
	switch mode {
	case "direct":
		r := HostRoute{Outcome: OutDirect, Rule: "mode: direct", Chain: []string{"DIRECT"}}
		return r, r
	case "global":
		out, chain, unc := resolve("GLOBAL")
		r := HostRoute{Outcome: out, Rule: "mode: global", Chain: chain, Uncertain: unc}
		return r, r
	}
	if final == "" || final == "MATCH-DEFAULT" {
		final = "DIRECT" // Clash: no MATCH rule => DIRECT
	}
	return evalRules(rules, final, mode, resolve)
}

func evalRules(rules []Rule, final, mode string, resolve Resolver) (HostRoute, HostRoute) {
	worst := func(hosts []string) HostRoute {
		var w HostRoute
		for i, h := range hosts {
			r := Evaluate(rules, final, mode, h, resolve)
			if i == 0 || rank(r) > rank(w) {
				w = r
			}
		}
		return w
	}
	return worst(AnthropicHosts), worst(CheckHosts)
}

// rank orders routes by how worrying they are for leaks.
func rank(r HostRoute) int {
	switch {
	case r.Outcome == OutDirect && !r.Uncertain:
		return 4
	case r.Outcome == OutDirect || r.Outcome == OutUnknown:
		return 3
	case r.Outcome == OutProxy:
		return 1
	}
	return 0
}

// AppDecision summarises what the detected apps mean for Claude's routes.
type AppDecision struct {
	// TUNDirect: a TUN-mode app that carries Anthropic's traffic sends Claude DIRECT.
	TUNDirect *ProxyApp
	// ProxyDirect: the app behind the system proxy / PAC route sends Claude DIRECT.
	ProxyDirect *ProxyApp
	// Misrouted: Claude is proxied but the IP-check sites go DIRECT (checks can't see Claude's exit).
	Misrouted *ProxyApp
}

// DecideApps relates detected apps to the routes in use. anthropicInTunnel: Anthropic's
// OS route enters a tunnel interface; desktopProxy: the proxy Claude Desktop uses ("" = none).
func DecideApps(apps []ProxyApp, anthropicInTunnel bool, desktopProxy string) AppDecision {
	var d AppDecision
	for i := range apps {
		a := &apps[i]
		viaTUN := a.TUN && anthropicInTunnel
		viaProxy := desktopProxy != "" && a.ServesPort(desktopProxy)
		live := len(a.LiveDirect) > 0
		if a.SendsClaudeDirect() {
			if (viaTUN || live) && d.TUNDirect == nil {
				d.TUNDirect = a
			}
			if (viaProxy || live) && d.ProxyDirect == nil {
				d.ProxyDirect = a
			}
		}
		if a.CheckMisrouted() && (viaTUN || viaProxy) && d.Misrouted == nil {
			d.Misrouted = a
		}
	}
	return d
}
