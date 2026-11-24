package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// GUI clients whose core config isn't simply named on a command line:
//
//   - Hiddify: a sing-box client. Its generated core config ("current-config.json")
//     and its Flutter preferences (Clash API / mixed port, service mode) live in the
//     app's data folder, whose name differs per OS and version - so it's searched for.
//   - NekoRay / NekoBox / Throne: hand the core its config over gRPC (never written to
//     disk), so the routing is rebuilt from the app's own settings: groups/nekobox.json
//     and the active route profile in routes_box/ (sing-box core) or routes/ (Xray core).

// ---------------------------------------------------------------- Hiddify

// HiddifyInfo is what was found in Hiddify's data folders.
type HiddifyInfo struct {
	Configs   []ConfigCandidate // current-config.json files (sing-box) + API addresses ("api")
	MixedPort int
	TUN       bool
}

// FindHiddify searches roots (AppData\Roaming, AppData\Local, ~/Library/Application
// Support, ~/Library/Group Containers, ~/.local/share ...) for Hiddify folders.
func FindHiddify(roots []string) HiddifyInfo {
	var info HiddifyInfo
	seen := map[string]bool{}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || !strings.Contains(strings.ToLower(e.Name()), "hiddify") {
				continue
			}
			walkLimited(filepath.Join(root, e.Name()), 7, func(path string) {
				switch strings.ToLower(filepath.Base(path)) {
				case "current-config.json":
					if !seen[path] {
						seen[path] = true
						info.Configs = append(info.Configs, ConfigCandidate{Kind: "json", Path: path, App: "Hiddify"})
					}
				case "shared_preferences.json":
					if data, err := os.ReadFile(path); err == nil {
						var prefs map[string]any
						if json.Unmarshal(data, &prefs) == nil {
							info.applyPrefs(prefs)
						}
					}
				}
			})
		}
	}
	info.finish()
	return info
}

// finish copies the port / TUN hints from the preferences onto the found configs.
func (h *HiddifyInfo) finish() {
	for i := range h.Configs {
		if h.MixedPort > 0 {
			h.Configs[i].Ports = []int{h.MixedPort}
		}
		h.Configs[i].TUN = h.TUN
	}
}

// ApplyHiddifyPrefs reads Hiddify's Flutter preferences ("flutter."-prefixed keys).
func (h *HiddifyInfo) applyPrefs(prefs map[string]any) {
	get := func(k string) any {
		if v, ok := prefs["flutter."+k]; ok {
			return v
		}
		return prefs[k]
	}
	if p := anyPort(get("clash-api-port")); p > 0 {
		h.Configs = append(h.Configs, ConfigCandidate{Kind: "api", Path: fmt.Sprintf("127.0.0.1:%d", p), App: "Hiddify"})
	}
	if p := anyPort(get("mixed-port")); p > 0 {
		h.MixedPort = p
	}
	if m := strings.ToLower(anyString(get("service-mode"))); m == "tun" || m == "vpn" {
		h.TUN = true
	}
}

// ApplyHiddifyPrefs is used by platform code that reads preferences elsewhere (plist).
func (h *HiddifyInfo) ApplyHiddifyPrefs(prefs map[string]any) { h.applyPrefs(prefs); h.finish() }

// walkLimited calls fn for every file under dir, at most depth levels deep (bounded).
func walkLimited(dir string, depth int, fn func(string)) {
	count := 0
	var walk func(string, int)
	walk = func(d string, left int) {
		entries, err := os.ReadDir(d)
		if err != nil {
			return
		}
		for _, e := range entries {
			if count++; count > 20000 {
				return
			}
			p := filepath.Join(d, e.Name())
			if e.IsDir() {
				if left > 0 && e.Type()&os.ModeSymlink == 0 {
					walk(p, left-1)
				}
			} else {
				fn(p)
			}
		}
	}
	walk(dir, depth)
}

// ---------------------------------------------------------------- NekoRay / NekoBox / Throne

// NekorayDirs lists config folders: "<exe dir>\config" for portable installs (Windows)
// plus the usual per-user locations.
func NekorayDirs(home string, exeDirs []string) []ConfigCandidate {
	var out []ConfigCandidate
	add := func(p string) { out = append(out, ConfigCandidate{Kind: "nekoray", Path: p}) }
	for _, d := range exeDirs {
		add(filepath.Join(d, "config"))
	}
	if home != "" {
		for _, n := range []string{"nekoray", "nekobox", "Throne", "throne"} {
			add(filepath.Join(home, ".config", n, "config"))
			add(filepath.Join(home, "Library/Preferences", n, "config"))
			add(filepath.Join(home, "Library/Application Support", n, "config"))
		}
	}
	return out
}

type nekoSettings struct {
	SocksPort   int    `json:"inbound_socks_port"`
	Address     string `json:"inbound_address"`
	Routing     string `json:"active_routing"`
	ClashAPI    int    `json:"core_box_clash_api"`
	ClashSecret string `json:"core_box_clash_api_secret"`
}

type nekoRoute struct {
	BlockDomain    string `json:"block_domain"`
	BlockIP        string `json:"block_ip"`
	ProxyDomain    string `json:"proxy_domain"`
	ProxyIP        string `json:"proxy_ip"`
	DirectDomain   string `json:"direct_domain"`
	DirectIP       string `json:"direct_ip"`
	DefOutbound    string `json:"def_outbound"`
	DomainStrategy string `json:"domain_strategy"`
	Custom         string `json:"custom"`
}

func nekoLines(s string) []any {
	var out []any
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "//") {
			out = append(out, l)
		}
	}
	return out
}

// nekoOutbounds: NekoRay's fixed outbound tags. "bypass" is its name for DIRECT.
var nekoOutbounds = []xrayOutbound{
	{Tag: "proxy", Protocol: "vless"}, {Tag: "bypass", Protocol: "freedom"}, {Tag: "direct", Protocol: "freedom"},
	{Tag: "block", Protocol: "blackhole"}, {Tag: "dns-out", Protocol: "dns"},
}

// evalNekoray rebuilds NekoRay's routing from its settings folder.
func evalNekoray(ctx context.Context, dir string, seenAPI map[string]bool) *ProxyApp {
	var settingsPath string
	box := false
	for _, n := range []string{"nekobox.json", "nekoray.json", "throne.json"} {
		p := filepath.Join(dir, "groups", n)
		if _, err := os.Stat(p); err == nil {
			settingsPath, box = p, n != "nekoray.json"
			break
		}
	}
	if settingsPath == "" {
		return nil
	}
	var st nekoSettings
	if data, err := os.ReadFile(settingsPath); err == nil {
		_ = json.Unmarshal(StripJSONComments(data), &st)
	}
	name := "NekoBox"
	switch {
	case strings.Contains(strings.ToLower(settingsPath), "throne"):
		name = "Throne"
	case !box:
		name = "NekoRay"
	}
	if st.SocksPort == 0 {
		st.SocksPort = 2080
	}
	if st.Routing == "" {
		st.Routing = "Default"
	}
	app := &ProxyApp{Kind: "nekoray", App: name, Source: settingsPath, Ports: []int{st.SocksPort}}

	var routePath string
	for _, sub := range []string{"routes_box", "routes"} {
		p := filepath.Join(dir, sub, st.Routing)
		if _, err := os.Stat(p); err == nil {
			routePath = p
			break
		}
	}
	var rt nekoRoute
	if routePath != "" {
		if data, err := os.ReadFile(routePath); err == nil {
			if json.Unmarshal(StripJSONComments(data), &rt) != nil {
				routePath = ""
			}
		}
	}
	if routePath == "" {
		app.Note = "route profile " + st.Routing + " not found"
		app.Anthropic = HostRoute{Outcome: OutUnknown, Uncertain: true}
		app.Check = app.Anthropic
		return app
	}
	app.Source = settingsPath + " + " + routePath

	resolveIP := !strings.EqualFold(rt.DomainStrategy, "AsIs") && rt.DomainStrategy != ""
	var rules []Rule
	// Custom rules first (sing-box route rules for NekoBox, Xray rules for NekoRay).
	if strings.TrimSpace(rt.Custom) != "" {
		var custom struct {
			Rules []map[string]any `json:"rules"`
		}
		if json.Unmarshal([]byte(rt.Custom), &custom) == nil {
			for _, r := range custom.Rules {
				if _, isXray := r["outboundTag"]; isXray {
					rules = append(rules, xrayRule(r, nil, resolveIP))
				} else {
					rules = append(rules, sbRule(r))
				}
			}
		} else {
			app.Note = "custom route rules unreadable"
		}
	}
	// Then NekoRay's lists: block, proxy, direct - domains first, then IPs.
	for _, l := range []struct {
		key, list, out string
	}{
		{"domain", rt.BlockDomain, "block"}, {"domain", rt.ProxyDomain, "proxy"}, {"domain", rt.DirectDomain, "bypass"},
		{"ip", rt.BlockIP, "block"}, {"ip", rt.ProxyIP, "proxy"}, {"ip", rt.DirectIP, "bypass"},
	} {
		if lines := nekoLines(l.list); len(lines) > 0 {
			rules = append(rules, xrayRule(map[string]any{l.key: lines, "outboundTag": l.out}, nil, resolveIP))
		}
	}
	final := strings.ToLower(rt.DefOutbound)
	switch final {
	case "", "proxy":
		final = "proxy"
	case "direct", "bypass":
		final = "bypass"
	}
	xf := &xrayFile{Outbounds: nekoOutbounds}
	resolve := xf.resolver()

	if st.ClashAPI > 0 {
		api := newAPI(fmt.Sprintf("127.0.0.1:%d", st.ClashAPI), st.ClashSecret)
		if s, err := api.fetch(ctx); err == nil {
			seenAPI[strings.TrimPrefix(api.base, "http://")] = true
			app.Live = true
			app.Source += " + API " + api.base
			app.LiveDirect = liveDirect(s)
		}
	}
	app.Anthropic, app.Check = evalRules(rules, final, "", resolve)
	return app
}

// AllCandidates is every config worth reading for one user: command-line configs of
// running cores, well-known locations, Hiddify / FlClash / Karing data folders and NekoRay's settings.
func AllCandidates(home, appData, localAppData string, procs ProcInfo) []ConfigCandidate {
	var c []ConfigCandidate
	generic := CandidateConfigs(home, appData, procs.Dirs)
	// Clash for Windows: its folder's yaml files are evaluated together (profile + settings);
	// its core's command-line API (-ext-ctl / -secret) is handed over.
	if cfw := CFWDir(home); cfw != "" {
		cand := ConfigCandidate{Kind: "cfw", Path: cfw, App: "Clash for Windows"}
		var keep []ConfigCandidate
		for _, p := range procs.Configs {
			if p.Kind == "clash" && strings.EqualFold(filepath.Dir(p.Path), cfw) {
				if p.API != (APIOverride{}) {
					cand.API = p.API
				}
				continue
			}
			keep = append(keep, p)
		}
		procs.Configs = keep
		c = append(c, cand)
		var g []ConfigCandidate
		for _, x := range generic {
			if !strings.EqualFold(filepath.Dir(x.Path), cfw) {
				g = append(g, x)
			}
		}
		generic = g
	}
	c = append(c, procs.Configs...)
	c = append(c, generic...)
	var roots []string
	for _, r := range []string{appData, localAppData} {
		if r != "" {
			roots = append(roots, r)
		}
	}
	if home != "" {
		for _, r := range []string{"Library/Application Support", "Library/Group Containers", "Library/Containers", ".local/share"} {
			roots = append(roots, filepath.Join(home, r))
		}
	}
	c = append(c, FindHiddify(roots).Configs...)
	c = append(c, FlClashCandidates(roots)...)
	// Mihomo Party (Electron: ~/.config on Linux), Clash Nyanpasu and Clash Verge (also
	// portable: <exe dir>\.config\...).
	mroots := append([]string{}, roots...)
	if home != "" {
		mroots = append(mroots, filepath.Join(home, ".config"))
	}
	for _, d := range procs.Dirs {
		mroots = append(mroots, d, filepath.Join(d, ".config"), filepath.Join(d, "data"))
	}
	c = append(c, MihomoGUICandidates(mroots)...)
	if home != "" {
		roots = append(roots, filepath.Join(home, "Documents"))
	}
	c = append(c, KaringCandidates(roots)...)
	return append(c, NekorayDirs(home, procs.Dirs)...)
}

// ---------------------------------------------------------------- FlClash

// FlClash (a mihomo GUI) keeps its subscriptions in profiles/<id>.yaml and applies its
// own settings on top when it starts the core: ports, mode, TUN, external controller
// ("patchClashConfig") and per-profile rule overrides. Older versions keep the
// settings in Flutter's shared_preferences.json ("flutter.config" / "flutter.clashConfig").

// FindAppDirs returns folders under roots whose name contains one of keys, plus
// their direct subfolders (Windows nests them: AppData\Roaming\com.follow\clash).
func FindAppDirs(roots []string, keys ...string) []string {
	var out []string
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			n := strings.ToLower(e.Name())
			hit := false
			for _, k := range keys {
				if strings.Contains(n, k) {
					hit = true
				}
			}
			if !hit || !e.IsDir() {
				continue
			}
			d := filepath.Join(root, e.Name())
			out = append(out, d)
			if subs, err := os.ReadDir(d); err == nil {
				for _, s := range subs {
					if s.IsDir() && s.Name() != "profiles" {
						out = append(out, filepath.Join(d, s.Name()))
					}
				}
			}
		}
	}
	return out
}

// FlClashCandidates: FlClash data folders (Roaming\com.follow\clash, com.follow.clash, ...).
func FlClashCandidates(roots []string) []ConfigCandidate {
	var out []ConfigCandidate
	for _, d := range FindAppDirs(roots, "com.follow", "flclash") {
		out = append(out, ConfigCandidate{Kind: "flclash", Path: d, App: "FlClash"})
	}
	return out
}

// jsonOrString decodes v as an object, also when it's a JSON-encoded string (prefs).
func jsonOrString(v any) map[string]any {
	switch x := v.(type) {
	case map[string]any:
		return x
	case string:
		var m map[string]any
		if json.Unmarshal([]byte(x), &m) == nil {
			return m
		}
	}
	return nil
}

func pick(m map[string]any, keys ...string) (any, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v, true
		}
	}
	return nil, false
}

// FlClashSettings reads FlClash's settings: (app config, clash patch).
func FlClashSettings(dir string, extraPrefs map[string]any) (cfg, patch map[string]any) {
	if data, err := os.ReadFile(filepath.Join(dir, "config.json")); err == nil {
		var m map[string]any
		if json.Unmarshal(data, &m) == nil {
			cfg = m
		}
	}
	prefs := extraPrefs
	if data, err := os.ReadFile(filepath.Join(dir, "shared_preferences.json")); err == nil {
		var m map[string]any
		if json.Unmarshal(data, &m) == nil {
			prefs = m
		}
	}
	if cfg == nil && prefs != nil {
		if v, ok := pick(prefs, "flutter.config", "config"); ok {
			cfg = jsonOrString(v)
		}
	}
	if cfg != nil {
		if v, ok := pick(cfg, "patchClashConfig", "clashConfig"); ok {
			patch = jsonOrString(v)
		}
	}
	if patch == nil && prefs != nil {
		if v, ok := pick(prefs, "flutter.clashConfig", "clashConfig"); ok {
			patch = jsonOrString(v)
		}
	}
	return cfg, patch
}

// evalFlClash merges the current profile with FlClash's settings and evaluates it.
func evalFlClash(ctx context.Context, dir string, seenAPI map[string]bool, extraPrefs map[string]any) *ProxyApp {
	cfg, patch := FlClashSettings(dir, extraPrefs)
	id := ""
	var profile map[string]any
	if cfg != nil {
		id = anyString(cfg["currentProfileId"])
		for _, p := range v5List(cfg["profiles"]) {
			if m, ok := p.(map[string]any); ok && anyString(m["id"]) == id {
				profile = m
			}
		}
	}
	var path string
	for _, p := range []string{filepath.Join(dir, "profiles", id+".yaml"), filepath.Join(dir, "profiles", id+".yml"), filepath.Join(dir, "config.yaml")} {
		if _, err := os.Stat(p); err == nil && (id != "" || filepath.Base(p) == "config.yaml") {
			path = p
			break
		}
	}
	if path == "" && cfg == nil {
		return nil // not a FlClash folder
	}
	if path == "" {
		app := &ProxyApp{Kind: "clash", App: "FlClash", Source: dir,
			Anthropic: HostRoute{Outcome: OutUnknown, Uncertain: true}, Note: "current profile not found"}
		app.Check = app.Anthropic
		return app
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	f, err := parseClashFile(data)
	if err != nil {
		return nil
	}
	// FlClash's own settings override the profile.
	if patch != nil {
		if v, ok := pick(patch, "mode"); ok && anyString(v) != "" {
			f.Mode = anyString(v)
		}
		if v, ok := pick(patch, "mixed-port", "mixedPort"); ok {
			f.MixedPort, f.Port, f.SocksPort = anyPort(v), 0, 0
		}
		if v, ok := pick(patch, "tun"); ok {
			if m, ok := v.(map[string]any); ok {
				en, _ := m["enable"].(bool)
				f.Tun.Enable = en
			}
		}
		if v, ok := pick(patch, "external-controller", "externalController"); ok {
			f.ExternalController = anyString(v)
		}
		if v, ok := pick(patch, "secret"); ok {
			f.Secret = anyString(v)
		}
		if v, ok := pick(patch, "rules", "rule"); ok {
			if rs := strList(v); len(rs) > 0 {
				f.Rules = rs
			}
		}
	}
	// Per-profile rule overrides ("overrideData": {"enable": true, "rule": {"type": "added"|"override", ...}}).
	if profile != nil {
		if od, ok := profile["overrideData"].(map[string]any); ok {
			if en, _ := od["enable"].(bool); en {
				if r, ok := od["rule"].(map[string]any); ok {
					override := strList(r["overrideRules"])
					added := strList(r["addedRules"])
					if strings.EqualFold(anyString(r["type"]), "override") && len(override) > 0 {
						f.Rules = override
					} else if len(added) > 0 {
						f.Rules = append(added, f.Rules...)
					}
				}
			}
		}
	}
	if f.Mode == "" {
		f.Mode = "rule"
	}
	app := evalClash(ctx, path, f, seenAPI)
	app.App = "FlClash"
	return app
}

// ---------------------------------------------------------------- Karing

// KaringCandidates: Karing (a sing-box GUI) writes the full config it runs into its
// data folder; the newest runnable sing-box config there is taken as the active one.
func KaringCandidates(roots []string) []ConfigCandidate {
	var best string
	var bestTime int64
	for _, d := range FindAppDirs(roots, "karing") {
		walkLimited(d, 4, func(p string) {
			if !strings.HasSuffix(strings.ToLower(p), ".json") {
				return
			}
			st, err := os.Stat(p)
			if err != nil || st.Size() > 8<<20 || st.ModTime().UnixNano() <= bestTime {
				return
			}
			data, err := os.ReadFile(p)
			if err != nil || !runnableSingBox(data) {
				return
			}
			best, bestTime = p, st.ModTime().UnixNano()
		})
	}
	if best == "" {
		return nil
	}
	return []ConfigCandidate{{Kind: "json", Path: best, App: "Karing"}}
}

// runnableSingBox: a full sing-box config (inbounds + outbounds + route), not a
// subscription / outbound list.
func runnableSingBox(data []byte) bool {
	if JSONKind(data) != "sing-box" {
		return false
	}
	var f struct {
		Inbounds  []any `json:"inbounds"`
		Outbounds []any `json:"outbounds"`
		Route     any   `json:"route"`
	}
	return json.Unmarshal(StripJSONComments(data), &f) == nil && len(f.Inbounds) > 0 && len(f.Outbounds) > 0 && f.Route != nil
}

// ---------------------------------------------------------------- Mihomo Party / Clash Nyanpasu

// They write the runtime config the core runs with before starting it: Mihomo Party
// <data>/work/config.yaml, Clash Nyanpasu <config>/clash-config.yaml, Clash Verge (Rev)
// <data>/clash-verge.yaml. The newest one per app is taken (rewritten on every start /
// profile switch).
func MihomoGUICandidates(roots []string) []ConfigCandidate {
	var out []ConfigCandidate
	for _, app := range []struct {
		name string
		keys []string
	}{
		{"Mihomo Party", []string{"mihomo-party", "mihomo party", "clash-party", "clash party"}},
		{"Clash Nyanpasu", []string{"nyanpasu"}},
		// Clash Verge Rev (io.github.clash-verge-rev.clash-verge-rev) and the original Clash Verge;
		// their config.yaml is only a partial override, clash-verge.yaml is the runtime file.
		{"Clash Verge", []string{"clash-verge"}},
	} {
		var best string
		var bestTime int64
		seen := map[string]bool{}
		for _, d := range FindAppDirs(roots, app.keys...) {
			walkLimited(d, 2, func(p string) {
				if seen[p] {
					return
				}
				seen[p] = true
				base := strings.ToLower(filepath.Base(p))
				runtime := base == "clash-config.yaml" || base == "clash-verge.yaml" ||
					(base == "config.yaml" && strings.EqualFold(filepath.Base(filepath.Dir(p)), "work"))
				if !runtime {
					return
				}
				if st, err := os.Stat(p); err == nil && st.ModTime().UnixNano() > bestTime {
					best, bestTime = p, st.ModTime().UnixNano()
				}
			})
		}
		if best != "" {
			out = append(out, ConfigCandidate{Kind: "clash", Path: best, App: app.name})
		}
	}
	return out
}

// AppLabel names the client a config file belongs to, from its path ("" = unknown).
func AppLabel(path string) string {
	p := strings.ToLower(filepath.ToSlash(path))
	for _, l := range []struct{ key, name string }{
		{"mihomo-party", "Mihomo Party"}, {"mihomo party", "Mihomo Party"}, {"clash-party", "Mihomo Party"},
		{"nyanpasu", "Clash Nyanpasu"}, {"clash-verge", "Clash Verge"}, {"clashx", "ClashX"},
		{"flclash", "FlClash"}, {"com.follow", "FlClash"}, {"hiddify", "Hiddify"}, {"karing", "Karing"},
		{"v2rayn", "v2rayN"}, {"v2rayu", "V2rayU"}, {"v2rayxs", "V2RayXS"}, {"qv2ray", "Qv2ray"},
		{"nekobox", "NekoBox"}, {"nekoray", "NekoRay"},
	} {
		if strings.Contains(p, l.key) {
			return l.name
		}
	}
	return ""
}

// ---------------------------------------------------------------- Clash for Windows

// Clash for Windows (also on macOS / Linux) keeps profiles in ~/.config/clash/profiles/,
// the selected one (and each group's saved selection) in profiles/list.yml, and its
// general settings (ports, mode, controller, secret) in ~/.config/clash/config.yaml,
// which it applies on top of the profile.

type cfwList struct {
	Index int `yaml:"index"`
	Files []struct {
		Time     string `yaml:"time"`
		Name     string `yaml:"name"`
		Selected []struct {
			Name string `yaml:"name"`
			Now  string `yaml:"now"`
		} `yaml:"selected"`
	} `yaml:"files"`
}

// CFWDir returns ~/.config/clash if it's a Clash for Windows home ("" otherwise).
func CFWDir(home string) string {
	if home == "" {
		return ""
	}
	d := filepath.Join(home, ".config", "clash")
	if _, err := os.Stat(filepath.Join(d, "profiles", "list.yml")); err != nil {
		return ""
	}
	return d
}

// evalCFW merges the selected profile with CFW's settings and saved selections.
func evalCFW(ctx context.Context, dir string, api APIOverride, seenAPI map[string]bool) *ProxyApp {
	uncertain := func(note string) *ProxyApp {
		a := &ProxyApp{Kind: "clash", App: "Clash for Windows", Source: dir, Note: note,
			Anthropic: HostRoute{Outcome: OutUnknown, Uncertain: true}}
		a.Check = a.Anthropic
		return a
	}
	data, err := os.ReadFile(filepath.Join(dir, "profiles", "list.yml"))
	if err != nil {
		return nil
	}
	var list cfwList
	if yaml.Unmarshal(data, &list) != nil || len(list.Files) == 0 {
		return uncertain("profiles/list.yml unreadable or empty")
	}
	if list.Index < 0 || list.Index >= len(list.Files) {
		list.Index = 0
	}
	sel := list.Files[list.Index]
	profilePath := filepath.Join(dir, "profiles", sel.Time)
	pdata, err := os.ReadFile(profilePath)
	if err != nil {
		return uncertain("selected profile " + sel.Time + " not found")
	}
	f, err := parseClashFile(pdata)
	if err != nil {
		return uncertain("selected profile unreadable")
	}
	// CFW's general settings override the profile's.
	if bdata, err := os.ReadFile(filepath.Join(dir, "config.yaml")); err == nil {
		if base, err := parseClashFile(bdata); err == nil {
			if p := nonZero(base.MixedPort, base.Port, base.SocksPort); len(p) > 0 {
				f.MixedPort, f.Port, f.SocksPort = base.MixedPort, base.Port, base.SocksPort
			}
			if base.Mode != "" {
				f.Mode = base.Mode
			}
			if base.ExternalController != "" {
				f.ExternalController, f.Secret = base.ExternalController, base.Secret
			}
			f.Tun.Enable = f.Tun.Enable || base.Tun.Enable
		}
	}
	if api.Addr != "" {
		f.ExternalController = api.Addr
	}
	if api.Secret != "" {
		f.Secret = api.Secret
	}
	f.selected = map[string]string{}
	for _, s := range sel.Selected {
		if s.Name != "" && s.Now != "" {
			f.selected[s.Name] = s.Now
		}
	}
	app := evalClash(ctx, profilePath, f, seenAPI)
	app.App = "Clash for Windows"
	if sdata, err := os.ReadFile(filepath.Join(dir, "cfw-settings.yaml")); err == nil {
		var st struct {
			Parsers []any `yaml:"parsers"`
		}
		if yaml.Unmarshal(sdata, &st) == nil && len(st.Parsers) > 0 && !app.Live {
			app.Note = strings.TrimPrefix(app.Note+"; profile parsers are on (rules may differ from the file)", "; ")
		}
	}
	return app
}
