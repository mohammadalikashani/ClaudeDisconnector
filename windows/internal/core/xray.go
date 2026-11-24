package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Xray-core / V2Ray (v4 JSON format) routing: used by v2rayN, V2rayU, V2RayXS,
// Qv2ray and plain xray/v2ray. Xray has no HTTP API like Clash, so the config file
// is the source of truth (its routing doesn't change at runtime, except balancers).

type xrayOutbound struct {
	Tag      string         `json:"tag"`
	Protocol string         `json:"protocol"`
	Settings map[string]any `json:"settings"`
}

type xrayInbound struct {
	Tag      string         `json:"tag"`
	Protocol string         `json:"protocol"`
	Port     any            `json:"port"`
	Listen   string         `json:"listen"`
	Settings map[string]any `json:"settings"`
}

type xrayFile struct {
	Inbounds  []xrayInbound  `json:"inbounds"`
	Outbounds []xrayOutbound `json:"outbounds"`
	Routing   *struct {
		DomainStrategy string           `json:"domainStrategy"`
		Rules          []map[string]any `json:"rules"`
		Balancers      []struct {
			Tag         string   `json:"tag"`
			Selector    []string `json:"selector"`
			FallbackTag string   `json:"fallbackTag"`
		} `json:"balancers"`
	} `json:"routing"`
	Router map[string]any `json:"router"` // V2Ray v5 format, translated by v5Routing
}

// StripJSONComments removes // and /* */ comments outside strings (xray accepts JSONC).
func StripJSONComments(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(b) && b[i+1] == '/' {
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, '\n')
			}
			continue
		}
		if c == '/' && i+1 < len(b) && b[i+1] == '*' {
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
			continue
		}
		if c == '#' && (len(out) == 0 || out[len(out)-1] == '\n') { // shell-style comment lines
			for i < len(b) && b[i] != '\n' {
				i++
			}
			continue
		}
		out = append(out, c)
	}
	return out
}

// JSONKind tells sing-box and xray/v2ray configs apart ("" = neither).
func JSONKind(data []byte) string {
	var probe struct {
		Outbounds []map[string]any `json:"outbounds"`
		Inbounds  []map[string]any `json:"inbounds"`
		Routing   any              `json:"routing"`
		Route     any              `json:"route"`
	}
	if json.Unmarshal(StripJSONComments(data), &probe) != nil {
		return ""
	}
	for _, list := range [][]map[string]any{probe.Outbounds, probe.Inbounds} {
		for _, o := range list {
			if _, ok := o["protocol"]; ok {
				return "xray"
			}
			if _, ok := o["type"]; ok {
				return "sing-box"
			}
		}
	}
	if probe.Routing != nil {
		return "xray"
	}
	if probe.Route != nil {
		return "sing-box"
	}
	return ""
}

// loadXray reads one config file, or merges every *.json in a directory (-confdir).
func loadXray(path string) (*xrayFile, error) {
	var files []string
	if st, err := os.Stat(path); err != nil {
		return nil, err
	} else if st.IsDir() {
		files, _ = filepath.Glob(filepath.Join(path, "*.json"))
		sort.Strings(files)
	} else {
		files = []string{path}
	}
	var merged xrayFile
	n := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var x xrayFile
		if json.Unmarshal(StripJSONComments(data), &x) != nil {
			continue
		}
		n++
		merged.Inbounds = append(merged.Inbounds, x.Inbounds...)
		merged.Outbounds = append(merged.Outbounds, x.Outbounds...)
		if x.Routing != nil {
			merged.Routing = x.Routing
		}
		if x.Router != nil {
			merged.Router = x.Router
		}
	}
	if n == 0 {
		return nil, fmt.Errorf("no readable xray config")
	}
	return &merged, nil
}

func anyPort(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		p, _ := strconv.Atoi(strings.TrimSpace(x))
		return p
	}
	return 0
}

func anyString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.Itoa(int(x))
	}
	return ""
}

func isLocalAddr(a string) bool {
	a = strings.ToLower(strings.Trim(a, "[]"))
	return a == "127.0.0.1" || a == "localhost" || a == "::1" || strings.HasPrefix(a, "127.")
}

// localForward returns "127.0.0.1:PORT" when a socks/http outbound points at a local
// port (i.e. it hands traffic to another proxy app on this machine), else "".
func localForward(protocol string, settings map[string]any) string {
	if protocol != "socks" && protocol != "http" {
		return ""
	}
	addr, port := anyString(settings["address"]), anyPort(settings["port"])
	if servers, ok := settings["servers"].([]any); ok && len(servers) > 0 {
		if s, ok := servers[0].(map[string]any); ok {
			addr, port = anyString(s["address"]), anyPort(s["port"])
		}
	}
	if port != 0 && isLocalAddr(addr) {
		return fmt.Sprintf("127.0.0.1:%d", port)
	}
	return ""
}

// LocalForwardPort parses a chain element produced by localForward.
func LocalForwardPort(chainElem string) int {
	if !strings.HasPrefix(chainElem, "127.0.0.1:") {
		return 0
	}
	p, _ := strconv.Atoi(strings.TrimPrefix(chainElem, "127.0.0.1:"))
	return p
}

func (f *xrayFile) resolver() Resolver {
	obs := map[string]xrayOutbound{}
	for _, o := range f.Outbounds {
		if _, dup := obs[o.Tag]; !dup {
			obs[o.Tag] = o
		}
	}
	type bal struct {
		selector []string
		fallback string
	}
	bals := map[string]bal{}
	if f.Routing != nil {
		for _, b := range f.Routing.Balancers {
			bals[b.Tag] = bal{b.Selector, b.FallbackTag}
		}
	}
	def := ""
	if len(f.Outbounds) > 0 {
		def = f.Outbounds[0].Tag
	}
	var one func(tag string, chain []string, depth int) (Outcome, []string, bool)
	one = func(tag string, chain []string, depth int) (Outcome, []string, bool) {
		if strings.HasPrefix(tag, "balancer:") {
			name := strings.TrimPrefix(tag, "balancer:")
			b, ok := bals[name]
			chain = append(chain, "balancer "+name)
			if !ok || depth > 4 {
				return OutUnknown, chain, true
			}
			var members []string
			for _, o := range f.Outbounds {
				for _, prefix := range b.selector {
					if strings.HasPrefix(o.Tag, prefix) {
						members = append(members, o.Tag)
						break
					}
				}
			}
			if b.fallback != "" {
				members = append(members, b.fallback)
			}
			if len(members) == 0 {
				return OutUnknown, chain, true
			}
			var first []string
			for i, m := range members {
				out, c, unc := one(m, nil, depth+1)
				if out != OutProxy || unc {
					return OutUnknown, chain, true // the balancer may pick a DIRECT / unknown member
				}
				if i == 0 {
					first = c
				}
			}
			return OutProxy, append(chain, first...), false
		}
		o, ok := obs[tag]
		if !ok {
			// xray sends traffic for a missing outbound tag to the default (first) outbound.
			if tag != def && def != "" && depth < 4 {
				return one(def, append(chain, tag+"(missing)"), depth+1)
			}
			return OutUnknown, append(chain, tag), true
		}
		chain = append(chain, tag)
		switch strings.ToLower(o.Protocol) {
		case "freedom":
			if _, frag := o.Settings["fragment"]; frag {
				chain[len(chain)-1] = tag + " (fragment)"
			}
			return OutDirect, chain, false
		case "blackhole":
			return OutReject, chain, false
		case "dns", "loopback":
			return OutUnknown, chain, true
		}
		if lf := localForward(strings.ToLower(o.Protocol), o.Settings); lf != "" {
			return OutProxy, append(chain, lf), false
		}
		return OutProxy, chain, false
	}
	return func(name string) (Outcome, []string, bool) { return one(name, nil, 0) }
}

// userInbounds are the inbounds ordinary traffic (Claude's) can arrive on.
func (f *xrayFile) userInbounds() map[string]bool {
	m := map[string]bool{}
	for _, in := range f.Inbounds {
		switch strings.ToLower(in.Protocol) {
		case "socks", "http", "mixed", "tun":
			m[in.Tag] = true
		case "dokodemo-door", "tunnel":
			if fr, _ := in.Settings["followRedirect"].(bool); fr {
				m[in.Tag] = true
			}
		}
	}
	return m
}

func xrayDomainTri(d string, t target) tri {
	ld := strings.ToLower(d)
	switch {
	case strings.HasPrefix(ld, "domain:"):
		return boolTri(domainSuffix(t.host, d[len("domain:"):]))
	case strings.HasPrefix(ld, "full:"):
		return boolTri(t.host == strings.ToLower(d[len("full:"):]))
	case strings.HasPrefix(ld, "regexp:"):
		re, err := regexp.Compile(d[len("regexp:"):])
		if err != nil {
			return maybe
		}
		return boolTri(re.MatchString(t.host))
	case strings.HasPrefix(ld, "keyword:"):
		return boolTri(strings.Contains(t.host, ld[len("keyword:"):]))
	case strings.HasPrefix(ld, "dotless:"):
		return boolTri(!strings.Contains(t.host, ".") && strings.Contains(t.host, ld[len("dotless:"):]))
	case strings.HasPrefix(ld, "geosite:"):
		name, _, _ := strings.Cut(ld[len("geosite:"):], "@")
		return nameHint(name, t)
	case strings.HasPrefix(ld, "ext:"):
		parts := strings.SplitN(ld, ":", 3)
		return nameHint(parts[len(parts)-1], t)
	}
	return boolTri(strings.Contains(t.host, ld)) // plain string = keyword
}

func xrayIPTri(e string, t target, resolve bool) tri {
	if !resolve && t.anthropic { // destination is a domain; IP rules don't apply (AsIs)
		return no
	}
	le := strings.ToLower(e)
	invert := false
	switch {
	case strings.HasPrefix(le, "geoip:"):
		code := le[len("geoip:"):]
		if strings.HasPrefix(code, "!") {
			invert, code = true, code[1:]
		}
		var r tri
		if !resolve {
			r = no
		} else {
			r = geoipTri(code, t, false)
		}
		if invert && r != maybe {
			r = 2 - r
		}
		return r
	case strings.HasPrefix(le, "ext:"):
		parts := strings.SplitN(le, ":", 3)
		if !resolve {
			return no
		}
		return nameHint(parts[len(parts)-1], t)
	}
	if !resolve {
		return no
	}
	return ipTri(e, t, false)
}

// xrayRule converts one routing rule. resolveIP: IPs are known (IPOnDemand, or the
// second pass of IPIfNonMatch); otherwise only domain conditions can match a domain.
func xrayRule(r map[string]any, userIn map[string]bool, resolveIP bool) Rule {
	raw, _ := json.Marshal(r)
	rule := Rule{Raw: string(raw)}
	if tag, _ := r["outboundTag"].(string); tag != "" {
		rule.Target = tag
	} else if b, _ := r["balancerTag"].(string); b != "" {
		rule.Target = "balancer:" + b
	} else {
		return rule
	}
	if en, ok := r["enabled"].(bool); ok && !en {
		rule.Target = ""
		return rule
	}
	rule.match = func(t target, _ string) tri {
		res := yes
		and := func(x tri) {
			if x < res {
				res = x
			}
		}
		for k, v := range r {
			switch k {
			case "type", "outboundTag", "balancerTag", "ruleTag", "tag", "enabled", "remarks", "domainMatcher", "id", "locked":
			case "domain", "domains":
				best := no
				for _, d := range strList(v) {
					if x := xrayDomainTri(d, t); x > best {
						best = x
					}
				}
				and(best)
			case "ip":
				best := no
				for _, e := range strList(v) {
					if x := xrayIPTri(e, t, resolveIP); x > best {
						best = x
					}
				}
				and(best)
			case "port":
				and(portTri(anyString(v), 443))
			case "network":
				and(boolTri(strings.Contains(strings.ToLower(anyString(v)), "tcp")))
			case "protocol":
				and(boolTri(contains(strList(v), "tls") || contains(strList(v), "http")))
			case "inboundTag":
				tags := strList(v)
				hit, all := false, len(userIn) > 0
				listed := map[string]bool{}
				for _, tg := range tags {
					listed[tg] = true
					if userIn[tg] {
						hit = true
					}
				}
				for tg := range userIn {
					if !listed[tg] {
						all = false
					}
				}
				switch {
				case !hit:
					and(no)
				case all:
				default:
					and(maybe)
				}
			case "process":
				ok := no
				for _, s := range strList(v) {
					if processTri(s, t) == yes {
						ok = yes
					}
				}
				and(ok)
			default: // source, sourcePort, user, attrs, localPort, ...
				and(maybe)
			}
		}
		return res
	}
	return rule
}

// XrayRules builds the ordered rule list for a routing domainStrategy.
func xrayRules(f *xrayFile) []Rule {
	if f.Routing == nil {
		return nil
	}
	userIn := f.userInbounds()
	strategy := strings.ToLower(f.Routing.DomainStrategy)
	var rules []Rule
	pass := func(resolveIP bool) {
		for _, r := range f.Routing.Rules {
			rules = append(rules, xrayRule(r, userIn, resolveIP))
		}
	}
	switch strategy {
	case "ipondemand":
		pass(true)
	case "ipifnonmatch":
		pass(false)
		pass(true) // no match by domain: xray resolves the domain and tries again
	default: // AsIs
		pass(false)
	}
	return rules
}

func evalXray(path string, f *xrayFile) *ProxyApp {
	app := &ProxyApp{Kind: "xray", Source: path}
	for _, in := range f.Inbounds {
		switch strings.ToLower(in.Protocol) {
		case "tun":
			app.TUN = true
		case "socks", "http", "mixed":
			if p := anyPort(in.Port); p != 0 {
				app.Ports = append(app.Ports, p)
			}
		}
	}
	if f.Router != nil && f.Routing == nil {
		if err := f.v5Routing(); err != nil {
			app.Note = "V2Ray v5 router: " + err.Error()
			app.Anthropic = HostRoute{Outcome: OutUnknown, Uncertain: true}
			app.Check = app.Anthropic
			return app
		}
		app.Note = "V2Ray v5 config format"
	}
	final := ""
	if len(f.Outbounds) > 0 {
		final = f.Outbounds[0].Tag // xray: no rule matched => first outbound
	}
	app.Anthropic, app.Check = evalRules(xrayRules(f), final, "", f.resolver())
	return app
}

// LinkLocalForwards follows chains between apps on this machine: e.g. v2rayN's TUN
// (sing-box) forwarding to its xray SOCKS port, where xray then decides DIRECT/proxy.
func LinkLocalForwards(apps []ProxyApp) {
	link := func(self int, r HostRoute) HostRoute {
		for hop := 0; hop < 4; hop++ {
			if len(r.Chain) == 0 {
				return r
			}
			port := LocalForwardPort(r.Chain[len(r.Chain)-1])
			if port == 0 {
				return r
			}
			next := -1
			for j := range apps {
				if j != self && apps[j].servesPortNum(port) {
					next = j
					break
				}
			}
			if next < 0 {
				return r
			}
			nr := apps[next].Anthropic
			if !anthropicHost(r.Host) {
				nr = apps[next].Check
			}
			merged := nr
			merged.Host = r.Host
			merged.Chain = append(append([]string{}, r.Chain...), nr.Chain...)
			merged.Rule = strings.TrimSpace(r.Rule + "; then " + apps[next].Name() + ": " + nr.Rule)
			merged.Uncertain = r.Uncertain || nr.Uncertain
			r, self = merged, next
		}
		return r
	}
	for i := range apps {
		apps[i].Anthropic = link(i, apps[i].Anthropic)
		apps[i].Check = link(i, apps[i].Check)
	}
}

func anthropicHost(h string) bool {
	for _, a := range AnthropicHosts {
		if a == h {
			return true
		}
	}
	return false
}

func (a ProxyApp) servesPortNum(p int) bool {
	for _, x := range a.Ports {
		if x == p {
			return true
		}
	}
	return false
}

// ProcInfo describes the running proxy apps found by the platform layer.
type ProcInfo struct {
	Dirs    []string        // executable folders (and their parents)
	Running map[string]bool // "clash" / "sing-box" / "xray"
	Configs []ConfigCandidate
}

func (p ProcInfo) IsRunning(kind string) bool { return p.Running[kind] }

// ProcKind classifies an executable name ("" = not a proxy core we understand).
func ProcKind(exe string) string {
	n := strings.ToLower(filepath.Base(strings.ReplaceAll(exe, `\`, "/")))
	n = strings.TrimSuffix(n, ".exe")
	switch {
	case strings.Contains(n, "mihomo") || strings.Contains(n, "clash") || n == "flclash":
		return "clash"
	case strings.Contains(n, "sing-box") || strings.Contains(n, "singbox") || strings.Contains(n, "hiddify") ||
		strings.Contains(n, "nekobox") || strings.Contains(n, "karing"):
		return "sing-box"
	case strings.Contains(n, "xray") || n == "v2ray" || n == "v2ray-core" || n == "wv2ray" || n == "v2ctl":
		return "xray"
	}
	return ""
}

// ConfigArgs extracts config paths from a proxy core's command line. Relative paths
// are tried against each of bases (process cwd, exe folder, ...).
func ConfigArgs(kind string, args []string, bases []string) []ConfigCandidate {
	var out []ConfigCandidate
	add := func(k, p string) {
		p = strings.Trim(p, `"'`)
		if p == "" || strings.HasPrefix(p, "stdin:") || p == "-" {
			return
		}
		if filepath.IsAbs(p) || strings.HasPrefix(p, "/") || len(bases) == 0 {
			out = append(out, ConfigCandidate{k, p})
			return
		}
		for _, b := range bases {
			out = append(out, ConfigCandidate{k, filepath.Join(b, p)})
		}
	}
	jsonKind := kind
	if kind == "sing-box" || kind == "xray" {
		jsonKind = "json" // decided by content
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		flag, val, hasEq := strings.Cut(a, "=")
		if !strings.HasPrefix(flag, "-") {
			continue
		}
		if !hasEq {
			if i+1 >= len(args) {
				break
			}
			val = args[i+1]
		}
		switch strings.TrimLeft(flag, "-") {
		case "c", "config", "f", "file":
			k := jsonKind
			if strings.HasSuffix(strings.ToLower(val), ".json") {
				k = "json"
			}
			add(k, val)
		case "confdir":
			add("xray", val)
		case "d", "D", "directory":
			if kind == "clash" {
				add("clash", filepath.Join(val, "config.yaml"))
			} else if kind == "sing-box" {
				add("json", filepath.Join(val, "config.json"))
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- V2Ray v5 format

// v5Get reads a protobuf-JSON field by its camelCase or snake_case name.
func v5Get(m map[string]any, camel string) any {
	if v, ok := m[camel]; ok {
		return v
	}
	var b strings.Builder
	for _, r := range camel {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return m[b.String()]
}

func v5List(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case nil:
		return nil
	}
	return []any{v}
}

// v5Domain turns {"type": "RootDomain", "value": "ir"} into the v4 form "domain:ir".
func v5Domain(e any) string {
	if s, ok := e.(string); ok {
		return s // v4-style string
	}
	m, ok := e.(map[string]any)
	if !ok {
		return ""
	}
	val := anyString(m["value"])
	switch strings.ToLower(anyString(m["type"])) {
	case "regex", "1":
		return "regexp:" + val
	case "rootdomain", "domain", "2":
		return "domain:" + val
	case "full", "3":
		return "full:" + val
	}
	return "keyword:" + val // Plain (0 / default)
}

func v5Code(m map[string]any) string {
	code := anyString(v5Get(m, "code"))
	if code == "" {
		code = anyString(v5Get(m, "countryCode"))
	}
	return strings.ToLower(code)
}

// v5CIDR turns {"ipAddr": "1.2.3.0", "prefix": 24} (or base64 "ip") into "1.2.3.0/24".
func v5CIDR(e any) string {
	m, ok := e.(map[string]any)
	if !ok {
		return anyString(e)
	}
	ip := anyString(v5Get(m, "ipAddr"))
	if ip == "" {
		if raw, err := base64Decode(anyString(m["ip"])); err == nil && (len(raw) == 4 || len(raw) == 16) {
			ip = net.IP(raw).String()
		}
	}
	if ip == "" {
		return "?" // unreadable: matched as "maybe"
	}
	if p := anyPort(m["prefix"]); p != 0 {
		return fmt.Sprintf("%s/%d", ip, p)
	}
	return ip
}

func base64Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	return base64.StdEncoding.DecodeString(s)
}

// V5Rule translates one V2Ray v5 router rule into the v4 rule shape.
func V5Rule(r map[string]any) map[string]any {
	out := map[string]any{}
	if t := anyString(r["tag"]); t != "" {
		out["outboundTag"] = t
	}
	if b := anyString(v5Get(r, "balancingTag")); b != "" {
		out["balancerTag"] = b
	}
	var domains []any
	for _, d := range v5List(r["domain"]) {
		if s := v5Domain(d); s != "" {
			domains = append(domains, s)
		}
	}
	for _, g := range v5List(v5Get(r, "geoDomain")) {
		m, ok := g.(map[string]any)
		if !ok {
			continue
		}
		if code := v5Code(m); code != "" {
			domains = append(domains, "geosite:"+code)
		}
		for _, d := range v5List(m["domain"]) {
			if s := v5Domain(d); s != "" {
				domains = append(domains, s)
			}
		}
	}
	if len(domains) > 0 {
		out["domain"] = domains
	}
	var ips []any
	addGeo := func(list any) {
		for _, g := range v5List(list) {
			m, ok := g.(map[string]any)
			if !ok {
				continue
			}
			inv, _ := v5Get(m, "inverseMatch").(bool)
			if code := v5Code(m); code != "" {
				if inv {
					code = "!" + code
				}
				ips = append(ips, "geoip:"+code)
			}
			for _, c := range v5List(m["cidr"]) {
				if inv {
					ips = append(ips, "?") // inverted CIDR list: can't express in v4, so "maybe"
				} else {
					ips = append(ips, v5CIDR(c))
				}
			}
		}
	}
	addGeo(r["geoip"])
	for _, c := range v5List(r["cidr"]) { // deprecated top-level cidr list
		ips = append(ips, v5CIDR(c))
	}
	if len(ips) > 0 {
		out["ip"] = ips
	}
	if pl := v5Get(r, "portList"); pl != nil {
		out["port"] = anyString(pl)
	} else if pr, ok := v5Get(r, "portRange").(map[string]any); ok {
		out["port"] = fmt.Sprintf("%d-%d", anyPort(pr["from"]), anyPort(pr["to"]))
	}
	if n := r["networks"]; n != nil {
		var parts []string
		for _, x := range v5List(n) {
			s := strings.ToLower(anyString(x))
			if s == "1" || s == "2" || s == "rawtcp" {
				s = "tcp"
			}
			parts = append(parts, s)
		}
		out["network"] = strings.Join(parts, ",")
	}
	for k, v := range r {
		switch k {
		case "tag", "balancingTag", "balancing_tag", "domain", "geoDomain", "geo_domain", "geoip", "cidr",
			"portList", "port_list", "portRange", "port_range", "networks", "domainMatcher", "domain_matcher":
			continue
		case "inboundTag", "inbound_tag":
			out["inboundTag"] = v
		case "protocol":
			out["protocol"] = v
		default: // sourceGeoip, sourcePortList, userEmail, attributes ...: can't tell
			if l, ok := v.([]any); ok && len(l) == 0 {
				continue
			}
			if v == nil || v == "" {
				continue
			}
			out[k] = v
		}
	}
	return out
}

// v5Routing fills f.Routing from a V2Ray v5 "router" object.
func (f *xrayFile) v5Routing() error {
	r := f.Router
	routing := map[string]any{}
	strategy := strings.ToLower(anyString(v5Get(r, "domainStrategy")))
	switch strategy {
	case "useip", "1", "ipondemand", "3":
		strategy = "IPOnDemand" // resolved before (UseIp) or at the first IP rule
	case "ipifnonmatch", "2":
		strategy = "IPIfNonMatch"
	default:
		strategy = "AsIs"
	}
	routing["domainStrategy"] = strategy
	var rules []any
	for _, x := range v5List(r["rule"]) {
		if m, ok := x.(map[string]any); ok {
			rules = append(rules, V5Rule(m))
		}
	}
	routing["rules"] = rules
	var bals []any
	for _, x := range v5List(v5Get(r, "balancingRule")) {
		if m, ok := x.(map[string]any); ok {
			bals = append(bals, map[string]any{"tag": anyString(m["tag"]),
				"selector": v5Get(m, "outboundSelector"), "fallbackTag": anyString(v5Get(m, "fallbackTag"))})
		}
	}
	routing["balancers"] = bals
	raw, err := json.Marshal(routing)
	if err != nil {
		return err
	}
	var x xrayFile
	if err := json.Unmarshal([]byte(`{"routing":`+string(raw)+`}`), &x); err != nil {
		return err
	}
	f.Routing = x.Routing
	return nil
}
