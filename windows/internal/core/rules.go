package core

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Rule-engine for Clash (mihomo) and sing-box routing rules: works out where a
// connection to a host would be sent - DIRECT, REJECT or a proxy.

type Outcome string

const (
	OutDirect  Outcome = "direct"
	OutProxy   Outcome = "proxy"
	OutReject  Outcome = "reject"
	OutUnknown Outcome = "unknown"
)

type tri int

const (
	no tri = iota
	maybe
	yes
)

// AnthropicHosts / CheckHosts are evaluated against the app's rules.
var (
	AnthropicHosts = []string{"claude.ai", "api.anthropic.com"}
	CheckHosts     = []string{"api4.ipify.org", "ipv4.icanhazip.com", "ipinfo.io", "ipapi.co", "api.country.is"}
)

// target describes a connection being routed.
type target struct {
	host      string
	ip        net.IP // known destination IP (Anthropic) or nil
	country   string // country of ip ("US" for Anthropic), "" if unknown
	anthropic bool
}

func targetFor(host string) target {
	for _, h := range AnthropicHosts {
		if h == host {
			return target{host: host, ip: net.ParseIP(AnthropicProbeIP), country: "US", anthropic: true}
		}
	}
	return target{host: host}
}

// Rule is one routing rule, normalised from Clash or sing-box.
type Rule struct {
	Raw    string // as written, for messages
	match  func(t target, mode string) tri
	Target string // policy / outbound tag ("" = not a final rule, e.g. sniff)
	Reject bool   // sing-box action: reject
}

// HostRoute is where a host's traffic goes.
type HostRoute struct {
	Host      string    `json:"host"`
	Outcome   Outcome   `json:"outcome"`
	Possible  []Outcome `json:"possible,omitempty"` // when uncertain, every outcome that might apply
	Uncertain bool      `json:"uncertain,omitempty"`
	Rule      string    `json:"rule,omitempty"`  // the rule that matched
	Chain     []string  `json:"chain,omitempty"` // policy chain, e.g. ["Proxy", "DE-1"]
}

// Resolver turns a policy/outbound name into an outcome and chain.
// uncertain=true when the selection isn't known (no API, selector with DIRECT member...).
type Resolver func(name string) (out Outcome, chain []string, uncertain bool)

// Evaluate walks rules in order for host. final is the fallback policy.
func Evaluate(rules []Rule, final, mode string, host string, resolve Resolver) HostRoute {
	t := targetFor(host)
	hr := HostRoute{Host: host}
	add := func(name, raw string, reject bool) (Outcome, []string, bool) {
		if reject {
			return OutReject, []string{"REJECT"}, false
		}
		return resolve(name)
	}
	var possible []Outcome
	uncertain := false
	decided := false
	for _, r := range rules {
		if r.Target == "" && !r.Reject {
			continue
		}
		m := r.match(t, mode)
		if m == no {
			continue
		}
		out, chain, unc := add(r.Target, r.Raw, r.Reject)
		if m == maybe {
			uncertain = true
			possible = append(possible, out)
			continue
		}
		hr.Rule, hr.Chain = r.Raw, chain
		possible = append(possible, out)
		uncertain = uncertain || unc
		decided = true
		break
	}
	if !decided {
		out, chain, unc := resolve(final)
		hr.Rule, hr.Chain = "final: "+final, chain
		possible = append(possible, out)
		uncertain = uncertain || unc
	}
	hr.Outcome = possible[len(possible)-1]
	if uncertain {
		hr.Uncertain = true
		hr.Possible = dedupe(possible)
		if len(hr.Possible) > 1 {
			for _, o := range hr.Possible {
				if o == OutDirect {
					hr.Outcome = OutUnknown // might go DIRECT
				}
			}
		}
	}
	return hr
}

func dedupe(in []Outcome) []Outcome {
	seen := map[Outcome]bool{}
	var out []Outcome
	for _, o := range in {
		if !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	return out
}

// ---------------------------------------------------------------- matchers

func normType(t string) string {
	t = strings.ToUpper(t)
	return strings.NewReplacer("-", "", "_", "").Replace(t)
}

func domainSuffix(host, suffix string) bool {
	suffix = strings.TrimPrefix(strings.ToLower(suffix), "+.")
	suffix = strings.TrimPrefix(suffix, ".")
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

func boolTri(b bool) tri {
	if b {
		return yes
	}
	return no
}

// nameHint guesses whether a GEOSITE / RULE-SET / rule_set named `name` contains t.host.
func nameHint(name string, t target) tri {
	n := strings.ToLower(name)
	for _, k := range []string{"anthropic", "claude", "category-ai", "ai-!cn", "ai_!cn"} {
		if strings.Contains(n, k) {
			return boolTri(t.anthropic)
		}
	}
	if strings.Contains(n, "!") { // "geolocation-!cn" & co: big "foreign sites" lists
		return maybe
	}
	// Domestic / ad / LAN lists never contain Anthropic or the IP-check sites.
	for _, tok := range strings.FieldsFunc(n, func(r rune) bool { return strings.ContainsRune("-_@:./ ", r) }) {
		switch tok {
		case "cn", "ir", "iran", "china", "private", "lan", "local", "ads", "adblock", "reject", "domestic", "direct", "system":
			return no
		}
	}
	// Lists named after one service never contain Anthropic or the IP-check sites.
	if singleService[strings.TrimPrefix(n, "geosite-")] {
		return no
	}
	return maybe
}

var singleService = map[string]bool{}

func init() {
	for _, s := range strings.Fields(`google youtube telegram twitter x facebook instagram meta whatsapp netflix
		spotify openai github microsoft apple icloud amazon aws cloudflare discord reddit tiktok bing gemini
		wikipedia linkedin steam pinterest twitch tumblr yahoo disney hbo hulu primevideo duckduckgo signal
		zoom slack notion figma docker npmjs pypi gitlab bilibili baidu tencent alibaba xiaomi huawei`) {
		singleService[s] = true
	}
}

func portTri(spec string, port int) tri {
	for _, part := range strings.FieldsFunc(spec, func(r rune) bool { return r == '/' || r == ',' }) {
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, e1 := strconv.Atoi(strings.TrimSpace(lo))
			b, e2 := strconv.Atoi(strings.TrimSpace(hi))
			if e1 == nil && e2 == nil && port >= a && port <= b {
				return yes
			}
		} else if p, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && p == port {
			return yes
		}
	}
	return no
}

func ipTri(cidr string, t target, noResolve bool) tri {
	if noResolve && t.ip == nil {
		return no
	}
	if t.ip == nil {
		return maybe
	}
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr += "/128"
		} else {
			cidr += "/32"
		}
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return maybe
	}
	return boolTri(n.Contains(t.ip))
}

func geoipTri(code string, t target, noResolve bool) tri {
	code = strings.ToUpper(code)
	if code == "PRIVATE" || code == "LAN" {
		return no // public destinations only
	}
	if t.country != "" {
		if noResolve && !t.anthropic {
			return no
		}
		return boolTri(code == t.country)
	}
	if noResolve {
		return no
	}
	if code == "IR" || code == "CN" {
		return no // the IP-check services aren't hosted in Iran/China
	}
	return maybe
}

func processTri(name string, t target) tri {
	n := strings.ToLower(name)
	if t.anthropic {
		return boolTri(strings.Contains(n, "claude") || n == "node" || n == "node.exe")
	}
	return boolTri(strings.Contains(n, "claudeguard"))
}

// ClashRule builds a rule from Clash/mihomo syntax: TYPE,payload,target[,no-resolve].
func ClashRule(typ, payload, policy string, params []string) Rule {
	raw := strings.Join(append([]string{typ, payload, policy}, params...), ",")
	if normType(typ) == "MATCH" || normType(typ) == "FINAL" {
		raw = "MATCH," + policy
	}
	noResolve := false
	for _, p := range params {
		if strings.EqualFold(strings.TrimSpace(p), "no-resolve") {
			noResolve = true
		}
	}
	nt := normType(typ)
	var m func(t target, mode string) tri
	switch nt {
	case "DOMAIN":
		m = func(t target, _ string) tri { return boolTri(t.host == strings.ToLower(payload)) }
	case "DOMAINSUFFIX":
		m = func(t target, _ string) tri { return boolTri(domainSuffix(t.host, payload)) }
	case "DOMAINKEYWORD":
		m = func(t target, _ string) tri { return boolTri(strings.Contains(t.host, strings.ToLower(payload))) }
	case "DOMAINREGEX":
		re, err := regexp.Compile(payload)
		m = func(t target, _ string) tri {
			if err != nil {
				return maybe
			}
			return boolTri(re.MatchString(t.host))
		}
	case "DOMAINWILDCARD":
		re, err := regexp.Compile("^" + strings.NewReplacer(".", `\.`, "*", "[^.]*", "?", ".").Replace(strings.ToLower(payload)) + "$")
		m = func(t target, _ string) tri {
			if err != nil {
				return maybe
			}
			return boolTri(re.MatchString(t.host))
		}
	case "GEOSITE", "RULESET", "DOMAINSET": // DOMAIN-SET: Surge / Shadowrocket
		m = func(t target, _ string) tri { return nameHint(payload, t) }
	case "GEOIP":
		m = func(t target, _ string) tri { return geoipTri(payload, t, noResolve) }
	case "IPCIDR", "IPCIDR6":
		m = func(t target, _ string) tri { return ipTri(payload, t, noResolve) }
	case "DSTPORT":
		m = func(t target, _ string) tri { return portTri(payload, 443) }
	case "NETWORK":
		m = func(t target, _ string) tri { return boolTri(strings.EqualFold(payload, "tcp")) }
	case "PROCESSNAME", "PROCESSPATH", "PROCESSNAMEREGEX", "PROCESSPATHREGEX", "PROCESS":
		m = func(t target, _ string) tri { return processTri(payload, t) }
	case "MATCH", "FINAL":
		m = func(target, string) tri { return yes }
	default: // SRC-*, IN-*, UID, AND/OR/NOT, SUB-RULE, DSCP ...: can't tell from here
		m = func(target, string) tri { return maybe }
	}
	return Rule{Raw: raw, match: m, Target: policy}
}

// ParseClashRuleLine parses "DOMAIN-SUFFIX,claude.ai,Proxy" / "MATCH,DIRECT" /
// "IP-CIDR,1.2.3.0/24,DIRECT,no-resolve". Logical rules keep their commas in parens.
func ParseClashRuleLine(line string) (Rule, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Rule{}, false
	}
	typ, rest, _ := strings.Cut(line, ",")
	if nt := normType(typ); nt == "MATCH" || nt == "FINAL" {
		policy, _, _ := strings.Cut(rest, ",") // "FINAL,PROXY,dns-failed" (Surge-style options)
		return ClashRule(typ, "", strings.TrimSpace(policy), nil), true
	}
	var payload string
	if strings.HasPrefix(strings.TrimSpace(rest), "(") { // AND,((...),(...)),Policy
		depth, i := 0, 0
		for i = 0; i < len(rest); i++ {
			if rest[i] == '(' {
				depth++
			} else if rest[i] == ')' {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		if i >= len(rest) {
			return Rule{}, false
		}
		payload, rest = rest[:i+1], strings.TrimPrefix(rest[i+1:], ",")
	} else {
		payload, rest, _ = strings.Cut(rest, ",")
	}
	parts := strings.Split(rest, ",")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return Rule{}, false
	}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return ClashRule(strings.TrimSpace(typ), strings.TrimSpace(payload), parts[0], parts[1:]), true
}
