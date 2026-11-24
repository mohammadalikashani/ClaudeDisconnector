import Foundation
import SystemConfiguration

// Detects Clash (mihomo) and sing-box, reads their configs / APIs, and works out
// where they send Claude's traffic: DIRECT, REJECT or a proxy.

public enum Outcome: String, Codable { case direct, proxy, reject, unknown }

public struct HostRoute: Codable, Equatable {
    public var host: String = ""
    public var outcome: Outcome = .unknown
    public var possible: [Outcome]?
    public var uncertain: Bool?
    public var rule: String?
    public var chain: [String]?
    public init() {}
}

public struct ProxyApp: Codable, Equatable {
    public var kind: String            // "clash", "sing-box" or "xray"
    public var source: String
    public var live: Bool
    public var mode: String?
    public var tun: Bool?
    public var ports: [Int]?
    public var anthropic: HostRoute
    public var check: HostRoute
    public var liveDirect: [String]?
    public var note: String?

    public init(kind: String, source: String, live: Bool, mode: String? = nil, tun: Bool? = nil, ports: [Int]? = nil,
                anthropic: HostRoute, check: HostRoute, liveDirect: [String]? = nil, note: String? = nil) {
        self.kind = kind; self.source = source; self.live = live; self.mode = mode; self.tun = tun; self.ports = ports
        self.anthropic = anthropic; self.check = check; self.liveDirect = liveDirect; self.note = note
    }

    public var name: String {
        switch kind {
        case "clash": return "Clash"
        case "xray": return "Xray/V2Ray"
        default: return "sing-box"
        }
    }

    public var sendsClaudeDirect: Bool {
        (anthropic.outcome == .direct && anthropic.uncertain != true) || !(liveDirect ?? []).isEmpty
    }

    /// Claude is proxied but the IP-check sites go DIRECT (checks would see the real IP).
    public var checkMisrouted: Bool { anthropic.outcome == .proxy && check.outcome == .direct }

    public func servesPort(_ proxyURL: String?) -> Bool {
        guard let proxyURL, let hp = ProxyURL.hostPort(proxyURL) else { return false }
        return (ports ?? []).contains(hp.port)
    }

    public var describe: String {
        var s = "\(name): Claude -> "
        if let l = liveDirect, let first = l.first {
            s += "DIRECT (live connection to \(first))"
        } else if anthropic.outcome == .unknown {
            s += "uncertain (might be DIRECT)"
        } else {
            s += anthropic.outcome.rawValue.uppercased()
            if let c = anthropic.chain, !c.isEmpty { s += " [\(c.joined(separator: " > "))]" }
        }
        if let r = anthropic.rule { s += " via rule \(r)" }
        return s
    }
}

// MARK: - Rule engine

enum Tri: Int, Comparable {
    case no = 0, maybe = 1, yes = 2
    static func < (a: Tri, b: Tri) -> Bool { a.rawValue < b.rawValue }
    init(_ b: Bool) { self = b ? .yes : .no }
}

public enum RuleEngine {
    public static let anthropicHosts = ["claude.ai", "api.anthropic.com"]
    public static let checkHosts = ["api4.ipify.org", "ipv4.icanhazip.com", "ipinfo.io", "ipapi.co", "api.country.is"]

    struct Target {
        var host: String
        var anthropic: Bool
        var ip: String? { anthropic ? NetInfo.anthropicProbeIP : nil }
        var country: String? { anthropic ? "US" : nil }
        init(_ host: String) {
            self.host = host
            anthropic = RuleEngine.anthropicHosts.contains(host)
        }
    }

    public struct Rule {
        var raw: String
        var match: (Target, String) -> Tri
        var target: String?   // policy / outbound; nil = not a routing decision
        var reject = false
    }

    /// (outcome, chain, uncertain)
    public typealias Resolver = (String) -> (Outcome, [String], Bool)

    static func evaluate(_ rules: [Rule], final: String, mode: String, host: String, resolve: Resolver) -> HostRoute {
        let t = Target(host)
        var hr = HostRoute()
        hr.host = host
        var possible: [Outcome] = []
        var uncertain = false
        var decided = false
        for r in rules where r.target != nil || r.reject {
            let m = r.match(t, mode)
            if m == .no { continue }
            let (out, chain, unc) = r.reject ? (Outcome.reject, ["REJECT"], false) : resolve(r.target!)
            if m == .maybe {
                uncertain = true
                possible.append(out)
                continue
            }
            hr.rule = r.raw
            hr.chain = chain
            possible.append(out)
            uncertain = uncertain || unc
            decided = true
            break
        }
        if !decided {
            let (out, chain, unc) = resolve(final)
            hr.rule = "final: \(final)"
            hr.chain = chain
            possible.append(out)
            uncertain = uncertain || unc
        }
        hr.outcome = possible.last!
        if uncertain {
            hr.uncertain = true
            var seen: [Outcome] = []
            for o in possible where !seen.contains(o) { seen.append(o) }
            hr.possible = seen
            if seen.count > 1 && seen.contains(.direct) { hr.outcome = .unknown }
        }
        return hr
    }

    static func rank(_ r: HostRoute) -> Int {
        if r.outcome == .direct && r.uncertain != true { return 4 }
        if r.outcome == .direct || r.outcome == .unknown { return 3 }
        return r.outcome == .proxy ? 1 : 0
    }

    public static func evalRules(_ rules: [Rule], final: String, mode: String, resolve: Resolver) -> (HostRoute, HostRoute) {
        func worst(_ hosts: [String]) -> HostRoute {
            var w: HostRoute?
            for h in hosts {
                let r = evaluate(rules, final: final, mode: mode, host: h, resolve: resolve)
                if w == nil || rank(r) > rank(w!) { w = r }
            }
            return w!
        }
        return (worst(anthropicHosts), worst(checkHosts))
    }

    /// Clash modes first (direct / global), then rules.
    public static func evalClash(_ rules: [Rule], mode: String, resolve: Resolver) -> (HostRoute, HostRoute) {
        if mode == "direct" {
            var r = HostRoute(); r.outcome = .direct; r.rule = "mode: direct"; r.chain = ["DIRECT"]
            return (r, r)
        }
        if mode == "global" {
            let (out, chain, unc) = resolve("GLOBAL")
            var r = HostRoute(); r.outcome = out; r.rule = "mode: global"; r.chain = chain; r.uncertain = unc ? true : nil
            return (r, r)
        }
        return evalRules(rules, final: "DIRECT", mode: mode, resolve: resolve)   // Clash: no MATCH => DIRECT
    }

    // MARK: matchers

    static func norm(_ t: String) -> String {
        t.uppercased().replacingOccurrences(of: "-", with: "").replacingOccurrences(of: "_", with: "")
    }

    static func suffix(_ host: String, _ s: String) -> Bool {
        var s = s.lowercased()
        if s.hasPrefix("+.") { s.removeFirst(2) }
        if s.hasPrefix(".") { s.removeFirst() }
        return host == s || host.hasSuffix("." + s)
    }

    static func regex(_ pattern: String, _ s: String) -> Tri {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return .maybe }
        return Tri(re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil)
    }

    static func nameHint(_ name: String, _ t: Target) -> Tri {
        let n = name.lowercased()
        for k in ["anthropic", "claude", "category-ai", "ai-!cn", "ai_!cn"] where n.contains(k) {
            return Tri(t.anthropic)
        }
        if n.contains("!") { return .maybe }
        let domestic: Set<String> = ["cn", "ir", "iran", "china", "private", "lan", "local", "ads", "adblock",
                                     "reject", "domestic", "direct"]
        let tokens = n.split(whereSeparator: { "-_@:./ ".contains($0) }).map(String.init)
        if tokens.contains(where: domestic.contains) { return .no }
        // Lists named after one service never contain Anthropic or the IP-check sites.
        return singleService.contains(n.hasPrefix("geosite-") ? String(n.dropFirst(8)) : n) ? .no : .maybe
    }

    static let singleService = Set("""
        google youtube telegram twitter x facebook instagram meta whatsapp netflix
        spotify openai github microsoft apple icloud amazon aws cloudflare discord reddit tiktok bing gemini
        wikipedia linkedin steam pinterest twitch tumblr yahoo disney hbo hulu primevideo duckduckgo signal
        zoom slack notion figma docker npmjs pypi gitlab bilibili baidu tencent alibaba xiaomi huawei
        """.split(whereSeparator: { $0 == " " || $0 == "\n" }).map(String.init))

    static func port(_ spec: String, _ p: Int) -> Tri {
        for part in spec.split(whereSeparator: { $0 == "/" || $0 == "," }) {
            let bits = part.split(separator: "-").map { Int($0.trimmingCharacters(in: .whitespaces)) }
            if bits.count == 2, let a = bits[0], let b = bits[1], p >= a && p <= b { return .yes }
            if bits.count == 1, bits[0] == p { return .yes }
        }
        return .no
    }

    static func ipCIDR(_ cidr: String, _ t: Target, noResolve: Bool) -> Tri {
        guard let ip = t.ip else { return noResolve ? .no : .maybe }
        let parts = cidr.split(separator: "/")
        guard !cidr.contains(":"), let net = parts.first, let a = ipv4(String(net)), let b = ipv4(ip) else {
            return cidr.contains(":") ? .no : .maybe
        }
        let bits = parts.count > 1 ? Int(parts[1]) ?? 32 : 32
        let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << UInt32(32 - bits)
        return Tri((a & mask) == (b & mask))
    }

    static func ipv4(_ s: String) -> UInt32? {
        let p = s.split(separator: ".").compactMap { UInt32($0) }
        guard p.count == 4, p.allSatisfy({ $0 < 256 }) else { return nil }
        return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]
    }

    static func geoip(_ code: String, _ t: Target, noResolve: Bool) -> Tri {
        let c = code.uppercased()
        if c == "PRIVATE" || c == "LAN" { return .no }
        if let country = t.country { return Tri(c == country) }
        if noResolve || c == "IR" || c == "CN" { return .no }
        return .maybe
    }

    static func process(_ name: String, _ t: Target) -> Tri {
        let n = name.lowercased()
        return t.anthropic ? Tri(n.contains("claude") || n == "node") : Tri(n.contains("claudeguard"))
    }

    static func clashRule(type: String, payload: String, policy: String, params: [String]) -> Rule {
        let nt = norm(type)
        let noResolve = params.contains { $0.trimmingCharacters(in: .whitespaces).lowercased() == "no-resolve" }
        let raw = (nt == "MATCH" || nt == "FINAL") ? "MATCH,\(policy)" : ([type, payload, policy] + params).joined(separator: ",")
        let p = payload
        let m: (Target, String) -> Tri
        switch nt {
        case "DOMAIN": m = { t, _ in Tri(t.host == p.lowercased()) }
        case "DOMAINSUFFIX": m = { t, _ in Tri(suffix(t.host, p)) }
        case "DOMAINKEYWORD": m = { t, _ in Tri(t.host.contains(p.lowercased())) }
        case "DOMAINREGEX": m = { t, _ in regex(p, t.host) }
        case "DOMAINWILDCARD":
            let pat = "^" + NSRegularExpression.escapedPattern(for: p.lowercased())
                .replacingOccurrences(of: "\\*", with: "[^.]*").replacingOccurrences(of: "\\?", with: ".") + "$"
            m = { t, _ in regex(pat, t.host) }
        case "GEOSITE", "RULESET": m = { t, _ in nameHint(p, t) }
        case "GEOIP": m = { t, _ in geoip(p, t, noResolve: noResolve) }
        case "IPCIDR", "IPCIDR6": m = { t, _ in ipCIDR(p, t, noResolve: noResolve) }
        case "DSTPORT": m = { _, _ in port(p, 443) }
        case "NETWORK": m = { _, _ in Tri(p.lowercased() == "tcp") }
        case "PROCESSNAME", "PROCESSPATH", "PROCESSNAMEREGEX", "PROCESSPATHREGEX", "PROCESS": m = { t, _ in process(p, t) }
        case "MATCH", "FINAL": m = { _, _ in .yes }
        default: m = { _, _ in .maybe }   // SRC-*, IN-*, UID, AND/OR/NOT, SUB-RULE ...
        }
        return Rule(raw: raw, match: m, target: policy)
    }

    /// "DOMAIN-SUFFIX,claude.ai,Proxy", "MATCH,DIRECT", "AND,((...),(...)),Proxy"
    public static func parseClashLine(_ line: String) -> Rule? {
        let line = line.trimmingCharacters(in: .whitespaces)
        guard let comma = line.firstIndex(of: ",") else { return nil }
        let type = String(line[..<comma]).trimmingCharacters(in: .whitespaces)
        var rest = String(line[line.index(after: comma)...])
        if norm(type) == "MATCH" || norm(type) == "FINAL" {
            return clashRule(type: type, payload: "", policy: rest.trimmingCharacters(in: .whitespaces), params: [])
        }
        var payload: String
        if rest.trimmingCharacters(in: .whitespaces).hasPrefix("(") {
            var depth = 0
            var end: String.Index?
            for i in rest.indices {
                if rest[i] == "(" { depth += 1 } else if rest[i] == ")" { depth -= 1; if depth == 0 { end = i; break } }
            }
            guard let end else { return nil }
            payload = String(rest[...end])
            rest = String(rest[rest.index(after: end)...])
            if rest.hasPrefix(",") { rest.removeFirst() }
        } else {
            let parts = rest.split(separator: ",", maxSplits: 1, omittingEmptySubsequences: false)
            payload = String(parts[0])
            rest = parts.count > 1 ? String(parts[1]) : ""
        }
        let parts = rest.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard let policy = parts.first, !policy.isEmpty else { return nil }
        return clashRule(type: type, payload: payload.trimmingCharacters(in: .whitespaces), policy: policy,
                         params: Array(parts.dropFirst()))
    }
}

// MARK: - Clash config (YAML subset)

public struct ClashFile {
    public var controller: String?
    public var secret: String?
    public var mode = "rule"
    public var tun = false
    public var ports: [Int] = []
    public var rules: [String] = []
    public var groups: [String: [String]] = [:]

    /// Reads the parts of a Clash/mihomo YAML config ClaudeGuard needs.
    public static func parse(_ text: String) -> ClashFile {
        var f = ClashFile()
        var section = ""
        var group: String?
        var inGroupProxies = false
        func unquote(_ s: Substring) -> String {
            var v = s.trimmingCharacters(in: .whitespaces)
            if let hash = v.range(of: " #") { v = String(v[..<hash.lowerBound]) }
            if v.count >= 2, let f = v.first, (f == "\"" || f == "'"), v.last == f { v = String(v.dropFirst().dropLast()) }
            return v
        }
        func flowList(_ s: String) -> [String] {
            guard let a = s.firstIndex(of: "["), let b = s.lastIndex(of: "]"), a < b else { return [] }
            return s[s.index(after: a)..<b].split(separator: ",").map { unquote($0) }.filter { !$0.isEmpty }
        }
        func flowField(_ s: String, _ key: String) -> String? {
            guard let r = s.range(of: "\(key):") else { return nil }
            let rest = s[r.upperBound...]
            if rest.trimmingCharacters(in: .whitespaces).hasPrefix("[") {
                return String(rest[rest.firstIndex(of: "[")!...(rest.firstIndex(of: "]") ?? rest.endIndex)])
            }
            let end = rest.firstIndex(where: { $0 == "," || $0 == "}" }) ?? rest.endIndex
            return unquote(rest[..<end])
        }

        for rawLine in text.components(separatedBy: .newlines) {
            if rawLine.trimmingCharacters(in: .whitespaces).hasPrefix("#") || rawLine.trimmingCharacters(in: .whitespaces).isEmpty { continue }
            let indent = rawLine.prefix(while: { $0 == " " }).count
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if indent == 0 {
                group = nil
                inGroupProxies = false
                guard let colon = line.firstIndex(of: ":") else { continue }
                let key = String(line[..<colon])
                let value = unquote(line[line.index(after: colon)...])
                section = key
                switch key {
                case "external-controller": f.controller = value
                case "secret": f.secret = value
                case "mode": f.mode = value.lowercased()
                case "mixed-port", "port", "socks-port": if let p = Int(value), p > 0 { f.ports.append(p) }
                default: break
                }
                continue
            }
            switch section {
            case "tun":
                if line.hasPrefix("enable:") { f.tun = unquote(line.dropFirst("enable:".count)) == "true" }
            case "rules":
                if line.hasPrefix("- ") { f.rules.append(unquote(line.dropFirst(2))) }
            case "proxy-groups":
                if line.hasPrefix("- {") || line.hasPrefix("-{") {        // flow style
                    if let name = flowField(line, "name") {
                        f.groups[name] = flowList(flowField(line, "proxies") ?? "")
                    }
                    group = nil
                } else if line.hasPrefix("- name:") {
                    group = unquote(line.dropFirst("- name:".count))
                    f.groups[group!] = []
                    inGroupProxies = false
                } else if let g = group, line.hasPrefix("name:") == false {
                    if line.hasPrefix("proxies:") {
                        let rest = String(line.dropFirst("proxies:".count))
                        if rest.contains("[") { f.groups[g] = flowList(rest); inGroupProxies = false } else { inGroupProxies = true }
                    } else if inGroupProxies && line.hasPrefix("- ") {
                        f.groups[g, default: []].append(unquote(line.dropFirst(2)))
                    } else if line.contains(":") {
                        inGroupProxies = false
                    }
                }
            default: break
            }
        }
        return f
    }

    /// Without the API the selected member of a group is unknown: a group that can
    /// select DIRECT (directly or through sub-groups) is uncertain.
    public func resolver() -> RuleEngine.Resolver {
        let groups = self.groups
        func hasDirect(_ n: String, _ depth: Int) -> Bool {
            if n.uppercased() == "DIRECT" { return true }
            if depth > 8 { return false }
            return (groups[n] ?? []).contains { hasDirect($0, depth + 1) }
        }
        return { name in
            switch name.uppercased() {
            case "DIRECT": return (.direct, [name], false)
            case "REJECT", "REJECT-DROP": return (.reject, [name], false)
            default: break
            }
            if let members = groups[name] {
                if hasDirect(name, 0) { return (.unknown, [name], true) }
                if let first = members.first { return (.proxy, [name, first + "?"], false) }
            }
            return (.proxy, [name], false)
        }
    }
}

// MARK: - Clash API

struct ClashAPI {
    let base: String
    let secret: String?

    init?(_ addr: String?, secret: String?) {
        guard var a = addr?.trimmingCharacters(in: .whitespaces), !a.isEmpty else { return nil }
        if a.hasPrefix(":") { a = "127.0.0.1" + a }
        a = a.replacingOccurrences(of: "0.0.0.0", with: "127.0.0.1").replacingOccurrences(of: "[::]", with: "127.0.0.1")
        if !a.contains("://") { a = "http://" + a }
        while a.hasSuffix("/") { a.removeLast() }
        base = a
        self.secret = (secret?.isEmpty ?? true) ? nil : secret
    }

    var hostPort: String { base.replacingOccurrences(of: "http://", with: "") }

    private static let session: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.connectionProxyDictionary = [:]
        cfg.timeoutIntervalForRequest = 1.5
        cfg.timeoutIntervalForResource = 2
        return URLSession(configuration: cfg)
    }()

    enum APIError: Error { case unauthorized, failed }

    func get(_ path: String) async throws -> Any {
        guard let url = URL(string: base + path) else { throw APIError.failed }
        var req = URLRequest(url: url)
        if let secret { req.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization") }
        let (data, resp) = try await Self.session.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        if code == 401 { throw APIError.unauthorized }
        guard code == 200 else { throw APIError.failed }
        return try JSONSerialization.jsonObject(with: data)
    }

    struct State {
        var version = ""
        var mode: String?
        var tun = false
        var ports: [Int] = []
        var proxies: [String: [String: Any]]?
        var rules: [RuleEngine.Rule]?
        var liveDirect: [String] = []
    }

    func fetch() async throws -> State {
        var st = State()
        let ver = try await get("/version") as? [String: Any]
        st.version = ver?["version"] as? String ?? ""
        if let cfg = try? await get("/configs") as? [String: Any] {
            st.mode = (cfg["mode"] as? String)?.lowercased()
            st.tun = ((cfg["tun"] as? [String: Any])?["enable"] as? Bool) ?? false
            st.ports = ["mixed-port", "port", "socks-port"].compactMap { cfg[$0] as? Int }.filter { $0 > 0 }
        }
        if let px = try? await get("/proxies") as? [String: Any] {
            st.proxies = px["proxies"] as? [String: [String: Any]]
        }
        if let r = try? await get("/rules") as? [String: Any], let list = r["rules"] as? [[String: Any]], !list.isEmpty {
            st.rules = list.map {
                RuleEngine.clashRule(type: $0["type"] as? String ?? "", payload: $0["payload"] as? String ?? "",
                                     policy: $0["proxy"] as? String ?? "", params: [])
            }
        }
        if let c = try? await get("/connections") as? [String: Any], let conns = c["connections"] as? [[String: Any]] {
            for conn in conns {
                let md = conn["metadata"] as? [String: Any] ?? [:]
                let host = ((md["host"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? md["sniffHost"] as? String ?? "").lowercased()
                let isClaude = md["destinationIP"] as? String == NetInfo.anthropicProbeIP
                    || ["anthropic.com", "claude.ai", "claude.com"].contains { RuleEngine.suffix(host, $0) }
                if isClaude, let chains = conn["chains"] as? [String], chains.first?.uppercased() == "DIRECT" {
                    st.liveDirect.append(host)
                }
            }
        }
        return st
    }

    static func resolver(_ proxies: [String: [String: Any]]) -> RuleEngine.Resolver {
        return { start in
            var name = start
            var chain: [String] = []
            for _ in 0..<16 {
                chain.append(name)
                switch name.uppercased() {
                case "DIRECT": return (.direct, chain, false)
                case "REJECT", "REJECT-DROP", "BLOCK": return (.reject, chain, false)
                default: break
                }
                guard let p = proxies[name] else { return (.proxy, chain, true) }
                let type = (p["type"] as? String ?? "").lowercased()
                switch type {
                case "direct": return (.direct, chain, false)
                case "reject", "rejectdrop", "block": return (.reject, chain, false)
                case "selector", "urltest", "fallback", "loadbalance", "smart":
                    guard let now = p["now"] as? String, !now.isEmpty else { return (.unknown, chain, true) }
                    name = now
                case "pass": return (.unknown, chain, true)
                default: return (.proxy, chain, false)
                }
            }
            return (.unknown, chain, true)
        }
    }
}

// MARK: - sing-box config

public enum SingBox {
    static func strings(_ v: Any?) -> [String] {
        if let s = v as? String { return [s] }
        return (v as? [Any])?.compactMap { $0 as? String } ?? []
    }

    public static func rule(_ r: [String: Any]) -> RuleEngine.Rule {
        let raw = (try? JSONSerialization.data(withJSONObject: r, options: [.sortedKeys]))
            .map { String(decoding: $0, as: UTF8.self) } ?? "{}"
        var rule = RuleEngine.Rule(raw: raw, match: { _, _ in .no }, target: nil)
        switch r["action"] as? String ?? "" {
        case "", "route": rule.target = r["outbound"] as? String
        case "reject": rule.reject = true
        default: return rule   // sniff / resolve / hijack-dns / route-options
        }
        if r["type"] as? String == "logical" {
            rule.match = { _, _ in .maybe }
            return rule
        }
        let invert = r["invert"] as? Bool ?? false
        rule.match = { t, mode in
            var dest: [Tri] = []
            dest += strings(r["domain"]).map { Tri(t.host == $0.lowercased()) }
            dest += strings(r["domain_suffix"]).map { $0.hasPrefix(".") ? Tri(t.host.hasSuffix($0.lowercased())) : Tri(RuleEngine.suffix(t.host, $0)) }
            dest += strings(r["domain_keyword"]).map { Tri(t.host.contains($0.lowercased())) }
            dest += strings(r["domain_regex"]).map { RuleEngine.regex($0, t.host) }
            dest += (strings(r["geosite"]) + strings(r["rule_set"])).map { RuleEngine.nameHint($0, t) }
            dest += strings(r["geoip"]).map { RuleEngine.geoip($0, t, noResolve: false) }
            dest += strings(r["ip_cidr"]).map { RuleEngine.ipCIDR($0, t, noResolve: false) }
            if r["ip_is_private"] as? Bool == true { dest.append(.no) }
            var res: Tri = dest.isEmpty ? .yes : (dest.max() ?? .no)
            func and(_ x: Tri) { if x < res { res = x } }
            for (k, v) in r {
                switch k {
                case "domain", "domain_suffix", "domain_keyword", "domain_regex", "geosite", "rule_set", "geoip",
                     "ip_cidr", "ip_is_private", "outbound", "action", "invert", "type", "rule_set_ip_cidr_match_source":
                    continue
                case "port":
                    let ports = (v as? [Any])?.compactMap { ($0 as? NSNumber)?.intValue } ?? [(v as? NSNumber)?.intValue ?? -1]
                    and(Tri(ports.contains(443)))
                case "port_range": and(Tri(strings(v).contains { RuleEngine.port($0.replacingOccurrences(of: ":", with: "-"), 443) == .yes }))
                case "network": and(Tri(strings(v).contains { $0.lowercased() == "tcp" }))
                case "protocol": and(Tri(strings(v).contains { ["tls", "http"].contains($0.lowercased()) }))
                case "clash_mode": and(mode.isEmpty ? .maybe : Tri("\(v)".lowercased() == mode.lowercased()))
                case "ip_version": and(Tri("\(v)" == "4"))
                case "process_name", "process_path", "process_path_regex":
                    and(Tri(strings(v).contains { RuleEngine.process($0, t) == .yes }))
                default: and(.maybe)
                }
            }
            if invert && res != .maybe { res = res == .yes ? .no : .yes }
            return res
        }
        return rule
    }

    public static func resolver(_ outbounds: [[String: Any]], api: [String: [String: Any]]?) -> RuleEngine.Resolver {
        var obs: [String: [String: Any]] = [:]
        for o in outbounds { if let tag = o["tag"] as? String { obs[tag] = o } }
        return { start in
            var name = start
            var chain: [String] = []
            for _ in 0..<16 {
                chain.append(name)
                guard let o = obs[name] else { return (.unknown, chain, true) }
                switch o["type"] as? String ?? "" {
                case "direct": return (.direct, chain, false)
                case "block": return (.reject, chain, false)
                case "dns": return (.unknown, chain, true)
                case "selector", "urltest":
                    if let now = api?[name]?["now"] as? String, !now.isEmpty { name = now; continue }
                    let members = strings(o["outbounds"])
                    if members.contains(where: { obs[$0]?["type"] as? String == "direct" }) {
                        return (.unknown, chain, true)   // DIRECT selectable, choice not visible
                    }
                    guard let next = (o["default"] as? String) ?? members.first else { return (.unknown, chain, true) }
                    name = next
                default:
                    if let lf = Xray.localForward(o["type"] as? String ?? "", ["address": o["server"] ?? "", "port": o["server_port"] ?? 0]) {
                        chain.append(lf)
                    }
                    return (.proxy, chain, false)
                }
            }
            return (.unknown, chain, true)
        }
    }
}

// MARK: - Detection

public struct ConfigCandidate {
    public var kind: String
    public var path: String
    public init(kind: String, path: String) { self.kind = kind; self.path = path }
}

public struct AppDecision {
    public var tunDirect: ProxyApp?
    public var proxyDirect: ProxyApp?
    public var misrouted: ProxyApp?
}

public enum ProxyApps {
    public static let defaultAPIs = ["127.0.0.1:9090", "127.0.0.1:9097", "127.0.0.1:16756"]

    /// Home folder of the user logged in at the console (the daemon runs as root).
    public static func consoleUserHome() -> String {
        var uid: uid_t = 0
        if let name = SCDynamicStoreCopyConsoleUser(nil, &uid, nil) as String?, name != "loginwindow",
           let home = FileManager.default.homeDirectory(forUser: name) {
            return home.path
        }
        return NSHomeDirectory()
    }

    public struct ProcInfo {
        public var running: Set<String> = []        // "clash" / "sing-box" / "xray"
        public var configs: [ConfigCandidate] = []
    }

    /// Running Clash / sing-box / Xray / V2Ray processes and the config paths their
    /// command lines name (exact argv via KERN_PROCARGS2; relative paths resolved
    /// against the process's working directory and executable folder).
    public static func processes() -> ProcInfo {
        var info = ProcInfo()
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return info }
        var pids = [pid_t](repeating: 0, count: Int(count) + 64)
        let n = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
        for pid in pids.prefix(Int(max(n, 0))) where pid > 0 {
            guard let (exe, args) = argv(pid), let kind = Xray.procKind(exe) else { continue }
            info.running.insert(kind)
            let exeDir = (exe as NSString).deletingLastPathComponent
            var bases: [String] = []
            if let cwd = cwd(pid), cwd != "/" { bases.append(cwd) }
            bases += [exeDir, (exeDir as NSString).deletingLastPathComponent]
            info.configs += Xray.configArgs(kind: kind, args: args, bases: bases)
        }
        return info
    }

    static func argv(_ pid: pid_t) -> (String, [String])? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return nil }
        var buf = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0, size > 4 else { return nil }
        let argc = Int(buf.withUnsafeBytes { $0.load(as: Int32.self) })
        var i = 4
        func cstr() -> String {
            let start = i
            while i < size && buf[i] != 0 { i += 1 }
            return String(decoding: buf[start..<i], as: UTF8.self)
        }
        let exe = cstr()
        while i < size && buf[i] == 0 { i += 1 }
        var args: [String] = []
        while args.count < argc && i < size {
            args.append(cstr())
            i += 1
        }
        return (exe, args)
    }

    static func cwd(_ pid: pid_t) -> String? {
        var vpi = proc_vnodepathinfo()
        let sz = Int32(MemoryLayout<proc_vnodepathinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vpi, sz) == sz else { return nil }
        return withUnsafeBytes(of: vpi.pvi_cdir.vip_path) { raw in
            String(cString: raw.bindMemory(to: CChar.self).baseAddress!)
        }
    }

    /// Well-known config locations. "json" files are sing-box or Xray/V2Ray, decided by content.
    public static func candidates(home: String) -> [ConfigCandidate] {
        let mac = home + "/Library/Application Support"
        var c: [ConfigCandidate] = [
            .init(kind: "clash", path: home + "/.config/mihomo/config.yaml"),
            .init(kind: "clash", path: home + "/.config/clash.meta/config.yaml"),
            .init(kind: "clash", path: home + "/.config/clash/config.yaml"),
            .init(kind: "clash", path: mac + "/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml"),
            .init(kind: "clash", path: mac + "/io.github.clash-verge-rev.clash-verge-rev/config.yaml"),
            .init(kind: "clash", path: mac + "/v2rayN/binConfigs/config.yaml"),
        ]
        var json = [
            home + "/.config/sing-box/config.json",
            home + "/.config/xray/config.json",
            home + "/.config/v2ray/config.json",
            home + "/.config/qv2ray/vcore/config.gen.json",
            home + "/.V2rayU/config.json",
            mac + "/app.hiddify.com/data/current-config.json",
            mac + "/v2rayN/binConfigs/config.json", mac + "/v2rayN/binConfigs/configPre.json",
            mac + "/v2rayN/guiConfigs/config.json", mac + "/v2rayN/guiConfigs/configPre.json",
            mac + "/V2RayXS/config.json",
            mac + "/qv2ray/vcore/config.gen.json",
            home + "/.local/share/v2rayN/binConfigs/config.json",
        ]
        for dir in ["/usr/local/etc", "/opt/homebrew/etc", "/etc"] {
            for app in ["sing-box", "xray", "v2ray"] { json.append("\(dir)/\(app)/config.json") }
        }
        c += json.map { ConfigCandidate(kind: "json", path: $0) }
        return c
    }

    /// Finds Clash / sing-box / Xray instances and works out how they route Claude.
    public static func detect(_ cands: [ConfigCandidate], running: (String) -> Bool,
                              probeDefaults: Bool = true) async -> [ProxyApp] {
        var apps: [ProxyApp] = []
        var seenAPI = Set<String>()
        var seenPath = Set<String>()
        for c in cands {
            let path = (c.path as NSString).standardizingPath
            if seenPath.contains(path) { continue }
            seenPath.insert(path)
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else { continue }
            var app: ProxyApp?
            if isDir.boolValue {   // xray -confdir
                if let cfg = Xray.load(path), !(cfg["outbounds"] as? [Any] ?? []).isEmpty {
                    app = Xray.evaluate(path: c.path, cfg)
                }
            } else {
                guard let data = FileManager.default.contents(atPath: path), !data.isEmpty else { continue }
                let kind = c.kind == "clash" ? "clash" : Xray.jsonKind(data)
                if kind == "clash" {
                    let f = ClashFile.parse(String(decoding: data, as: UTF8.self))
                    if f.rules.isEmpty && f.controller == nil { continue }
                    app = await evalClash(c.path, f, &seenAPI)
                } else if kind == "xray" {
                    if let cfg = Xray.load(path), !(cfg["outbounds"] as? [Any] ?? []).isEmpty {
                        app = Xray.evaluate(path: c.path, cfg)
                    }
                } else if kind == "sing-box", let obj = Xray.object(data),
                          let outbounds = obj["outbounds"] as? [[String: Any]], !outbounds.isEmpty {
                    app = await evalSingBox(c.path, obj, outbounds, &seenAPI)
                }
            }
            guard let a = app else { continue }
            if !a.live && !running(a.kind) { continue }   // config of an app that isn't running
            apps.append(a)
        }
        guard probeDefaults else { Xray.linkLocalForwards(&apps); return apps }
        for addr in defaultAPIs where !seenAPI.contains(addr) {
            guard let api = ClashAPI(addr, secret: nil), let st = try? await api.fetch() else { continue }
            seenAPI.insert(addr)
            let kind = st.version.lowercased().contains("sing-box") ? "sing-box" : "clash"
            var app = ProxyApp(kind: kind, source: "API \(api.base)", live: true, mode: st.mode, tun: st.tun,
                               ports: st.ports, anthropic: HostRoute(), check: HostRoute(),
                               liveDirect: st.liveDirect.isEmpty ? nil : st.liveDirect)
            if st.rules == nil && st.mode != "global" && st.mode != "direct" {
                app.note = "rules not available from the API (no config file found)"
                app.anthropic.uncertain = true
                app.check = app.anthropic
            } else {
                (app.anthropic, app.check) = RuleEngine.evalClash(st.rules ?? [], mode: st.mode ?? "rule",
                                                                  resolve: ClashAPI.resolver(st.proxies ?? [:]))
            }
            apps.append(app)
        }
        Xray.linkLocalForwards(&apps)
        return apps
    }

    static func evalClash(_ path: String, _ f: ClashFile, _ seenAPI: inout Set<String>) async -> ProxyApp {
        var app = ProxyApp(kind: "clash", source: path, live: false, mode: f.mode, tun: f.tun, ports: f.ports,
                           anthropic: HostRoute(), check: HostRoute())
        var rules = f.rules.compactMap(RuleEngine.parseClashLine)
        var resolve = f.resolver()
        if let api = ClashAPI(f.controller, secret: f.secret) {
            do {
                let st = try await api.fetch()
                seenAPI.insert(api.hostPort)
                app.live = true
                app.source = "\(path) + API \(api.base)"
                if let m = st.mode { app.mode = m }
                app.tun = f.tun || st.tun
                if !st.ports.isEmpty { app.ports = st.ports }
                if let r = st.rules { rules = r }
                if let p = st.proxies { resolve = ClashAPI.resolver(p) }
                if !st.liveDirect.isEmpty { app.liveDirect = st.liveDirect }
            } catch ClashAPI.APIError.unauthorized {
                app.note = "API \(api.base): API needs the secret"
            } catch {
                app.note = "API \(api.base): not reachable"
            }
        }
        (app.anthropic, app.check) = RuleEngine.evalClash(rules, mode: app.mode ?? "rule", resolve: resolve)
        return app
    }

    static func evalSingBox(_ path: String, _ obj: [String: Any], _ outbounds: [[String: Any]],
                            _ seenAPI: inout Set<String>) async -> ProxyApp {
        let clashAPI = (obj["experimental"] as? [String: Any])?["clash_api"] as? [String: Any]
        var app = ProxyApp(kind: "sing-box", source: path, live: false,
                           mode: (clashAPI?["default_mode"] as? String)?.lowercased(), tun: false, ports: [],
                           anthropic: HostRoute(), check: HostRoute())
        for inb in obj["inbounds"] as? [[String: Any]] ?? [] {
            switch inb["type"] as? String {
            case "tun": app.tun = true
            case "mixed", "http", "socks": if let p = inb["listen_port"] as? Int { app.ports?.append(p) }
            default: break
            }
        }
        var apiProxies: [String: [String: Any]]?
        if let api = ClashAPI(clashAPI?["external_controller"] as? String, secret: clashAPI?["secret"] as? String) {
            if let st = try? await api.fetch() {
                seenAPI.insert(api.hostPort)
                app.live = true
                app.source = "\(path) + API \(api.base)"
                if let m = st.mode { app.mode = m }
                apiProxies = st.proxies
                if !st.liveDirect.isEmpty { app.liveDirect = st.liveDirect }
            } else {
                app.note = "API \(api.base): not reachable"
            }
        }
        let route = obj["route"] as? [String: Any] ?? [:]
        let rules = (route["rules"] as? [[String: Any]] ?? []).map(SingBox.rule)
        let final = (route["final"] as? String) ?? (outbounds.first?["tag"] as? String ?? "")
        (app.anthropic, app.check) = RuleEngine.evalRules(rules, final: final, mode: app.mode ?? "",
                                                          resolve: SingBox.resolver(outbounds, api: apiProxies))
        return app
    }

    /// Relates the apps to the routes in use (same logic as the Windows version).
    public static func decide(_ apps: [ProxyApp], anthropicInTunnel: Bool, desktopProxy: String?) -> AppDecision {
        var d = AppDecision()
        for a in apps {
            let viaTUN = a.tun == true && anthropicInTunnel
            let viaProxy = a.servesPort(desktopProxy)
            let live = !(a.liveDirect ?? []).isEmpty
            if a.sendsClaudeDirect {
                if (viaTUN || live) && d.tunDirect == nil { d.tunDirect = a }
                if (viaProxy || live) && d.proxyDirect == nil { d.proxyDirect = a }
            }
            if a.checkMisrouted && (viaTUN || viaProxy) && d.misrouted == nil { d.misrouted = a }
        }
        return d
    }

    /// The physical (non-tunnel) interface with a default route, e.g. "en0".
    public static func physicalInterface() -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
        p.arguments = ["-rn", "-f", "inet"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return nil }
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        for line in out.split(separator: "\n") {
            let cols = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard cols.first == "default", cols.count >= 4 else { continue }
            let iface = cols[3]
            if !NetInfo.isTunnel(iface) && !iface.hasPrefix("lo") { return iface }
        }
        return nil
    }
}
