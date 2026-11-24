import Foundation

// Xray-core / V2Ray (v4 JSON format) routing: used by v2rayN, V2rayU, V2RayXS, Qv2ray
// and plain xray/v2ray. Xray has no Clash-style HTTP API, so the config file is the
// source of truth (its routing doesn't change at runtime, except balancers).
// Same logic as windows/internal/core/xray.go.

public enum Xray {
    /// Removes // and /* */ comments (and "#" comment lines) outside strings: xray accepts JSONC.
    public static func stripComments(_ data: Data) -> Data {
        let b = [UInt8](data)
        var out: [UInt8] = []
        out.reserveCapacity(b.count)
        var inStr = false, esc = false
        var i = 0
        let slash = UInt8(ascii: "/"), star = UInt8(ascii: "*"), quote = UInt8(ascii: "\""),
            bs = UInt8(ascii: "\\"), nl = UInt8(ascii: "\n"), hash = UInt8(ascii: "#")
        while i < b.count {
            let c = b[i]
            if inStr {
                out.append(c)
                if esc { esc = false } else if c == bs { esc = true } else if c == quote { inStr = false }
                i += 1
                continue
            }
            if c == quote { inStr = true; out.append(c); i += 1; continue }
            if c == slash, i + 1 < b.count, b[i + 1] == slash {
                while i < b.count && b[i] != nl { i += 1 }
                continue
            }
            if c == slash, i + 1 < b.count, b[i + 1] == star {
                i += 2
                while i + 1 < b.count && !(b[i] == star && b[i + 1] == slash) { i += 1 }
                i += 2
                continue
            }
            if c == hash, out.isEmpty || out.last == nl {
                while i < b.count && b[i] != nl { i += 1 }
                continue
            }
            out.append(c)
            i += 1
        }
        return Data(out)
    }

    static func object(_ data: Data) -> [String: Any]? {
        try? JSONSerialization.jsonObject(with: stripComments(data)) as? [String: Any]
    }

    /// "xray", "sing-box" or nil, decided by the JSON's content.
    public static func jsonKind(_ data: Data) -> String? {
        guard let obj = object(data) else { return nil }
        for key in ["outbounds", "inbounds"] {
            for o in obj[key] as? [[String: Any]] ?? [] {
                if o["protocol"] != nil { return "xray" }
                if o["type"] != nil { return "sing-box" }
            }
        }
        if obj["routing"] != nil { return "xray" }
        if obj["route"] != nil { return "sing-box" }
        return nil
    }

    /// One config file, or every *.json in a directory merged (xray -confdir).
    public static func load(_ path: String) -> [String: Any]? {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else { return nil }
        let files = isDir.boolValue
            ? ((try? FileManager.default.contentsOfDirectory(atPath: path)) ?? [])
                .filter { $0.hasSuffix(".json") }.sorted().map { path + "/" + $0 }
            : [path]
        var merged: [String: Any] = [:]
        var n = 0
        for f in files {
            guard let d = FileManager.default.contents(atPath: f), let o = object(d) else { continue }
            n += 1
            for key in ["inbounds", "outbounds"] {
                merged[key] = (merged[key] as? [[String: Any]] ?? []) + (o[key] as? [[String: Any]] ?? [])
            }
            if let r = o["routing"] { merged["routing"] = r }
            if let r = o["router"] { merged["router"] = r }
        }
        return n == 0 ? nil : merged
    }

    static func port(_ v: Any?) -> Int {
        if let n = v as? NSNumber { return n.intValue }
        if let s = v as? String { return Int(s.trimmingCharacters(in: .whitespaces)) ?? 0 }
        return 0
    }

    static func str(_ v: Any?) -> String {
        if let s = v as? String { return s }
        if let n = v as? NSNumber { return n.stringValue }
        return ""
    }

    static func isLocal(_ a: String) -> Bool {
        let a = a.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        return a == "localhost" || a == "::1" || a.hasPrefix("127.")
    }

    /// "127.0.0.1:PORT" when a socks/http outbound hands traffic to a local app.
    static func localForward(_ proto: String, _ settings: [String: Any]?) -> String? {
        guard proto == "socks" || proto == "http", let s = settings else { return nil }
        var addr = str(s["address"]), p = port(s["port"])
        if let first = (s["servers"] as? [[String: Any]])?.first {
            addr = str(first["address"]); p = port(first["port"])
        }
        return p != 0 && isLocal(addr) ? "127.0.0.1:\(p)" : nil
    }

    public static func localForwardPort(_ elem: String) -> Int? {
        guard elem.hasPrefix("127.0.0.1:") else { return nil }
        return Int(elem.dropFirst("127.0.0.1:".count))
    }

    static func resolver(_ cfg: [String: Any]) -> RuleEngine.Resolver {
        let outbounds = cfg["outbounds"] as? [[String: Any]] ?? []
        var obs: [String: [String: Any]] = [:]
        for o in outbounds { let t = str(o["tag"]); if obs[t] == nil { obs[t] = o } }
        let routing = cfg["routing"] as? [String: Any] ?? [:]
        var bals: [String: [String: Any]] = [:]
        for b in routing["balancers"] as? [[String: Any]] ?? [] { bals[str(b["tag"])] = b }
        let def = outbounds.first.map { str($0["tag"]) }

        func one(_ tag: String, _ chainIn: [String], _ depth: Int) -> (Outcome, [String], Bool) {
            var chain = chainIn
            if tag.hasPrefix("balancer:") {
                let name = String(tag.dropFirst("balancer:".count))
                chain.append("balancer \(name)")
                guard let b = bals[name], depth <= 4 else { return (.unknown, chain, true) }
                let selector = (b["selector"] as? [String]) ?? []
                var members = outbounds.map { str($0["tag"]) }.filter { t in selector.contains { t.hasPrefix($0) } }
                if let fb = b["fallbackTag"] as? String, !fb.isEmpty { members.append(fb) }
                guard !members.isEmpty else { return (.unknown, chain, true) }
                var first: [String] = []
                for (i, m) in members.enumerated() {
                    let (out, c, unc) = one(m, [], depth + 1)
                    if out != .proxy || unc { return (.unknown, chain, true) }   // may pick DIRECT / unknown
                    if i == 0 { first = c }
                }
                return (.proxy, chain + first, false)
            }
            guard let o = obs[tag] else {
                // xray sends traffic for a missing outbound tag to the default (first) outbound.
                if let def, tag != def, depth < 4 { return one(def, chain + ["\(tag)(missing)"], depth + 1) }
                return (.unknown, chain + [tag], true)
            }
            let proto = str(o["protocol"]).lowercased()
            let settings = o["settings"] as? [String: Any]
            switch proto {
            case "freedom":
                return (.direct, chain + [settings?["fragment"] != nil ? "\(tag) (fragment)" : tag], false)
            case "blackhole": return (.reject, chain + [tag], false)
            case "dns", "loopback": return (.unknown, chain + [tag], true)
            default:
                chain.append(tag)
                if let lf = localForward(proto, settings) { chain.append(lf) }
                return (.proxy, chain, false)
            }
        }
        return { one($0, [], 0) }
    }

    /// Inbounds ordinary traffic (Claude's) can arrive on.
    static func userInbounds(_ cfg: [String: Any]) -> Set<String> {
        var s = Set<String>()
        for i in cfg["inbounds"] as? [[String: Any]] ?? [] {
            switch str(i["protocol"]).lowercased() {
            case "socks", "http", "mixed", "tun": s.insert(str(i["tag"]))
            case "dokodemo-door", "tunnel":
                if (i["settings"] as? [String: Any])?["followRedirect"] as? Bool == true { s.insert(str(i["tag"])) }
            default: break
            }
        }
        return s
    }

    static func domainTri(_ d: String, _ t: RuleEngine.Target) -> Tri {
        let ld = d.lowercased()
        func after(_ p: String) -> String { String(d.dropFirst(p.count)) }
        if ld.hasPrefix("domain:") { return Tri(RuleEngine.suffix(t.host, after("domain:"))) }
        if ld.hasPrefix("full:") { return Tri(t.host == after("full:").lowercased()) }
        if ld.hasPrefix("regexp:") { return RuleEngine.regex(after("regexp:"), t.host) }
        if ld.hasPrefix("keyword:") { return Tri(t.host.contains(after("keyword:").lowercased())) }
        if ld.hasPrefix("dotless:") { return Tri(!t.host.contains(".") && t.host.contains(after("dotless:").lowercased())) }
        if ld.hasPrefix("geosite:") {
            let name = after("geosite:").lowercased().split(separator: "@").first.map(String.init) ?? ""
            return RuleEngine.nameHint(name, t)
        }
        if ld.hasPrefix("ext:") {
            return RuleEngine.nameHint(ld.split(separator: ":", maxSplits: 2).last.map(String.init) ?? "", t)
        }
        return Tri(t.host.contains(ld))   // plain string = keyword
    }

    static func ipTri(_ e: String, _ t: RuleEngine.Target, resolve: Bool) -> Tri {
        if !resolve { return .no }   // destination is a domain: IP rules don't apply (AsIs)
        let le = e.lowercased()
        if le.hasPrefix("geoip:") {
            var code = String(le.dropFirst("geoip:".count))
            let invert = code.hasPrefix("!")
            if invert { code.removeFirst() }
            let r = RuleEngine.geoip(code, t, noResolve: false)
            return invert && r != .maybe ? (r == .yes ? .no : .yes) : r
        }
        if le.hasPrefix("ext:") {
            return RuleEngine.nameHint(le.split(separator: ":", maxSplits: 2).last.map(String.init) ?? "", t)
        }
        return RuleEngine.ipCIDR(e, t, noResolve: false)
    }

    static func rule(_ r: [String: Any], userIn: Set<String>, resolveIP: Bool) -> RuleEngine.Rule {
        let raw = (try? JSONSerialization.data(withJSONObject: r, options: [.sortedKeys]))
            .map { String(decoding: $0, as: UTF8.self) } ?? "{}"
        var rule = RuleEngine.Rule(raw: raw, match: { _, _ in .no }, target: nil)
        if let tag = r["outboundTag"] as? String, !tag.isEmpty {
            rule.target = tag
        } else if let b = r["balancerTag"] as? String, !b.isEmpty {
            rule.target = "balancer:" + b
        } else {
            return rule
        }
        if r["enabled"] as? Bool == false { rule.target = nil; return rule }
        rule.match = { t, _ in
            var res = Tri.yes
            func and(_ x: Tri) { if x < res { res = x } }
            for (k, v) in r {
                switch k {
                case "type", "outboundTag", "balancerTag", "ruleTag", "tag", "enabled", "remarks", "domainMatcher", "id", "locked":
                    continue
                case "domain", "domains": and(SingBox.strings(v).map { domainTri($0, t) }.max() ?? .no)
                case "ip": and(SingBox.strings(v).map { ipTri($0, t, resolve: resolveIP) }.max() ?? .no)
                case "port": and(RuleEngine.port(str(v), 443))
                case "network": and(Tri(str(v).lowercased().contains("tcp")))
                case "protocol": and(Tri(SingBox.strings(v).contains { ["tls", "http"].contains($0.lowercased()) }))
                case "inboundTag":
                    let listed = Set(SingBox.strings(v))
                    if listed.isDisjoint(with: userIn) { and(.no) } else if !userIn.isSubset(of: listed) { and(.maybe) }
                case "process": and(Tri(SingBox.strings(v).contains { RuleEngine.process($0, t) == .yes }))
                default: and(.maybe)   // source, sourcePort, user, attrs, ...
                }
            }
            return res
        }
        return rule
    }

    /// Ordered rules for the routing domainStrategy.
    static func rules(_ cfg: [String: Any]) -> [RuleEngine.Rule] {
        guard let routing = cfg["routing"] as? [String: Any] else { return [] }
        let list = routing["rules"] as? [[String: Any]] ?? []
        let userIn = userInbounds(cfg)
        func pass(_ resolve: Bool) -> [RuleEngine.Rule] { list.map { rule($0, userIn: userIn, resolveIP: resolve) } }
        switch str(routing["domainStrategy"]).lowercased() {
        case "ipondemand": return pass(true)
        case "ipifnonmatch": return pass(false) + pass(true)   // no domain match: resolve and retry
        default: return pass(false)                            // AsIs
        }
    }

    public static func evaluate(path: String, _ cfg: [String: Any]) -> ProxyApp {
        var app = ProxyApp(kind: "xray", source: path, live: false, tun: false, ports: [],
                           anthropic: HostRoute(), check: HostRoute())
        for i in cfg["inbounds"] as? [[String: Any]] ?? [] {
            switch str(i["protocol"]).lowercased() {
            case "tun": app.tun = true
            case "socks", "http", "mixed": let p = port(i["port"]); if p != 0 { app.ports?.append(p) }
            default: break
            }
        }
        var cfg = cfg
        if cfg["routing"] == nil, let router = cfg["router"] as? [String: Any] {
            cfg["routing"] = v5Routing(router)   // V2Ray v5 format -> v4 shape
            app.note = "V2Ray v5 config format"
        }
        let outbounds = cfg["outbounds"] as? [[String: Any]] ?? []
        let final = outbounds.first.map { str($0["tag"]) } ?? ""   // no rule matched => first outbound
        (app.anthropic, app.check) = RuleEngine.evalRules(rules(cfg), final: final, mode: "", resolve: resolver(cfg))
        return app
    }

    /// Follows chains between local apps: e.g. v2rayN's TUN (sing-box) forwarding to its
    /// xray SOCKS port, where xray then decides DIRECT / proxy.
    public static func linkLocalForwards(_ apps: inout [ProxyApp]) {
        let snapshot = apps
        func link(_ start: Int, _ route: HostRoute) -> HostRoute {
            var r = route, me = start
            for _ in 0..<4 {
                guard let last = r.chain?.last, let p = localForwardPort(last),
                      let next = snapshot.indices.first(where: { $0 != me && (snapshot[$0].ports ?? []).contains(p) })
                else { return r }
                let nr = RuleEngine.anthropicHosts.contains(r.host) ? snapshot[next].anthropic : snapshot[next].check
                var m = nr
                m.host = r.host
                m.chain = (r.chain ?? []) + (nr.chain ?? [])
                m.rule = "\(r.rule ?? ""); then \(snapshot[next].name): \(nr.rule ?? "")"
                if r.uncertain == true || nr.uncertain == true { m.uncertain = true }
                r = m
                me = next
            }
            return r
        }
        for i in apps.indices {
            apps[i].anthropic = link(i, apps[i].anthropic)
            apps[i].check = link(i, apps[i].check)
        }
    }

    // MARK: - Command lines

    /// "clash" / "sing-box" / "xray" for a proxy core executable, nil otherwise.
    public static func procKind(_ exe: String) -> String? {
        var n = (exe.split(separator: "/").last.map(String.init) ?? exe).lowercased()
        if n.hasSuffix(".exe") { n.removeLast(4) }
        if n.contains("mihomo") || n.contains("clash") || n == "flclash" { return "clash" }
        if ["sing-box", "singbox", "hiddify", "nekobox", "karing"].contains(where: n.contains) { return "sing-box" }
        if n.contains("xray") || ["v2ray", "v2ray-core", "wv2ray", "v2ctl"].contains(n) { return "xray" }
        return nil
    }

    /// Config paths named on a proxy core's command line; relative ones resolved against `bases`.
    public static func configArgs(kind: String, args: [String], bases: [String]) -> [ConfigCandidate] {
        var out: [ConfigCandidate] = []
        func add(_ k: String, _ p: String) {
            let p = p.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            if p.isEmpty || p.hasPrefix("stdin:") || p == "-" { return }
            if p.hasPrefix("/") || bases.isEmpty { out.append(.init(kind: k, path: p)); return }
            for b in bases { out.append(.init(kind: k, path: (b as NSString).appendingPathComponent(p))) }
        }
        let jsonKind = kind == "clash" ? "clash" : "json"
        var i = 1
        while i < args.count {
            let a = args[i]
            i += 1
            guard a.hasPrefix("-") else { continue }
            var flag = a, val: String
            if let eq = a.firstIndex(of: "=") {
                flag = String(a[..<eq]); val = String(a[a.index(after: eq)...])
            } else {
                guard i < args.count else { break }
                val = args[i]
            }
            switch flag.trimmingCharacters(in: CharacterSet(charactersIn: "-")) {
            case "c", "config", "f", "file":
                add(kind == "clash" && val.lowercased().hasSuffix(".json") ? "json" : jsonKind, val)
            case "confdir": add("xray", val)
            case "d", "D", "directory":
                if kind == "clash" { add("clash", val + "/config.yaml") }
                else if kind == "sing-box" { add("json", val + "/config.json") }
            default: break
            }
        }
        return out
    }

    // MARK: - V2Ray v5 format

    /// A protobuf-JSON field by its camelCase or snake_case name.
    static func v5Get(_ m: [String: Any], _ camel: String) -> Any? {
        if let v = m[camel] { return v }
        var snake = ""
        for c in camel { if c.isUppercase { snake += "_" + c.lowercased() } else { snake.append(c) } }
        return m[snake]
    }

    static func v5List(_ v: Any?) -> [Any] {
        guard let v else { return [] }
        return v as? [Any] ?? [v]
    }

    /// {"type": "RootDomain", "value": "ir"} -> "domain:ir"
    static func v5Domain(_ e: Any) -> String? {
        if let s = e as? String { return s }
        guard let m = e as? [String: Any] else { return nil }
        let val = str(m["value"])
        switch str(m["type"]).lowercased() {
        case "regex", "1": return "regexp:" + val
        case "rootdomain", "domain", "2": return "domain:" + val
        case "full", "3": return "full:" + val
        default: return "keyword:" + val   // Plain
        }
    }

    static func v5Code(_ m: [String: Any]) -> String {
        let c = str(v5Get(m, "code"))
        return (c.isEmpty ? str(v5Get(m, "countryCode")) : c).lowercased()
    }

    /// {"ipAddr": "1.2.3.0", "prefix": 24} (or base64 "ip") -> "1.2.3.0/24"
    static func v5CIDR(_ e: Any) -> String {
        guard let m = e as? [String: Any] else { return str(e) }
        var ip = str(v5Get(m, "ipAddr"))
        if ip.isEmpty, let raw = Data(base64Encoded: str(m["ip"])), raw.count == 4 {
            ip = raw.map(String.init).joined(separator: ".")
        }
        if ip.isEmpty { return "?" }   // unreadable: matched as "maybe"
        let p = port(m["prefix"])
        return p != 0 ? "\(ip)/\(p)" : ip
    }

    /// Translates one V2Ray v5 router rule into the v4 rule shape.
    public static func v5Rule(_ r: [String: Any]) -> [String: Any] {
        var out: [String: Any] = [:]
        if !str(r["tag"]).isEmpty { out["outboundTag"] = str(r["tag"]) }
        if !str(v5Get(r, "balancingTag")).isEmpty { out["balancerTag"] = str(v5Get(r, "balancingTag")) }
        var domains = v5List(r["domain"]).compactMap(v5Domain)
        for case let g as [String: Any] in v5List(v5Get(r, "geoDomain")) {
            let code = v5Code(g)
            if !code.isEmpty { domains.append("geosite:" + code) }
            domains += v5List(g["domain"]).compactMap(v5Domain)
        }
        if !domains.isEmpty { out["domain"] = domains }
        var ips: [String] = []
        for case let g as [String: Any] in v5List(r["geoip"]) {
            let inv = v5Get(g, "inverseMatch") as? Bool ?? false
            let code = v5Code(g)
            if !code.isEmpty { ips.append("geoip:" + (inv ? "!" : "") + code) }
            for c in v5List(g["cidr"]) { ips.append(inv ? "?" : v5CIDR(c)) }   // inverted CIDR list -> "maybe"
        }
        ips += v5List(r["cidr"]).map(v5CIDR)
        if !ips.isEmpty { out["ip"] = ips }
        if let pl = v5Get(r, "portList") {
            out["port"] = str(pl)
        } else if let pr = v5Get(r, "portRange") as? [String: Any] {
            out["port"] = "\(port(pr["from"]))-\(port(pr["to"]))"
        }
        if let n = r["networks"] {
            out["network"] = v5List(n).map { x -> String in
                let s = str(x).lowercased()
                return ["1", "2", "rawtcp"].contains(s) ? "tcp" : s
            }.joined(separator: ",")
        }
        let handled: Set<String> = ["tag", "balancingTag", "balancing_tag", "domain", "geoDomain", "geo_domain", "geoip", "cidr",
                                    "portList", "port_list", "portRange", "port_range", "networks", "domainMatcher", "domain_matcher"]
        for (k, v) in r where !handled.contains(k) {
            switch k {
            case "inboundTag", "inbound_tag": out["inboundTag"] = v
            case "protocol": out["protocol"] = v
            default:   // sourceGeoip, sourcePortList, userEmail, attributes ...: can't tell
                if (v as? [Any])?.isEmpty == true || (v as? String)?.isEmpty == true || v is NSNull { continue }
                out[k] = v
            }
        }
        return out
    }

    /// A V2Ray v5 "router" object as a v4 "routing" object.
    public static func v5Routing(_ r: [String: Any]) -> [String: Any] {
        let strategy: String
        switch str(v5Get(r, "domainStrategy")).lowercased() {
        case "useip", "1", "ipondemand", "3": strategy = "IPOnDemand"   // resolved before / at the first IP rule
        case "ipifnonmatch", "2": strategy = "IPIfNonMatch"
        default: strategy = "AsIs"
        }
        let rules = v5List(r["rule"]).compactMap { ($0 as? [String: Any]).map(v5Rule) }
        let bals = v5List(v5Get(r, "balancingRule")).compactMap { x -> [String: Any]? in
            guard let m = x as? [String: Any] else { return nil }
            return ["tag": str(m["tag"]), "selector": v5Get(m, "outboundSelector") as? [String] ?? [],
                    "fallbackTag": str(v5Get(m, "fallbackTag"))]
        }
        return ["domainStrategy": strategy, "rules": rules, "balancers": bals]
    }
}
