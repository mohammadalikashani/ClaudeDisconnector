import Foundation

// Shadowrocket, Stash, Surge, Quantumult X, Loon and Egern: Apple-only proxy apps (no Windows
// versions). They run as a VPN (Network Extension / Surge Enhanced Mode), i.e. TUN.
//
//  - Shadowrocket: Surge-style .conf files ([General] / [Rule] / [Proxy Group] ...).
//    Policies: DIRECT, REJECT*, PROXY (the server picked in the app) and groups.
//  - Stash: Clash-format YAML profiles, read with the Clash parser.
//
// Their files live in sandbox / group containers (or iCloud Drive). Which profile is
// active is kept in the app's private settings, so the most recently modified one is
// taken (and said so in the note). Reading containers needs Full Disk Access.

public enum AppleApps {
    /// Folders where the apps keep their files.
    public static func roots(home: String) -> [String] {
        let lib = home + "/Library"
        return [lib + "/Containers", lib + "/Group Containers", lib + "/Mobile Documents", lib + "/Application Support"]
    }

    static func newest(in dirs: [String], ext: [String], accept: (String, Data) -> Bool) -> (String, Int)? {
        var best: (path: String, date: Date)?
        var count = 0
        var seen = Set<String>()   // dirs overlap (a folder and its subfolders)
        for d in dirs {
            GUIApps.walk(d, depth: 6) { p in
                guard seen.insert(p).inserted, ext.contains((p as NSString).pathExtension.lowercased()),
                      let attrs = try? FileManager.default.attributesOfItem(atPath: p),
                      let mtime = attrs[.modificationDate] as? Date, (attrs[.size] as? Int ?? 0) < 8 << 20,
                      let data = FileManager.default.contents(atPath: p), accept(p, data) else { return }
                count += 1
                if best == nil || mtime > best!.date { best = (p, mtime) }
            }
        }
        return best.map { ($0.path, count) }
    }

    // MARK: Shadowrocket

    public static func shadowrocketCandidates(_ roots: [String]) -> [ConfigCandidate] {
        let dirs = GUIApps.findAppDirs(roots, ["shadowrocket"])
        guard let (path, n) = newest(in: dirs, ext: ["conf"], accept: { _, d in
            let t = String(decoding: d, as: UTF8.self)
            return t.contains("[Rule]") || t.contains("[General]")
        }) else { return [] }
        var c = ConfigCandidate(kind: "surge", path: path, app: "Shadowrocket")
        c.tun = true
        c.note = n > 1 ? "newest of \(n) configs assumed active" : nil
        return [c]
    }

    // MARK: Surge (Mac) - same .conf format, plus an HTTP API for the live state

    public static func surgeCandidates(_ roots: [String]) -> [ConfigCandidate] {
        let dirs = GUIApps.findAppDirs(roots, ["nssurge", "surge-mac", "surge"]).filter { !$0.lowercased().contains("shadowrocket") }
        guard let (path, n) = newest(in: dirs, ext: ["conf"], accept: { _, d in
            let t = String(decoding: d, as: UTF8.self)
            return t.contains("[Rule]") || t.contains("[General]")
        }) else { return [] }
        var c = ConfigCandidate(kind: "surge", path: path, app: "Surge")
        c.note = n > 1 ? "newest of \(n) profiles assumed active" : nil
        return [c]
    }

    /// The parts of a Surge-style config ClaudeGuard needs.
    public struct SurgeFile {
        public var rules: [String] = []
        public var groups: [String: [String]] = [:]
        public var groupTypes: [String: String] = [:]
        public var proxies: Set<String> = []
        public var general: [String: String] = [:]
        /// Loon [Remote Rule]: "url, policy=X, tag=Y, enabled=true" -> (label, policy)
        public var remote: [(label: String, policy: String)] = []
    }

    public static func parseSurge(_ text: String) -> SurgeFile {
        var f = SurgeFile()
        var section = ""
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") || line.hasPrefix("//") { continue }
            if line.hasPrefix("[") && line.hasSuffix("]") {
                section = line.dropFirst().dropLast().lowercased()
                continue
            }
            let kv: (String, String)? = line.firstIndex(of: "=").map {
                (line[..<$0].trimmingCharacters(in: .whitespaces), line[line.index(after: $0)...].trimmingCharacters(in: .whitespaces))
            }
            switch section {
            case "rule":
                f.rules.append(line)
            case "proxy group":
                guard let (name, value) = kv else { continue }
                let parts = value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                f.groupTypes[name] = parts.first?.lowercased() ?? ""
                f.groups[name] = parts.dropFirst().compactMap { p -> String? in
                    if !p.contains("=") { return p.isEmpty ? nil : p }
                    // subnet groups: default = X, "SSID:home" = DIRECT ... -> their policies are members
                    let pv = p.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                    // subnet (Surge) / ssid (Loon) groups: their per-network policies are members
                    return ["subnet", "ssid"].contains(f.groupTypes[name] ?? "") && pv.count == 2 ? pv[1] : nil
                }
            case "proxy":
                if let (name, _) = kv { f.proxies.insert(name) }
            case "general":
                if let (k, v) = kv { f.general[k.lowercased()] = v }
            case "remote rule":
                let parts = line.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                var opts: [String: String] = [:]
                for p in parts.dropFirst() {
                    let o = p.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                    if o.count == 2 { opts[o[0].lowercased()] = o[1] }
                }
                if opts["enabled"]?.lowercased() == "false" { continue }
                f.remote.append(("\(opts["tag"] ?? "") \(parts.first ?? "")", opts["policy"] ?? "?list"))
            default: break
            }
        }
        return f
    }

    /// DIRECT / REJECT* / PROXY (Shadowrocket: the server chosen in the app) / groups.
    /// `selected` holds live selections (Surge HTTP API); without them a group that can
    /// select DIRECT is uncertain.
    public static func surgeResolver(_ f: SurgeFile, selected: [String: String] = [:]) -> RuleEngine.Resolver {
        func hasDirect(_ n: String, _ depth: Int) -> Bool {
            if n.uppercased() == "DIRECT" { return true }
            if depth > 8 { return false }
            return (f.groups[n] ?? []).contains { hasDirect($0, depth + 1) }
        }
        return { start in
            var name = start
            var chain: [String] = []
            for _ in 0..<12 {
                chain.append(name)
                let u = name.uppercased()
                if u == "DIRECT" { return (.direct, chain, false) }
                if u.hasPrefix("REJECT") { return (.reject, chain, false) }
                if name == "?list" { return (.unknown, ["remote list policy"], true) }
                guard let members = f.groups[name] else { return (.proxy, chain, false) }   // PROXY or a server
                if let now = selected[name], !now.isEmpty { name = now; continue }
                if hasDirect(name, 0) { return (.unknown, chain, true) }
                return (.proxy, chain + (members.first.map { [$0 + "?"] } ?? []), false)
            }
            return (.unknown, chain, true)
        }
    }

    /// Surge's HTTP API ([General] http-api = key@127.0.0.1:6171).
    struct SurgeAPI {
        let base: String
        let key: String

        init?(_ spec: String?) {
            guard let spec, !spec.isEmpty else { return nil }
            var key = "", addr = spec
            if let at = spec.lastIndex(of: "@") { key = String(spec[..<at]); addr = String(spec[spec.index(after: at)...]) }
            guard let colon = addr.lastIndex(of: ":"), let port = Int(addr[addr.index(after: colon)...]) else { return nil }
            base = "http://127.0.0.1:\(port)"
            self.key = key
        }

        private static let session: URLSession = {
            let cfg = URLSessionConfiguration.ephemeral
            cfg.connectionProxyDictionary = [:]
            cfg.timeoutIntervalForRequest = 1.5
            cfg.timeoutIntervalForResource = 2
            return URLSession(configuration: cfg)
        }()

        func get(_ path: String) async -> [String: Any]? {
            guard let url = URL(string: base + path) else { return nil }
            var req = URLRequest(url: url)
            req.setValue(key, forHTTPHeaderField: "X-Key")
            guard let (data, resp) = try? await Self.session.data(for: req),
                  (resp as? HTTPURLResponse)?.statusCode == 200 else { return nil }
            return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        }

        struct State {
            var mode = "rule"
            var global: String?
            var enhanced: Bool?
            var selected: [String: String] = [:]
            var liveDirect: [String] = []
        }

        func fetch(groups: [String]) async -> State? {
            guard let out = await get("/v1/outbound") else { return nil }
            var st = State()
            st.mode = Xray.str(out["mode"]).lowercased()
            if st.mode == "proxy" { st.global = Xray.str(await get("/v1/outbound/global")?["policy"]) }
            st.enhanced = await get("/v1/features/enhanced_mode")?["enabled"] as? Bool
            for g in groups {
                let q = g.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? g
                if let p = await get("/v1/policy_groups/select?group_name=\(q)")?["policy"] as? String { st.selected[g] = p }
            }
            for r in await get("/v1/requests/active")?["requests"] as? [[String: Any]] ?? [] {
                var host = Xray.str(r["remoteHost"]).lowercased()
                if let c = host.lastIndex(of: ":") { host = String(host[..<c]) }
                let isClaude = ["anthropic.com", "claude.ai", "claude.com"].contains { RuleEngine.suffix(host, $0) }
                if isClaude && Xray.str(r["policyName"]).uppercased() == "DIRECT" { st.liveDirect.append(host) }
            }
            return st
        }
    }

    /// Evaluates a Surge-format config for Shadowrocket or Surge.
    static func evalSurge(_ path: String, _ text: String, app name: String) async -> ProxyApp {
        let f = parseSurge(text)
        let surge = name == "Surge"
        var app = ProxyApp(kind: name.lowercased(), source: path, live: false, tun: true, ports: [],
                           anthropic: HostRoute(), check: HostRoute())
        app.app = name
        if surge {
            for k in ["http-listen", "socks5-listen"] {
                if let v = f.general[k], let p = Int(v.split(separator: ":").last ?? "") { app.ports?.append(p) }
            }
            if app.ports?.isEmpty == true { app.ports = [6152, 6153] }   // Surge defaults
        }
        var mode = "rule"
        var resolve = surgeResolver(f)
        if surge, let api = SurgeAPI(f.general["http-api"]) {
            if let st = await api.fetch(groups: Array(f.groups.keys)) {
                app.live = true
                app.source += " + API \(api.base)"
                mode = st.mode.isEmpty ? "rule" : st.mode
                if let e = st.enhanced { app.tun = e }
                resolve = surgeResolver(f, selected: st.selected)
                if !st.liveDirect.isEmpty { app.liveDirect = st.liveDirect }
                if mode == "proxy", let g = st.global, !g.isEmpty {
                    let (out, chain, unc) = resolve(g)
                    var r = HostRoute(); r.outcome = out; r.chain = chain; r.rule = "mode: global proxy"; r.uncertain = unc ? true : nil
                    app.mode = "global"
                    app.anthropic = r; app.check = r
                    return app
                }
            } else {
                app.note = "Surge API \(api.base): not reachable"
            }
        }
        var rules = f.rules.compactMap(RuleEngine.parseClashLine)   // same "TYPE,payload,POLICY" syntax; FINAL = MATCH
        var final = name == "Shadowrocket" ? "PROXY" : "DIRECT"   // Shadowrocket's default; Surge / Loon require FINAL
        if !f.remote.isEmpty {
            // Loon: local rules, then remote rule lists, then FINAL.
            if let i = rules.firstIndex(where: { $0.raw.hasPrefix("MATCH,") }), let t = rules[i].target { final = t }
            rules = rules.filter { !$0.raw.hasPrefix("MATCH,") }
                + f.remote.map { RuleEngine.clashRule(type: "RULE-SET", payload: $0.label, policy: $0.policy, params: []) }
        }
        app.mode = mode
        if mode == "direct" {
            var r = HostRoute(); r.outcome = .direct; r.rule = "mode: direct"; r.chain = ["DIRECT"]
            app.anthropic = r; app.check = r
            return app
        }
        (app.anthropic, app.check) = RuleEngine.evalRules(rules, final: final, mode: "", resolve: resolve)
        return app
    }

    // MARK: Quantumult X - its own lowercase filter syntax and policy types

    public static func quantumultXCandidates(_ roots: [String]) -> [ConfigCandidate] {
        let dirs = GUIApps.findAppDirs(roots, ["quantumult"])
        guard let (path, n) = newest(in: dirs, ext: ["conf", "txt"], accept: { _, d in
            let t = String(decoding: d, as: UTF8.self).lowercased()
            return t.contains("[filter_local]") || t.contains("[policy]")
        }) else { return [] }
        var c = ConfigCandidate(kind: "quantumultx", path: path, app: "Quantumult X")
        c.tun = true
        c.note = n > 1 ? "newest of \(n) configs assumed active" : nil
        return [c]
    }

    /// Quantumult X filter types -> Clash rule types.
    static let qxTypes: [String: String] = [
        "host": "DOMAIN", "host-suffix": "DOMAIN-SUFFIX", "host-keyword": "DOMAIN-KEYWORD", "host-wildcard": "DOMAIN-WILDCARD",
        "host-regex": "DOMAIN-REGEX", "ip-cidr": "IP-CIDR", "ip6-cidr": "IP-CIDR6", "geoip": "GEOIP", "final": "MATCH",
    ]

    public struct QXFile {
        public var rules: [RuleEngine.Rule] = []
        public var finalPolicy: String?
        public var policies: [String: (type: String, members: [String])] = [:]
    }

    public static func parseQX(_ text: String) -> QXFile {
        var f = QXFile()
        var section = ""
        var local: [RuleEngine.Rule] = [], remote: [RuleEngine.Rule] = []
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") || line.hasPrefix("//") { continue }
            if line.hasPrefix("[") && line.hasSuffix("]") { section = line.dropFirst().dropLast().lowercased(); continue }
            let parts = line.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            switch section {
            case "filter_local":
                guard parts.count >= 2 else { continue }
                let type = parts[0].lowercased()
                if type == "final" { f.finalPolicy = parts[1]; continue }
                guard parts.count >= 3 else { continue }
                let clashType = qxTypes[type] ?? type.uppercased()   // user-agent, ip-asn ...: "maybe"
                local.append(RuleEngine.clashRule(type: clashType, payload: parts[1], policy: parts[2],
                                                  params: Array(parts.dropFirst(3))))
            case "filter_remote":
                // url, tag=Iran, force-policy=direct, enabled=true
                var opts: [String: String] = [:]
                for p in parts.dropFirst() {
                    let kv = p.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                    if kv.count == 2 { opts[kv[0].lowercased()] = kv[1] }
                }
                if opts["enabled"]?.lowercased() == "false" { continue }
                let label = "\(opts["tag"] ?? "") \(parts.first ?? "")"
                // Without force-policy the list's own policies apply: unknown here.
                remote.append(RuleEngine.clashRule(type: "RULE-SET", payload: label, policy: opts["force-policy"] ?? "?list", params: []))
            case "policy":
                // static=Proxy, de-1, nl-2, direct, img-url=...
                guard let eq = parts.first?.firstIndex(of: "=") else { continue }
                let type = String(parts[0][..<eq]).lowercased()
                let name = String(parts[0][parts[0].index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                var members: [String] = []
                for p in parts.dropFirst() {
                    if let e = p.firstIndex(of: "=") {
                        if type == "ssid" { members.append(String(p[p.index(after: e)...]).trimmingCharacters(in: .whitespaces)) }
                    } else if !p.isEmpty {
                        members.append(p)
                    }
                }
                f.policies[name] = (type, members)
            default: break
            }
        }
        f.rules = local + remote   // local filters take priority over remote ones
        return f
    }

    /// direct / reject* / proxy (the server selected in the app) / [policy] groups.
    static func qxResolver(_ f: QXFile) -> RuleEngine.Resolver {
        func hasDirect(_ n: String, _ depth: Int) -> Bool {
            if n.lowercased() == "direct" { return true }
            if depth > 8 { return false }
            return (f.policies[n]?.members ?? []).contains { hasDirect($0, depth + 1) }
        }
        return { name in
            let l = name.lowercased()
            if l == "direct" { return (.direct, [name], false) }
            if l.hasPrefix("reject") { return (.reject, [name], false) }
            if name == "?list" { return (.unknown, ["remote list policy"], true) }
            if let p = f.policies[name] {
                if hasDirect(name, 0) { return (.unknown, [name], true) }
                return (.proxy, [name] + (p.members.first.map { [$0 + "?"] } ?? []), false)
            }
            return (.proxy, [name], false)   // "proxy" or a server
        }
    }

    static func evalQX(_ path: String, _ text: String) -> ProxyApp {
        let f = parseQX(text)
        var app = ProxyApp(kind: "quantumultx", source: path, live: false, tun: true, ports: [],
                           anthropic: HostRoute(), check: HostRoute())
        app.app = "Quantumult X"
        (app.anthropic, app.check) = RuleEngine.evalRules(f.rules, final: f.finalPolicy ?? "proxy", mode: "", resolve: qxResolver(f))
        return app
    }

    // MARK: Loon - Surge-like .conf with [Remote Rule]

    public static func loonCandidates(_ roots: [String]) -> [ConfigCandidate] {
        let dirs = GUIApps.findAppDirs(roots, ["loon", "ruikq"])
        guard let (path, n) = newest(in: dirs, ext: ["conf", "lcf", "txt"], accept: { _, d in
            let t = String(decoding: d, as: UTF8.self)
            return t.contains("[Rule]") || t.contains("[Remote Rule]")
        }) else { return [] }
        var c = ConfigCandidate(kind: "surge", path: path, app: "Loon")
        c.tun = true
        c.note = n > 1 ? "newest of \(n) configs assumed active" : nil
        return [c]
    }

    // MARK: Egern - nested YAML

    public static func egernCandidates(_ roots: [String]) -> [ConfigCandidate] {
        let dirs = GUIApps.findAppDirs(roots, ["egern"])
        guard let (path, n) = newest(in: dirs, ext: ["yaml", "yml"], accept: { _, d in
            let t = String(decoding: d, as: UTF8.self)
            return t.contains("rules:") || t.contains("policy_groups:")
        }) else { return [] }
        var c = ConfigCandidate(kind: "egern", path: path, app: "Egern")
        c.tun = true
        c.note = n > 1 ? "newest of \(n) profiles assumed active" : nil
        return [c]
    }

    /// Egern rule types -> Clash rule types (others are "maybe").
    static let egernTypes: [String: String] = [
        "domain": "DOMAIN", "domain_suffix": "DOMAIN-SUFFIX", "domain_keyword": "DOMAIN-KEYWORD", "domain_regex": "DOMAIN-REGEX",
        "domain_wildcard": "DOMAIN-WILDCARD", "ip_cidr": "IP-CIDR", "ip_cidr6": "IP-CIDR6", "geoip": "GEOIP",
        "dst_port": "DST-PORT", "rule_set": "RULE-SET", "domain_set": "DOMAIN-SET", "default": "MATCH",
    ]

    public static func evalEgern(_ path: String, _ text: String) -> ProxyApp {
        var app = ProxyApp(kind: "egern", source: path, live: false, tun: true, ports: [], anthropic: HostRoute(), check: HostRoute())
        app.app = "Egern"
        guard let root = MiniYAML.parse(text) as? [String: Any] else {
            app.note = "config not readable"
            app.anthropic.uncertain = true
            app.check = app.anthropic
            return app
        }
        // policy_groups: [{select: {name: Proxy, policies: [a, DIRECT]}}, {ssid: {name: X, default: .., cellular: DIRECT}}]
        var groups: [String: [String]] = [:]
        for g in root["policy_groups"] as? [[String: Any]] ?? [] {
            for (_, body) in g {
                guard let b = body as? [String: Any], let name = b["name"] as? String else { continue }
                var members = SingBox.strings(b["policies"])
                for (k, v) in b where k != "name" && k != "policies" {
                    if let sv = v as? String { members.append(sv) }   // ssid groups: default / cellular / per-network
                    if let m = v as? [String: Any] { members += m.values.compactMap { $0 as? String } }
                }
                groups[name] = members
            }
        }
        var f = SurgeFile()
        f.groups = groups
        var rules: [RuleEngine.Rule] = []
        var final = "DIRECT"
        for r in root["rules"] as? [[String: Any]] ?? [] {
            for (type, body) in r {
                let b = body as? [String: Any] ?? [:]
                let policy = Xray.str(b["policy"])
                if type == "default" { if !policy.isEmpty { final = policy }; continue }
                guard !policy.isEmpty else { continue }
                let clashType = egernTypes[type] ?? type.uppercased()   // asn, protocol, and/or/not ...: "maybe"
                let params = b["no_resolve"] as? Bool == true ? ["no-resolve"] : []
                let matches = SingBox.strings(b["match"]).isEmpty ? [Xray.str(b["match"])] : SingBox.strings(b["match"])
                for m in matches { rules.append(RuleEngine.clashRule(type: clashType, payload: m, policy: policy, params: params)) }
            }
        }
        (app.anthropic, app.check) = RuleEngine.evalRules(rules, final: final, mode: "", resolve: surgeResolver(f))
        return app
    }

    // MARK: Stash

    public static func stashCandidates(_ roots: [String]) -> [ConfigCandidate] {
        let dirs = GUIApps.findAppDirs(roots, ["ws.stash", "ws~stash", "stash.app"])
        guard let (path, n) = newest(in: dirs, ext: ["yaml", "yml"], accept: { _, d in
            let t = String(decoding: d, as: UTF8.self)
            return t.contains("rules:") || t.contains("proxy-groups:")
        }) else { return [] }
        var c = ConfigCandidate(kind: "clash", path: path, app: "Stash")
        c.tun = true
        c.note = n > 1 ? "newest of \(n) profiles assumed active" : nil
        return [c]
    }
}
