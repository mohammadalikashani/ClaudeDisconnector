import Foundation

// GUI clients whose core config isn't simply named on a command line (same logic as
// windows/internal/core/guiapps.go):
//
//  - Hiddify: a sing-box client. Its generated core config ("current-config.json") and
//    its Flutter preferences (Clash API / mixed port, service mode) live in the app's
//    data folder, whose name differs per OS / version - so it's searched for. On macOS
//    the preferences are a plist (NSUserDefaults).
//  - NekoRay / NekoBox / Throne: hand the core its config over gRPC (never written to
//    disk), so the routing is rebuilt from the app's own settings: groups/nekobox.json
//    and the active route profile in routes_box/ (sing-box core) or routes/ (Xray core).

public enum GUIApps {
    // MARK: Hiddify

    public struct HiddifyInfo {
        public var configs: [ConfigCandidate] = []
        public var mixedPort: Int?
        public var tun = false

        mutating func apply(_ prefs: [String: Any]) {
            func get(_ k: String) -> Any? { prefs["flutter." + k] ?? prefs[k] }
            let api = Xray.port(get("clash-api-port"))
            if api > 0 {
                configs.append(ConfigCandidate(kind: "api", path: "127.0.0.1:\(api)", app: "Hiddify"))
            }
            let mixed = Xray.port(get("mixed-port"))
            if mixed > 0 { mixedPort = mixed }
            if ["tun", "vpn"].contains(Xray.str(get("service-mode")).lowercased()) { tun = true }
        }

        mutating func finish() {
            for i in configs.indices {
                if let p = mixedPort { configs[i].ports = [p] }
                configs[i].tun = tun
            }
        }
    }

    /// Searches roots (~/Library/Application Support, Group Containers, Containers, ...)
    /// for Hiddify folders, and `plists` for Hiddify's preferences.
    public static func findHiddify(roots: [String], plists: [String]) -> HiddifyInfo {
        var info = HiddifyInfo()
        var seen = Set<String>()
        let fm = FileManager.default
        for root in roots {
            for name in (try? fm.contentsOfDirectory(atPath: root)) ?? [] where name.lowercased().contains("hiddify") {
                walk(root + "/" + name, depth: 7) { path in
                    switch (path as NSString).lastPathComponent.lowercased() {
                    case "current-config.json":
                        if seen.insert(path).inserted {
                            info.configs.append(ConfigCandidate(kind: "json", path: path, app: "Hiddify"))
                        }
                    case "shared_preferences.json":
                        if let d = fm.contents(atPath: path),
                           let prefs = try? JSONSerialization.jsonObject(with: d) as? [String: Any] {
                            info.apply(prefs)
                        }
                    default: break
                    }
                }
            }
        }
        for p in plists {
            if let d = fm.contents(atPath: p),
               let prefs = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any] {
                info.apply(prefs)
            }
        }
        info.finish()
        return info
    }

    static func walk(_ dir: String, depth: Int, _ fn: (String) -> Void) {
        var count = 0
        func go(_ d: String, _ left: Int) {
            guard let items = try? FileManager.default.contentsOfDirectory(atPath: d) else { return }
            for item in items {
                count += 1
                if count > 20000 { return }
                let p = d + "/" + item
                var isDir: ObjCBool = false
                guard let attrs = try? FileManager.default.attributesOfItem(atPath: p),
                      attrs[.type] as? FileAttributeType != .typeSymbolicLink,
                      FileManager.default.fileExists(atPath: p, isDirectory: &isDir) else { continue }
                if isDir.boolValue { if left > 0 { go(p, left - 1) } } else { fn(p) }
            }
        }
        go(dir, depth)
    }

    // MARK: NekoRay / NekoBox / Throne

    /// Config folders: "<exe dir>/config" plus the usual per-user locations.
    public static func nekorayDirs(home: String, exeDirs: [String]) -> [ConfigCandidate] {
        var out = exeDirs.map { ConfigCandidate(kind: "nekoray", path: $0 + "/config") }
        for n in ["nekoray", "nekobox", "Throne", "throne"] {
            for base in [home + "/.config", home + "/Library/Preferences", home + "/Library/Application Support"] {
                out.append(ConfigCandidate(kind: "nekoray", path: "\(base)/\(n)/config"))
            }
        }
        return out
    }

    static func lines(_ s: Any?) -> [String] {
        Xray.str(s).replacingOccurrences(of: "\r", with: "").split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") && !$0.hasPrefix("//") }
    }

    /// NekoRay's fixed outbound tags. "bypass" is its name for DIRECT.
    static let outbounds: [[String: Any]] = [
        ["tag": "proxy", "protocol": "vless"], ["tag": "bypass", "protocol": "freedom"], ["tag": "direct", "protocol": "freedom"],
        ["tag": "block", "protocol": "blackhole"], ["tag": "dns-out", "protocol": "dns"],
    ]

    /// Rebuilds NekoRay's routing from its settings folder (nil if it isn't one).
    static func evalNekoray(_ dir: String) -> (ProxyApp, clashAPI: (port: Int, secret: String?)?)? {
        let fm = FileManager.default
        guard let settingsPath = ["nekobox.json", "nekoray.json", "throne.json"].map({ "\(dir)/groups/\($0)" })
            .first(where: { fm.fileExists(atPath: $0) }) else { return nil }
        let st = fm.contents(atPath: settingsPath).flatMap(Xray.object) ?? [:]
        let lower = settingsPath.lowercased()
        let name = lower.contains("throne") ? "Throne" : lower.hasSuffix("nekoray.json") ? "NekoRay" : "NekoBox"
        let socks = Xray.port(st["inbound_socks_port"])
        var routing = Xray.str(st["active_routing"])
        if routing.isEmpty { routing = "Default" }
        var app = ProxyApp(kind: "nekoray", source: settingsPath, live: false, tun: false, ports: [socks > 0 ? socks : 2080],
                           anthropic: HostRoute(), check: HostRoute())
        app.app = name
        let api = Xray.port(st["core_box_clash_api"])
        let apiInfo = api > 0 ? (port: api, secret: st["core_box_clash_api_secret"] as? String) : nil

        guard let routePath = ["routes_box", "routes"].map({ "\(dir)/\($0)/\(routing)" }).first(where: { fm.fileExists(atPath: $0) }),
              let rt = fm.contents(atPath: routePath).flatMap(Xray.object) else {
            app.note = "route profile \(routing) not found"
            app.anthropic.uncertain = true
            app.check = app.anthropic
            return (app, apiInfo)
        }
        app.source = "\(settingsPath) + \(routePath)"
        let strategy = Xray.str(rt["domain_strategy"])
        let resolveIP = !strategy.isEmpty && strategy.lowercased() != "asis"
        var rules: [RuleEngine.Rule] = []
        // Custom rules first (sing-box route rules for NekoBox, Xray rules for NekoRay).
        let custom = Xray.str(rt["custom"]).trimmingCharacters(in: .whitespacesAndNewlines)
        if !custom.isEmpty {
            if let obj = try? JSONSerialization.jsonObject(with: Data(custom.utf8)) as? [String: Any] {
                for r in obj["rules"] as? [[String: Any]] ?? [] {
                    rules.append(r["outboundTag"] != nil ? Xray.rule(r, userIn: [], resolveIP: resolveIP) : SingBox.rule(r))
                }
            } else {
                app.note = "custom route rules unreadable"
            }
        }
        // Then NekoRay's lists: block, proxy, direct - domains first, then IPs.
        for (key, field, out) in [("domain", "block_domain", "block"), ("domain", "proxy_domain", "proxy"), ("domain", "direct_domain", "bypass"),
                                  ("ip", "block_ip", "block"), ("ip", "proxy_ip", "proxy"), ("ip", "direct_ip", "bypass")] {
            let l = lines(rt[field])
            if !l.isEmpty { rules.append(Xray.rule([key: l, "outboundTag": out], userIn: [], resolveIP: resolveIP)) }
        }
        var final = Xray.str(rt["def_outbound"]).lowercased()
        if final.isEmpty || final == "proxy" { final = "proxy" } else if final == "direct" { final = "bypass" }
        (app.anthropic, app.check) = RuleEngine.evalRules(rules, final: final, mode: "",
                                                          resolve: Xray.resolver(["outbounds": outbounds]))
        return (app, apiInfo)
    }
}

// MARK: - FlClash / Karing (same logic as guiapps.go)

extension GUIApps {
    /// Folders under roots whose name contains one of keys, plus their direct subfolders.
    public static func findAppDirs(_ roots: [String], _ keys: [String]) -> [String] {
        let fm = FileManager.default
        var out: [String] = []
        for root in roots {
            for name in (try? fm.contentsOfDirectory(atPath: root)) ?? [] where keys.contains(where: name.lowercased().contains) {
                let d = root + "/" + name
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: d, isDirectory: &isDir), isDir.boolValue else { continue }
                out.append(d)
                for sub in (try? fm.contentsOfDirectory(atPath: d)) ?? [] where sub != "profiles" {
                    var sd: ObjCBool = false
                    if fm.fileExists(atPath: d + "/" + sub, isDirectory: &sd), sd.boolValue { out.append(d + "/" + sub) }
                }
            }
        }
        return out
    }

    // FlClash (a mihomo GUI) keeps subscriptions in profiles/<id>.yaml and applies its own
    // settings when starting the core: ports, mode, TUN, external controller
    // ("patchClashConfig") and per-profile rule overrides. Older versions keep settings in
    // Flutter preferences ("flutter.config" / "flutter.clashConfig"; a plist on macOS).

    public static func flClashCandidates(_ roots: [String]) -> [ConfigCandidate] {
        findAppDirs(roots, ["com.follow", "flclash"]).map { ConfigCandidate(kind: "flclash", path: $0, app: "FlClash") }
    }

    /// Flutter preferences plists FlClash may use on macOS.
    static var flClashPlists: [String] = []

    static func jsonOrString(_ v: Any?) -> [String: Any]? {
        if let m = v as? [String: Any] { return m }
        if let s = v as? String { return try? JSONSerialization.jsonObject(with: Data(s.utf8)) as? [String: Any] }
        return nil
    }

    static func pick(_ m: [String: Any], _ keys: String...) -> Any? {
        for k in keys { if let v = m[k] { return v } }
        return nil
    }

    static func flClashSettings(_ dir: String) -> (cfg: [String: Any]?, patch: [String: Any]?) {
        let fm = FileManager.default
        var cfg = fm.contents(atPath: dir + "/config.json").flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        var prefs = fm.contents(atPath: dir + "/shared_preferences.json").flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        if prefs == nil {
            for p in flClashPlists {
                if let d = fm.contents(atPath: p),
                   let m = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any] { prefs = m; break }
            }
        }
        if cfg == nil, let prefs { cfg = jsonOrString(pick(prefs, "flutter.config", "config")) }
        var patch = cfg.flatMap { jsonOrString(pick($0, "patchClashConfig", "clashConfig")) }
        if patch == nil, let prefs { patch = jsonOrString(pick(prefs, "flutter.clashConfig", "clashConfig")) }
        return (cfg, patch)
    }

    /// The current profile merged with FlClash's settings (nil if dir isn't FlClash's).
    static func flClashFile(_ dir: String) -> (path: String, file: ClashFile)? {
        let fm = FileManager.default
        let (cfg, patch) = flClashSettings(dir)
        let id = Xray.str(cfg?["currentProfileId"])
        let profile = (cfg?["profiles"] as? [[String: Any]])?.first { Xray.str($0["id"]) == id }
        var candidates = [dir + "/config.yaml"]
        if !id.isEmpty { candidates.insert(contentsOf: ["\(dir)/profiles/\(id).yaml", "\(dir)/profiles/\(id).yml"], at: 0) }
        guard let path = candidates.first(where: { fm.fileExists(atPath: $0) }),
              let data = fm.contents(atPath: path) else {
            if cfg == nil { return nil }
            var f = ClashFile()
            f.rules = []
            f.controller = nil
            return (dir, f)   // FlClash folder, profile missing: evaluated as uncertain by the caller
        }
        var f = ClashFile.parse(String(decoding: data, as: UTF8.self))
        if let p = patch {
            if let m = pick(p, "mode").map(Xray.str), !m.isEmpty { f.mode = m.lowercased() }
            if let v = pick(p, "mixed-port", "mixedPort") { f.ports = [Xray.port(v)].filter { $0 > 0 } }
            if let t = p["tun"] as? [String: Any] { f.tun = t["enable"] as? Bool ?? false }
            if let v = pick(p, "external-controller", "externalController") {
                let c = Xray.str(v)
                f.controller = c.isEmpty ? nil : c
            }
            if let v = p["secret"] { f.secret = Xray.str(v) }
            if let r = pick(p, "rules", "rule") { let rs = SingBox.strings(r); if !rs.isEmpty { f.rules = rs } }
        }
        // Per-profile rule overrides ("overrideData": {"enable": true, "rule": {"type": "added"|"override", ...}}).
        if let od = profile?["overrideData"] as? [String: Any], od["enable"] as? Bool == true,
           let r = od["rule"] as? [String: Any] {
            let override = SingBox.strings(r["overrideRules"]), added = SingBox.strings(r["addedRules"])
            if Xray.str(r["type"]).lowercased() == "override" && !override.isEmpty { f.rules = override }
            else if !added.isEmpty { f.rules = added + f.rules }
        }
        return (path, f)
    }

    // Karing (a sing-box GUI) writes the full config it runs into its data folder; the
    // newest runnable sing-box config there is taken as the active one.
    public static func karingCandidates(_ roots: [String]) -> [ConfigCandidate] {
        var best: (String, Date)?
        for d in findAppDirs(roots, ["karing"]) {
            walk(d, depth: 4) { p in
                guard p.lowercased().hasSuffix(".json"),
                      let attrs = try? FileManager.default.attributesOfItem(atPath: p),
                      let mtime = attrs[.modificationDate] as? Date, (attrs[.size] as? Int ?? 0) < 8 << 20,
                      best == nil || mtime > best!.1,
                      let data = FileManager.default.contents(atPath: p), runnableSingBox(data) else { return }
                best = (p, mtime)
            }
        }
        return best.map { [ConfigCandidate(kind: "json", path: $0.0, app: "Karing")] } ?? []
    }

    /// A full sing-box config (inbounds + outbounds + route), not a subscription / outbound list.
    static func runnableSingBox(_ data: Data) -> Bool {
        guard Xray.jsonKind(data) == "sing-box", let o = Xray.object(data) else { return false }
        return !(o["inbounds"] as? [Any] ?? []).isEmpty && !(o["outbounds"] as? [Any] ?? []).isEmpty && o["route"] != nil
    }
}

// MARK: - Mihomo Party / Clash Nyanpasu (same logic as guiapps.go)

extension GUIApps {
    /// Both write the runtime config the core runs with before starting it: Mihomo Party
    /// <data>/work/config.yaml, Clash Nyanpasu <config>/clash-config.yaml. The newest one per
    /// app is taken (rewritten on every start / profile switch).
    public static func mihomoGUICandidates(_ roots: [String]) -> [ConfigCandidate] {
        var out: [ConfigCandidate] = []
        for (name, keys) in [("Mihomo Party", ["mihomo-party", "mihomo party", "clash-party", "clash party"]),
                             ("Clash Nyanpasu", ["nyanpasu"]),
                             // Clash Verge Rev / Clash Verge: config.yaml is only a partial override,
                             // clash-verge.yaml is the runtime file.
                             ("Clash Verge", ["clash-verge"])] {
            var best: (String, Date)?
            var seen = Set<String>()
            for d in findAppDirs(roots, keys) {
                walk(d, depth: 2) { p in
                    guard seen.insert(p).inserted else { return }
                    let base = (p as NSString).lastPathComponent.lowercased()
                    let parent = ((p as NSString).deletingLastPathComponent as NSString).lastPathComponent.lowercased()
                    guard base == "clash-config.yaml" || base == "clash-verge.yaml" || (base == "config.yaml" && parent == "work"),
                          let m = (try? FileManager.default.attributesOfItem(atPath: p))?[.modificationDate] as? Date,
                          best == nil || m > best!.1 else { return }
                    best = (p, m)
                }
            }
            if let b = best { out.append(ConfigCandidate(kind: "clash", path: b.0, app: name)) }
        }
        return out
    }

    /// The client a config file belongs to, from its path (nil = unknown).
    public static func appLabel(_ path: String) -> String? {
        let p = path.lowercased()
        let labels: [(String, String)] = [
            ("mihomo-party", "Mihomo Party"), ("mihomo party", "Mihomo Party"), ("clash-party", "Mihomo Party"),
            ("nyanpasu", "Clash Nyanpasu"), ("clash-verge", "Clash Verge"), ("clashx", "ClashX"),
            ("flclash", "FlClash"), ("com.follow", "FlClash"), ("hiddify", "Hiddify"), ("karing", "Karing"),
            ("v2rayn", "v2rayN"), ("v2rayu", "V2rayU"), ("v2rayxs", "V2RayXS"), ("qv2ray", "Qv2ray"),
            ("nekobox", "NekoBox"), ("nekoray", "NekoRay"),
        ]
        return labels.first { p.contains($0.0) }?.1
    }
}

// MARK: - ClashX Meta / ClashX (macOS)

extension GUIApps {
    /// ClashX Meta keeps its profiles in ~/.config/clash.meta/<name>.yaml (ClashX / ClashX Pro:
    /// ~/.config/clash) and the active one's name in its preferences ("selectConfigName").
    public static func clashXCandidates(home: String) -> [ConfigCandidate] {
        var out: [ConfigCandidate] = []
        for (name, plist, dir) in [("ClashX Meta", "com.metacubex.ClashX.meta", "clash.meta"),
                                   ("ClashX Pro", "com.west2online.ClashXPro", "clash"),
                                   ("ClashX", "com.west2online.ClashX", "clash")] {
            let prefs = FileManager.default.contents(atPath: "\(home)/Library/Preferences/\(plist).plist")
                .flatMap { try? PropertyListSerialization.propertyList(from: $0, format: nil) as? [String: Any] }
            guard let prefs else { continue }
            let selected = (prefs["selectConfigName"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "config"
            // The API comes from the profile's external-controller (or ClashX's default 9090, probed anyway).
            out.append(ConfigCandidate(kind: "clash", path: "\(home)/.config/\(dir)/\(selected).yaml", app: name))
        }
        return out
    }
}

// MARK: - Clash for Windows (also macOS / Linux) - same logic as guiapps.go

extension GUIApps {
    /// ~/.config/clash if it's a Clash for Windows home (has profiles/list.yml).
    public static func cfwDir(home: String) -> String? {
        let d = home + "/.config/clash"
        return FileManager.default.fileExists(atPath: d + "/profiles/list.yml") ? d : nil
    }

    /// The selected profile (list.yml "index"), CFW's general settings from config.yaml on top,
    /// and each group's saved selection (used when the API isn't reachable).
    static func evalCFW(_ dir: String, _ cand: ConfigCandidate, _ seenAPI: inout Set<String>) async -> ProxyApp? {
        func uncertain(_ note: String) -> ProxyApp {
            var a = ProxyApp(kind: "clash", source: dir, live: false, anthropic: HostRoute(), check: HostRoute(), note: note)
            a.app = "Clash for Windows"
            a.anthropic.uncertain = true
            a.check = a.anthropic
            return a
        }
        let fm = FileManager.default
        guard let ldata = fm.contents(atPath: dir + "/profiles/list.yml") else { return nil }
        guard let list = MiniYAML.parse(String(decoding: ldata, as: UTF8.self)) as? [String: Any],
              let files = list["files"] as? [[String: Any]], !files.isEmpty else { return uncertain("profiles/list.yml unreadable or empty") }
        var index = list["index"] as? Int ?? 0
        if index < 0 || index >= files.count { index = 0 }
        let sel = files[index]
        let profilePath = dir + "/profiles/" + Xray.str(sel["time"])
        guard let pdata = fm.contents(atPath: profilePath) else { return uncertain("selected profile \(Xray.str(sel["time"])) not found") }
        var f = ClashFile.parse(String(decoding: pdata, as: UTF8.self))
        if let bdata = fm.contents(atPath: dir + "/config.yaml") {
            let base = ClashFile.parse(String(decoding: bdata, as: UTF8.self))
            if !base.ports.isEmpty { f.ports = base.ports }
            if base.mode != "rule" || bdata.range(of: Data("mode:".utf8)) != nil { f.mode = base.mode }
            if let c = base.controller, !c.isEmpty { f.controller = c; f.secret = base.secret }
            f.tun = f.tun || base.tun
        }
        if let v = cand.extCtl { f.controller = v }
        if let v = cand.extCtlUnix { f.controllerUnix = v }
        if let v = cand.secret { f.secret = v }
        for s in sel["selected"] as? [[String: Any]] ?? [] {
            let name = Xray.str(s["name"]), now = Xray.str(s["now"])
            if !name.isEmpty && !now.isEmpty { f.selected[name] = now }
        }
        var app = await ProxyApps.evalClash(profilePath, f, &seenAPI)
        app.app = "Clash for Windows"
        if !app.live, let sdata = fm.contents(atPath: dir + "/cfw-settings.yaml"),
           let st = MiniYAML.parse(String(decoding: sdata, as: UTF8.self)) as? [String: Any],
           let parsers = st["parsers"] as? [Any], !parsers.isEmpty {
            app.note = [app.note, "profile parsers are on (rules may differ from the file)"].compactMap { $0 }.joined(separator: "; ")
        }
        return app
    }
}
