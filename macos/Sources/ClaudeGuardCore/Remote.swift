import Foundation

// Remote Clash (same logic as windows/internal/core/remote.go): a proxy app on ANOTHER
// device this computer uses as its proxy - typically Clash Meta for Android (CMFA) with
// "Allow LAN", the Mac's system proxy / PAC / HTTPS_PROXY pointing at the phone. Its files
// are in the app's private storage, but its Clash API can be enabled on the LAN (CMFA:
// Override > External controller 0.0.0.0:9090, optional secret). If it sends Claude
// DIRECT, Claude leaves through the PHONE's connection, which can't be checked from here.

public enum RemoteAPIs {
    public static let defaultPorts = [9090, 9097]
    /// Extra controllers: one "host:port [secret]" per line.
    /// CLAUDEGUARD_REMOTE_APIS overrides the location (for testing).
    public static let file = ProcessInfo.processInfo.environment["CLAUDEGUARD_REMOTE_APIS"] ?? GuardPaths.supportDir + "/remote-apis.txt"

    public static func load(_ path: String = file) -> [(addr: String, secret: String?)] {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
        return text.split(separator: "\n").compactMap { raw in
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { return nil }
            let parts = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            let addr = parts[0].replacingOccurrences(of: "http://", with: "").replacingOccurrences(of: "https://", with: "")
            return (addr, parts.count > 1 ? parts[1] : nil)
        }
    }

    public static func save(_ list: [(addr: String, secret: String?)], _ path: String = file) throws {
        var s = "# Remote Clash APIs (e.g. Clash Meta for Android with Allow LAN): host:port [secret]\n"
        for r in list { s += r.addr + (r.secret.map { " " + $0 } ?? "") + "\n" }
        try FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try s.write(toFile: path, atomically: true, encoding: .utf8)
        chmod(path, 0o600)
    }

    static func isLocal(_ host: String) -> Bool {
        let h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        return h == "localhost" || h == "::1" || h.hasPrefix("127.")
    }

    static func join(_ host: String, _ port: Int) -> String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }

    /// API candidates for every non-local proxy host (system proxy, PAC answer, Claude
    /// Code's proxy), plus configured controllers.
    public static func candidates(proxies: [String?], configured: [(addr: String, secret: String?)]) -> [ConfigCandidate] {
        var out: [ConfigCandidate] = []
        var seen = Set<String>()
        func add(_ addr: String, _ secret: String?) {
            guard seen.insert(addr).inserted else { return }
            let host = addr.hasPrefix("[") ? String(addr.dropFirst().prefix(while: { $0 != "]" }))
                                           : String(addr.split(separator: ":").first ?? "")
            var c = ConfigCandidate(kind: "api", path: addr, app: "Clash on \(host)")
            c.secret = secret
            out.append(c)
        }
        for r in configured { add(r.addr, r.secret) }
        for p in proxies.compactMap({ $0 }) {
            guard let hp = ProxyURL.hostPort(p), !isLocal(hp.host) else { continue }
            for port in defaultPorts { add(join(hp.host, port), nil) }
        }
        return out
    }

    /// "claudeguard remote-api list | add <host:port> [secret] | remove <host:port>"
    public static func command(_ args: [String], path: String = file) throws -> String {
        var list = load(path)
        switch args.first ?? "list" {
        case "list":
            if list.isEmpty { return "no remote Clash APIs configured (proxy hosts are still probed on ports 9090 / 9097)\n" }
            return list.map { $0.addr + ($0.secret != nil ? "  (with secret)" : "") + "\n" }.joined()
        case "add" where args.count >= 2:
            let addr = args[1].replacingOccurrences(of: "http://", with: "").replacingOccurrences(of: "https://", with: "")
            guard let port = addr.split(separator: ":").last.flatMap({ Int($0) }), port > 0, addr.contains(":") else { throw CommandError.usage }
            list.removeAll { $0.addr == addr }
            list.append((addr, args.count > 2 ? args[2] : nil))
            try save(list, path)
            return "added \(addr) - click Refresh (or run refresh) to check it\n"
        case "remove" where args.count >= 2:
            list.removeAll { $0.addr == args[1] }
            try save(list, path)
            return "removed \(args[1])\n"
        default:
            throw CommandError.usage
        }
    }

    public enum CommandError: Error, CustomStringConvertible {
        case usage
        public var description: String { "usage: remote-api list | add <host:port> [secret] | remove <host:port>" }
    }
}

extension ClaudeSettings {
    /// env.HTTPS_PROXY / HTTP_PROXY from <home>/.claude/settings.json (the daemon runs as root).
    public static func proxy(home: String) -> String? {
        guard let data = FileManager.default.contents(atPath: home + "/.claude/settings.json"),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let env = obj["env"] as? [String: Any] else { return nil }
        return ProxyURL.claudeCode(env.compactMapValues { $0 as? String })
    }
}
