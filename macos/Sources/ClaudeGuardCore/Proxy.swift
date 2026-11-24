import Foundation
import CFNetwork

/// The macOS system proxy (what V2rayU / V2Box / v2rayN set in "system proxy" mode).
/// Claude Desktop (Chromium) follows it; Claude Code does NOT - Claude Code only uses
/// the https_proxy / HTTPS_PROXY / http_proxy / HTTP_PROXY environment variables.
public struct SystemProxy: Codable, Equatable {
    public var http: String?   // "http://host:port"  (usable by Claude Code)
    public var socks: String?  // "socks5://host:port" (Claude Desktop only)
    public var pac: String?    // PAC URL (not evaluated)

    public init(http: String? = nil, socks: String? = nil, pac: String? = nil) {
        self.http = http
        self.socks = socks
        self.pac = pac
    }

    public var enabled: Bool { http != nil || socks != nil }
    /// The proxy whose exit IP decides whether Claude Desktop is safe.
    public var checkURL: String? { http ?? socks }

    /// Reads the current system proxy (works as root and as a user).
    public static func current() -> SystemProxy {
        guard let dict = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return SystemProxy()
        }
        func endpoint(_ prefix: String) -> (String, Int)? {
            guard (dict["\(prefix)Enable"] as? Int) == 1,
                  let host = dict["\(prefix)Proxy"] as? String, !host.isEmpty,
                  let port = dict["\(prefix)Port"] as? Int else { return nil }
            return (host, port)
        }
        var p = SystemProxy()
        if let (h, port) = endpoint("HTTPS") ?? endpoint("HTTP") {
            p.http = "http://\(h):\(port)"
        }
        if let (h, port) = endpoint("SOCKS") {
            p.socks = "socks5://\(h):\(port)"
        }
        if (dict["ProxyAutoConfigEnable"] as? Int) == 1 {
            p.pac = (dict["ProxyAutoConfigURLString"] as? String) ?? "PAC"
        }
        return p
    }
}

/// Result of checking the system-proxy route.
/// `system.http` holds an HTTP proxy usable by Claude Code (in PAC mode: the PAC's PROXY entry).
public struct ProxyRoute: Codable, Equatable {
    public var system: SystemProxy
    public var mode: String?       // "manual" or "pac"
    public var checked: String?    // proxy whose exit was checked (nil = DIRECT)
    public var pacResult: String?  // PAC answer for claude.ai
    public var kind: String     // Verdict.Kind raw value
    public var ok: Bool
    public var ipv4: String?
    public var ipv6: String?
    public var country: String?
    public var detail: String

    public init(system: SystemProxy, mode: String? = nil, checked: String? = nil, pacResult: String? = nil,
                kind: String, ok: Bool, ipv4: String? = nil, ipv6: String? = nil,
                country: String? = nil, detail: String) {
        self.system = system
        self.mode = mode
        self.checked = checked
        self.pacResult = pacResult
        self.kind = kind
        self.ok = ok
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.country = country
        self.detail = detail
    }
}

extension ProxyRoute {
    /// Short label, e.g. "http://127.0.0.1:10809" or "PAC -> DIRECT".
    public var describe: String {
        let via = checked ?? "DIRECT"
        return mode == "pac" ? "PAC -> \(via)" : via
    }
}

public enum ProxyURL {
    /// Adds http:// when the scheme is missing, maps socks:// -> socks5://.
    public static func normalize(_ s: String) -> String {
        var s = s.trimmingCharacters(in: .whitespaces)
        if s.isEmpty { return s }
        if !s.contains("://") { s = "http://" + s }
        if s.lowercased().hasPrefix("socks://") { s = "socks5://" + s.dropFirst("socks://".count) }
        while s.hasSuffix("/") { s.removeLast() }
        return s
    }

    public static func hostPort(_ s: String) -> (scheme: String, host: String, port: Int)? {
        guard let u = URLComponents(string: normalize(s)), let host = u.host else { return nil }
        let scheme = (u.scheme ?? "http").lowercased()
        return (scheme, host, u.port ?? (scheme.hasPrefix("socks") ? 1080 : 80))
    }

    public static func sameEndpoint(_ a: String?, _ b: String?) -> Bool {
        guard let a, let b, let x = hostPort(a), let y = hostPort(b) else { return false }
        func canon(_ h: String) -> String {
            let h = h.lowercased()
            return (h == "localhost" || h == "::1") ? "127.0.0.1" : h
        }
        return canon(x.host) == canon(y.host) && x.port == y.port
    }

    /// The proxy Claude Code itself uses, given its environment (same precedence as
    /// Claude Code), or nil when it goes direct (none set, or NO_PROXY covers Anthropic).
    public static func claudeCode(_ env: [String: String]) -> String? {
        guard let p = ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"]
            .lazy.compactMap({ env[$0]?.trimmingCharacters(in: .whitespaces) }).first(where: { !$0.isEmpty })
        else { return nil }
        let noProxy = env["no_proxy"] ?? env["NO_PROXY"] ?? ""
        if noProxy.trimmingCharacters(in: .whitespaces) == "*" { return nil }
        for raw in noProxy.split(whereSeparator: { $0 == "," || $0 == " " }) {
            var e = raw.lowercased()
            if e.hasPrefix("*") { e.removeFirst() }
            if e.hasPrefix(".") { e.removeFirst() }
            if e.isEmpty { continue }
            for h in ["api.anthropic.com", "anthropic.com", "claude.ai"] where h == e || h.hasSuffix("." + e) {
                return nil
            }
        }
        return normalize(p)
    }

    /// URLSession proxy dictionary for a proxy URL. Empty dictionary = no proxy at all
    /// (nil would mean "use the system proxy", which the direct check must NOT do).
    public static func sessionDictionary(_ url: String?) -> [AnyHashable: Any] {
        guard let url, let hp = hostPort(url) else { return [:] }
        if hp.scheme.hasPrefix("socks") {
            return ["SOCKSEnable": 1, "SOCKSProxy": hp.host, "SOCKSPort": hp.port]
        }
        return ["HTTPEnable": 1, "HTTPProxy": hp.host, "HTTPPort": hp.port,
                "HTTPSEnable": 1, "HTTPSProxy": hp.host, "HTTPSPort": hp.port]
    }
}

/// Reads/writes Claude Code's proxy in ~/.claude/settings.json (env.HTTPS_PROXY).
public enum ClaudeSettings {
    public static var path: String { NSHomeDirectory() + "/.claude/settings.json" }

    public static func proxy() -> String? {
        guard let data = FileManager.default.contents(atPath: path),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let env = obj["env"] as? [String: Any] else { return nil }
        return ProxyURL.claudeCode(env.compactMapValues { $0 as? String })
    }
}
