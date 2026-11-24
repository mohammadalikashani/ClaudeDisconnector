import Foundation
import CFNetwork

/// The route Claude Desktop (Chromium) takes to Anthropic.
public struct DesktopRoute {
    public var mode: String          // "manual" or "pac"
    public var proxy: String?        // proxy to check (nil = DIRECT)
    public var http: String?         // an HTTP proxy usable by Claude Code
    public var pacResult: String?    // PAC answer for claude.ai, e.g. "PROXY 127.0.0.1:10809; DIRECT"
    public var note: String?         // PAC load/eval problem (Chromium then goes DIRECT)
}

public enum PAC {
    /// URLs whose PAC answer decides Claude Desktop's route.
    public static let targets = ["https://claude.ai/", "https://api.anthropic.com/"]

    /// Works out Claude Desktop's route. PAC takes precedence over the manual proxy.
    public static func resolveDesktopRoute(_ sp: SystemProxy) async -> DesktopRoute {
        guard let pacURL = sp.pac else {
            return DesktopRoute(mode: "manual", proxy: sp.checkURL, http: sp.http)
        }
        var r = DesktopRoute(mode: "pac")
        guard let script = await fetch(pacURL) else {
            r.note = "couldn't load the PAC file \(pacURL), so Claude Desktop connects DIRECT"
            return r
        }
        var answers: [[String?]] = []
        for t in targets {
            guard let a = evaluate(script, url: t) else {
                r.note = "PAC script failed, so Claude Desktop connects DIRECT"
                return r
            }
            answers.append(a)
        }
        var first = answers[0]
        // Anthropic hosts get different routes: if either goes DIRECT, use DIRECT
        // so the stricter direct verdict applies to Claude Desktop.
        for other in answers.dropFirst() where other.first! != first.first! && other.first! == nil {
            first = other
        }
        r.pacResult = describe(first)
        r.proxy = first.first ?? nil
        r.http = first.compactMap { $0 }.first { $0.hasPrefix("http://") }
        return r
    }

    /// Runs FindProxyForURL via CFNetwork. Returns proxy URLs in order (nil = DIRECT).
    public static func evaluate(_ script: String, url: String) -> [String?]? {
        guard let target = URL(string: url) else { return nil }
        // CFNetwork ignores Chromium's "SOCKS5"/"SOCKS4"/"HTTPS" keywords; rewrite the answer
        // into ones it understands so we see the same route Claude Desktop (Chromium) takes.
        let wrapped = script + """

        ;(function () {
          var __cgOrig = FindProxyForURL;
          FindProxyForURL = function (u, h) {
            var r = __cgOrig(u, h);
            return (typeof r === "string")
              ? r.replace(/\\bSOCKS[45]\\s/gi, "SOCKS ").replace(/\\bHTTPS\\s/g, "PROXY ")
              : r;
          };
        })();
        """
        var err: Unmanaged<CFError>?
        guard let res = CFNetworkCopyProxiesForAutoConfigurationScript(wrapped as CFString, target as CFURL, &err)?
                .takeRetainedValue() as? [[String: Any]] else {
            err?.release()
            return nil
        }
        var out: [String?] = []
        for p in res {
            let type = p[kCFProxyTypeKey as String] as? String
            let host = p[kCFProxyHostNameKey as String] as? String
            let port = (p[kCFProxyPortNumberKey as String] as? NSNumber)?.intValue
            let none = kCFProxyTypeNone as String, http = kCFProxyTypeHTTP as String
            let https = kCFProxyTypeHTTPS as String, socks = kCFProxyTypeSOCKS as String
            if type == none {
                out.append(nil)
            } else if type == http || type == https {   // "PROXY h:p" (HTTPS = CONNECT for https URLs)
                if let host, let port { out.append("http://\(host):\(port)") }
            } else if type == socks {
                if let host, let port { out.append("socks5://\(host):\(port)") }
            }
        }
        return out.isEmpty ? [nil] : out
    }

    static func describe(_ list: [String?]) -> String {
        list.map { p -> String in
            guard let p else { return "DIRECT" }
            let hp = ProxyURL.hostPort(p)
            let kw = p.hasPrefix("socks") ? "SOCKS5" : "PROXY"
            return "\(kw) \(hp?.host ?? "?"):\(hp?.port ?? 0)"
        }.joined(separator: "; ")
    }

    /// Downloads a PAC file directly (never through a proxy). file:// is supported.
    static func fetch(_ s: String) async -> String? {
        guard let url = URL(string: s) else { return nil }
        if url.isFileURL { return try? String(contentsOf: url, encoding: .utf8) }
        let cfg = URLSessionConfiguration.ephemeral
        cfg.connectionProxyDictionary = [:]
        cfg.timeoutIntervalForRequest = 5
        cfg.timeoutIntervalForResource = 6
        let session = URLSession(configuration: cfg)
        defer { session.finishTasksAndInvalidate() }
        guard let (data, resp) = try? await session.data(from: url),
              (resp as? HTTPURLResponse)?.statusCode == 200 else { return nil }
        return String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
    }
}
