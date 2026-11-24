import Foundation

/// Side effects the Claude Code hook needs (injectable for tests).
public struct HookDeps {
    public var load: () -> GuardStatus?
    public var refresh: () -> Void
    public var checkVia: (String) -> Verdict      // live check of Claude Code's own proxy
    public var env: [String: String]              // Claude Code's environment (hooks inherit it)
    public var wait: TimeInterval
    public var cachePath: String?
    public var cli: String

    public init(load: @escaping () -> GuardStatus?, refresh: @escaping () -> Void,
                checkVia: @escaping (String) -> Verdict, env: [String: String],
                wait: TimeInterval, cachePath: String?, cli: String) {
        self.load = load
        self.refresh = refresh
        self.checkVia = checkVia
        self.env = env
        self.wait = wait
        self.cachePath = cachePath
        self.cli = cli
    }
}

/// Decides whether Claude Code may send a prompt.
///
/// Claude Code ignores the macOS system proxy; it only uses https_proxy / HTTPS_PROXY /
/// http_proxy / HTTP_PROXY. So the route that matters is decided by its environment:
///  - proxy env set -> the prompt goes through that proxy: allowed if it exits abroad;
///  - no proxy env  -> the prompt goes direct: allowed only if the direct route is verified.
public enum Hook {
    static let cacheTTL: TimeInterval = 60

    public static func run(_ d: HookDeps) -> (allow: Bool, message: String) {
        guard var s = d.load(), !s.isStale else {
            return (false, "⛔ ClaudeGuard: the protection service is not running, so your location can't be verified.\n" +
                           "Prompt blocked to avoid leaking an Iranian IP. Reinstall/restart ClaudeGuard.\n")
        }

        var note: String?
        if let proxy = ProxyURL.claudeCode(d.env) {
            if let a = (s.apps ?? []).first(where: { $0.servesPort(proxy) && $0.sendsClaudeDirect }) {
                // Claude Code's proxy is Clash/sing-box, whose rules send Claude DIRECT:
                // the prompt really leaves through the direct route.
                note = "Claude Code's proxy \(proxy) is \(a.name), which sends Claude DIRECT (\(a.anthropic.rule ?? "?")). " +
                       "Route anthropic.com and claude.ai through your proxy (group / outbound).\n"
            } else {
                return viaProxy(d, s, proxy)
            }
        }
        let r = direct(d, &s)
        if !r.allow, let note { return (false, r.message.trimmingCharacters(in: .newlines) + "\n" + note) }
        return r
    }

    static func direct(_ d: HookDeps, _ s: inout GuardStatus) -> (allow: Bool, message: String) {
        // Direct route.
        if !s.enforcing && s.state != .blocked { return (true, "") }
        let asked = Date().addingTimeInterval(-1)
        d.refresh()   // maybe the VPN was just turned on
        let deadline = Date().addingTimeInterval(d.wait)
        while Date() < deadline {
            Thread.sleep(forTimeInterval: 0.25)
            if let cur = d.load(), cur.state != .checking, let c = cur.checkedAt, c >= asked {
                s = cur
                if !s.enforcing { return (true, "") }
                break
            }
        }

        let ip = s.ipv4 ?? s.ipv6 ?? "-"
        let place = s.inIran ? "IRAN" : "an unverified location"
        if s.state == .proxyOnly, let http = s.proxy?.system.http {
            return (false, """
            ⛔ ClaudeGuard: your direct connection is in \(place) (IP \(ip)) and this Claude Code session is NOT using your v2ray proxy.
            Claude Code ignores the system proxy. Route it through v2ray:
                \(d.cli) claude-proxy on      (then restart Claude Code)
            or start Claude Code with  HTTPS_PROXY=\(http) claude

            """)
        }
        if s.state == .proxyOnly {
            return (false, "⛔ ClaudeGuard: your direct connection is in \(place) (IP \(ip)). Your system proxy is SOCKS-only, " +
                           "which Claude Code can't use. Enable v2ray's HTTP proxy and set HTTPS_PROXY to it, or use TUN mode.\n")
        }
        if let a = (s.apps ?? []).first(where: { $0.sendsClaudeDirect }) {
            return (false, "⛔ ClaudeGuard: Claude is blocked - \(a.name) sends Claude traffic DIRECT (\(a.anthropic.rule ?? "?")), " +
                           "so your real IP \(ip) would be used.\nRoute anthropic.com and claude.ai through your proxy (group / outbound) in \(a.name), " +
                           "then click Refresh in the ClaudeGuard menu bar icon.\n")
        }
        if s.inIran, let n = s.network, n.bound == true {
            return (false, """
            ⛔ ClaudeGuard: You are in IRAN (IP \(ip)): your VPN is on, but Anthropic traffic BYPASSES it (goes via \(n.anthropicIface ?? "?")).
            Claude is blocked so your Iranian IP is not sent to Anthropic. Fix your VPN's split-tunnel/bypass rules, then click Refresh in the ClaudeGuard menu bar icon.

            """)
        }
        if s.inIran, let n = s.network, n.tunnelActive {
            return (false, """
            ⛔ ClaudeGuard: You are in IRAN (IP \(ip)), even though a TUN VPN (\(n.tunnelName ?? "?")) is up - is it connected?
            Claude is blocked so your Iranian IP is not sent to Anthropic. Click Refresh in the ClaudeGuard menu bar icon (or send your prompt again).

            """)
        }
        if s.inIran {
            return (false, """
            ⛔ ClaudeGuard: You are in IRAN (IP \(ip)).
            Claude is blocked so your Iranian IP is not sent to Anthropic.
            Turn on your VPN (TUN mode, or system-proxy mode + `\(d.cli) claude-proxy on`), then click Refresh in the ClaudeGuard menu bar icon (or just send your prompt again).

            """)
        }
        return (false, "⛔ ClaudeGuard: Claude is blocked - \(s.message)\n" +
                       "Click Refresh in the ClaudeGuard menu bar icon (or send your prompt again) once you're connected.\n")
    }

    static func viaProxy(_ d: HookDeps, _ s: GuardStatus, _ proxy: String) -> (allow: Bool, message: String) {
        if proxy.lowercased().hasPrefix("socks") {
            return (false, "⛔ ClaudeGuard: Claude Code's proxy is \(proxy), but Claude Code doesn't support SOCKS proxies.\n" +
                           "Set HTTPS_PROXY to v2ray's HTTP port instead (e.g. http://127.0.0.1:10809).\n")
        }
        if let route = s.proxy, route.ok, ProxyURL.sameEndpoint(proxy, route.checked) {
            return (true, "")
        }
        if readCache(d.cachePath, proxy) { return (true, "") }
        let v = d.checkVia(proxy)
        switch v.kind {
        case .allowed:
            writeCache(d.cachePath, proxy)
            return (true, "")
        case .iran:
            return (false, "⛔ ClaudeGuard: Claude Code's proxy \(proxy) exits in IRAN. \(v.detail)\n" +
                           "Prompt blocked so your Iranian IP is not sent to Anthropic. Check your v2ray server/routing.\n")
        case .unknown:
            return (false, "⛔ ClaudeGuard: couldn't verify Claude Code's proxy \(proxy): \(v.detail)\n" +
                           "Make sure v2ray is running and connected, then send your prompt again.\n")
        }
    }

    struct Cache: Codable { var proxy: String; var checkedAt: Date }

    static func readCache(_ path: String?, _ proxy: String) -> Bool {
        guard let path, let data = FileManager.default.contents(atPath: path),
              let c = try? JSONDecoder().decode(Cache.self, from: data) else { return false }
        return ProxyURL.sameEndpoint(c.proxy, proxy) && Date().timeIntervalSince(c.checkedAt) < cacheTTL
    }

    static func writeCache(_ path: String?, _ proxy: String) {
        guard let path, let data = try? JSONEncoder().encode(Cache(proxy: proxy, checkedAt: Date())) else { return }
        FileManager.default.createFile(atPath: path, contents: data, attributes: [.posixPermissions: 0o600])
    }
}
