import Foundation
import Darwin
import Network

public struct Verdict {
    public enum Kind: String { case allowed, iran, unknown }
    public var kind: Kind
    public var ipv4: String?
    public var ipv6: String?
    public var country: String?
    public var detail: String

    public init(kind: Kind, ipv4: String? = nil, ipv6: String? = nil, country: String? = nil, detail: String) {
        self.kind = kind
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.country = country
        self.detail = detail
    }
}

/// Finds the public IPv4/IPv6 addresses (and their countries) that a route exits from:
/// the DIRECT route (never the system proxy), a given proxy, or a specific network
/// interface (used when Anthropic traffic bypasses a TUN VPN).
///
/// Rules (fail-closed):
///  - no public IP found at all            -> unknown (block)
///  - ANY address geolocates to IR         -> iran    (block)
///  - any address whose country is unknown -> unknown (block)
///  - otherwise                            -> allowed
/// Several geo services are asked in parallel; if any of them says IR, it's IR.
public final class IPChecker {
    static let v4Endpoints = ["https://api4.ipify.org", "https://ipv4.icanhazip.com"]
    static let v6Endpoints = ["https://api6.ipify.org", "https://ipv6.icanhazip.com"]

    typealias Fetch = (String) async -> String?

    private var sessions: [String: URLSession] = [:]   // "" = direct
    private var cache: [String: String] = [:]          // ip -> country code
    private let lock = NSLock()

    public init() {}

    public func clearCache() {
        lock.withLock { cache.removeAll() }
    }

    private func session(_ proxy: String?) -> URLSession {
        let key = proxy ?? ""
        return lock.withLock {
            if let s = sessions[key] { return s }
            let cfg = URLSessionConfiguration.ephemeral
            cfg.timeoutIntervalForRequest = 6
            cfg.timeoutIntervalForResource = 8
            cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            cfg.urlCache = nil
            cfg.waitsForConnectivity = false
            cfg.httpShouldUsePipelining = false
            cfg.httpMaximumConnectionsPerHost = 2
            cfg.httpAdditionalHeaders = ["User-Agent": "ClaudeGuard/1.0", "Accept": "*/*"]
            // IMPORTANT: an empty dictionary disables proxies. The default (nil) silently
            // uses the macOS system proxy, which Claude Code itself ignores.
            cfg.connectionProxyDictionary = ProxyURL.sessionDictionary(proxy)
            let s = URLSession(configuration: cfg)
            sessions[key] = s
            return s
        }
    }

    /// Checks the direct route.
    public func check() async -> Verdict { await check(via: nil) }

    /// Checks the route through `proxy` (nil = direct).
    public func check(via proxy: String?) async -> Verdict {
        let s = session(proxy)
        return await check(fetch: { await Self.get(s, $0) }, failure: proxy.map {
            "Couldn't reach the internet through the proxy \($0) (is v2ray connected?)."
        })
    }

    /// Checks the exit of one specific network interface (IPv4), e.g. "en0".
    public func check(interface name: String) async -> Verdict {
        guard let iface = await BoundHTTP.interface(named: name) else {
            return Verdict(kind: .unknown, detail: "Network interface \(name) isn't available.")
        }
        return await check(fetch: { await BoundHTTP.get($0, via: iface) },
                           failure: "Couldn't reach the internet through \(name).", ipv6: false)
    }

    private func check(fetch: @escaping Fetch, failure: String?, ipv6: Bool = true) async -> Verdict {
        async let a = firstIP(fetch, Self.v4Endpoints, family: AF_INET)
        async let b = ipv6 ? firstIP(fetch, Self.v6Endpoints, family: AF_INET6) : nil
        let ip4 = await a
        let ip6 = await b

        if ip4 == nil && ip6 == nil {
            return Verdict(kind: .unknown, detail: failure
                ?? "Couldn't determine your public IP (offline, or IP-check services unreachable).")
        }

        async let ca: String? = ip4 == nil ? nil : country(fetch, ip4!)
        async let cb: String? = ip6 == nil ? nil : country(fetch, ip6!)
        let c4 = await ca
        let c6 = await cb
        return Self.decide(ip4: ip4, c4: c4, ip6: ip6, c6: c6)
    }

    static func decide(ip4: String?, c4: String?, ip6: String?, c6: String?) -> Verdict {
        if c4 == "IR" || c6 == "IR" {
            let ip = c4 == "IR" ? ip4! : ip6!
            return Verdict(kind: .iran, ipv4: ip4, ipv6: ip6, country: "IR",
                           detail: "Your public IP \(ip) is located in Iran.")
        }
        if let ip4, c4 == nil {
            return Verdict(kind: .unknown, ipv4: ip4, ipv6: ip6, country: c6,
                           detail: "Couldn't determine which country your IP \(ip4) is in.")
        }
        if let ip6, c6 == nil {
            return Verdict(kind: .unknown, ipv4: ip4, ipv6: ip6, country: c4,
                           detail: "Couldn't determine which country your IPv6 \(ip6) is in.")
        }
        let c = c4 ?? c6
        return Verdict(kind: .allowed, ipv4: ip4, ipv6: ip6, country: c,
                       detail: "Your public IP is in \(CountryInfo.name(c)).")
    }

    // MARK: - IP

    private func firstIP(_ fetch: Fetch, _ urls: [String], family: Int32) async -> String? {
        for u in urls {
            if let t = await fetch(u), Self.isIP(t, family: family) { return t }
        }
        return nil
    }

    static func isIP(_ s: String, family: Int32) -> Bool {
        var buf = [UInt8](repeating: 0, count: 16)
        return inet_pton(family, s, &buf) == 1
    }

    // MARK: - Country

    /// Country of `ip`, looked up directly.
    public func country(for ip: String) async -> String? {
        let s = session(nil)
        return await country({ await Self.get(s, $0) }, ip)
    }

    private func country(_ fetch: @escaping Fetch, _ ip: String) async -> String? {
        let cached = lock.withLock { cache[ip] }
        if let cached { return cached }

        let enc = ip.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ip
        async let a = fetch("https://ipinfo.io/\(enc)/country")
        async let b = fetch("https://ipapi.co/\(enc)/country/")
        async let c = fetch("https://api.country.is/\(enc)")

        let answers = [Self.code(await a), Self.code(await b), Self.countryIs(await c)].compactMap { $0 }
        guard let first = answers.first else { return nil }
        let result = answers.contains("IR") ? "IR" : first

        lock.withLock { cache[ip] = result }
        return result
    }

    static func code(_ s: String?) -> String? {
        guard let s = s?.trimmingCharacters(in: .whitespacesAndNewlines).uppercased(),
              s.count == 2, s.allSatisfy({ $0 >= "A" && $0 <= "Z" }) else { return nil }
        return s
    }

    static func countryIs(_ s: String?) -> String? {
        guard let s, let data = s.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return code(obj["country"] as? String)
    }

    // MARK: - HTTP

    static func get(_ s: URLSession, _ str: String) async -> String? {
        guard let url = URL(string: str) else { return nil }
        do {
            let (data, resp) = try await s.data(from: url)
            guard let http = resp as? HTTPURLResponse, http.statusCode == 200 else { return nil }
            return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
        } catch {
            return nil
        }
    }
}

/// Minimal HTTPS GET pinned to one network interface (Network.framework sets
/// IP_BOUND_IF, and DNS is scoped to that interface too).
enum BoundHTTP {
    static func interface(named name: String) async -> NWInterface? {
        await withCheckedContinuation { cont in
            let monitor = NWPathMonitor()
            let once = Once()
            monitor.pathUpdateHandler = { path in
                once.run {
                    cont.resume(returning: path.availableInterfaces.first { $0.name == name })
                    monitor.cancel()
                }
            }
            monitor.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + 3) {
                once.run { cont.resume(returning: nil); monitor.cancel() }
            }
        }
    }

    static func get(_ str: String, via iface: NWInterface) async -> String? {
        guard let url = URL(string: str), let host = url.host else { return nil }
        let params = NWParameters.tls
        params.requiredInterface = iface
        params.preferNoProxies = true
        let conn = NWConnection(host: NWEndpoint.Host(host), port: 443, using: params)
        let buffer = Buffer()
        let once = Once()

        return await withCheckedContinuation { cont in
            func finish(_ s: String?) {
                once.run { conn.cancel(); cont.resume(returning: s) }
            }
            func receive() {
                conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, complete, error in
                    if let data { buffer.append(data) }
                    if complete || error != nil { finish(parse(buffer.data)) } else { receive() }
                }
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    // URLComponents keeps the trailing slash (ipapi.co needs it); URL.path drops it.
                    let raw = URLComponents(string: str)?.percentEncodedPath ?? ""
                    let path = raw.isEmpty ? "/" : raw
                    let req = "GET \(path) HTTP/1.0\r\n" +
                              "Host: \(host)\r\nUser-Agent: ClaudeGuard/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                    conn.send(content: Data(req.utf8), completion: .contentProcessed { error in
                        if error != nil { finish(nil) } else { receive() }
                    })
                case .failed, .waiting, .cancelled:
                    finish(nil)
                default:
                    break
                }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + 8) { finish(nil) }
        }
    }

    static func parse(_ d: Data) -> String? {
        let s = String(decoding: d, as: UTF8.self)
        guard let split = s.range(of: "\r\n\r\n") else { return nil }
        let statusLine = s[..<split.lowerBound].split(separator: "\r\n").first ?? ""
        guard statusLine.contains(" 200") else { return nil }
        return String(s[split.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    final class Once: @unchecked Sendable {
        private var done = false
        private let lock = NSLock()
        func run(_ f: () -> Void) {
            lock.lock()
            if done { lock.unlock(); return }
            done = true
            lock.unlock()
            f()
        }
    }

    final class Buffer: @unchecked Sendable {
        private(set) var data = Data()
        private let lock = NSLock()
        func append(_ d: Data) { lock.withLock { data.append(d) } }
    }
}
