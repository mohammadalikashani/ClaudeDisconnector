import Foundation
import Darwin

/// Which network interfaces traffic takes, to detect TUN-mode VPNs (v2rayN/V2Box/
/// sing-box/Clash TUN, WireGuard, OpenVPN, ...) and Anthropic traffic that bypasses them.
public struct NetInfo: Codable, Equatable {
    /// api.anthropic.com / claude.ai. Only its ROUTE is looked up; nothing is sent to it.
    public static let anthropicProbeIP = "160.79.104.10"
    /// IP-check site whose route is compared with Anthropic's.
    public static let checkProbeHost = "api4.ipify.org"

    public var checkIface: String?
    public var checkIsTunnel: Bool?
    public var anthropicIface: String?
    public var anthropicIsTunnel: Bool?
    public var tunnelName: String?
    /// The direct check was pinned to `anthropicIface` because Anthropic bypasses the tunnel.
    public var bound: Bool?

    public init() {}

    public var tunnelActive: Bool { checkIsTunnel == true || anthropicIsTunnel == true }

    /// Anthropic traffic leaves through a different interface than the IP-check sites.
    public var anthropicBypassesCheck: Bool {
        guard let c = checkIface, let a = anthropicIface else { return false }
        return c != a
    }

    public var summary: String {
        let name = tunnelName ?? "?"
        if anthropicBypassesCheck && checkIsTunnel == true && anthropicIsTunnel != true {
            return "TUN VPN \(name) is on, but Anthropic traffic BYPASSES it (goes via \(anthropicIface ?? "?"))"
        }
        if anthropicBypassesCheck {
            return "Anthropic traffic goes via \(anthropicIface ?? "?"), other traffic via \(checkIface ?? "?")"
        }
        if tunnelActive { return "TUN VPN on: \(name)" }
        if let c = checkIface { return "No TUN VPN (traffic goes via \(c))" }
        return "unknown"
    }

    public static func isTunnel(_ name: String) -> Bool {
        ["utun", "tun", "tap", "ipsec", "ppp", "wg"].contains { name.hasPrefix($0) }
    }

    /// Looks up the routes (via /sbin/route) for Anthropic and for the IP-check site.
    public static func current() -> NetInfo {
        var n = NetInfo()
        // The IP-check host may resolve to a TUN "fake-ip" (198.18.x.x) - that's its real path too.
        let checkIP = resolve4(checkProbeHost) ?? "1.1.1.1"
        if let i = routeInterface(checkIP) {
            n.checkIface = i
            n.checkIsTunnel = isTunnel(i)
            if isTunnel(i) { n.tunnelName = i }
        }
        if let i = routeInterface(anthropicProbeIP) {
            n.anthropicIface = i
            n.anthropicIsTunnel = isTunnel(i)
            if isTunnel(i) { n.tunnelName = i }
        }
        return n
    }

    static func routeInterface(_ ip: String) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/sbin/route")
        p.arguments = ["-n", "get", ip]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return nil }
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        for line in out.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("interface:") {
                return t.dropFirst("interface:".count).trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    static func resolve4(_ host: String) -> String? {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_STREAM,
                             ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let ai = res else { return nil }
        defer { freeaddrinfo(res) }
        var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &buf, socklen_t(buf.count),
                          nil, 0, NI_NUMERICHOST) == 0 else { return nil }
        return String(cString: buf)
    }
}
