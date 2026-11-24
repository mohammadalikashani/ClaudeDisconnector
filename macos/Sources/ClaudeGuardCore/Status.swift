import Foundation
import Darwin
import notify

public enum GuardPaths {
    public static let supportDir = "/Library/Application Support/ClaudeGuard"
    /// CLAUDEGUARD_STATUS_FILE overrides the location (for testing the UI without the daemon).
    public static let statusFile = ProcessInfo.processInfo.environment["CLAUDEGUARD_STATUS_FILE"]
        ?? supportDir + "/status.json"
    public static let pfRulesFile = supportDir + "/pf.rules"
    public static let pfTokenFile = supportDir + "/pf.token"
    public static let daemonBinary = "/Library/PrivilegedHelperTools/claudeguardd"
}

/// Darwin notifications (system-wide, no privileges needed to post).
public enum GuardNotify {
    /// App / hook -> daemon: "check my IP again now".
    public static let refresh = "com.claudeguard.refresh"
    /// Daemon -> app: "status.json changed".
    public static let statusChanged = "com.claudeguard.status"

    public static func post(_ name: String) {
        notify_post(name)
    }

    @discardableResult
    public static func observe(_ name: String, queue: DispatchQueue, _ handler: @escaping () -> Void) -> Int32 {
        var token: Int32 = 0
        notify_register_dispatch(name, &token, queue) { _ in handler() }
        return token
    }
}

public struct GuardStatus: Codable, Equatable {
    public enum State: String, Codable {
        case allowed    // direct route verified, not Iran
        case proxyOnly  // direct route Iran/unknown (blocked), system proxy exits abroad
        case blocked    // Iran / unverified, and no safe proxy
        case checking   // a check is in progress
    }

    public var state: State
    /// Direct connections to Anthropic are blocked (pf). Traffic through a local
    /// proxy (v2ray) is not affected by this block.
    public var enforcing: Bool
    /// The DIRECT route exits in Iran.
    public var inIran: Bool
    public var message: String
    /// Direct route (what Claude Code uses without proxy env vars).
    public var ipv4: String?
    public var ipv6: String?
    public var country: String?
    /// System-proxy route (what Claude Desktop uses), if a system proxy is set.
    public var proxy: ProxyRoute?
    /// Which interfaces traffic takes (TUN VPN detection).
    public var network: NetInfo?
    /// Detected Clash / sing-box instances and how they route Claude.
    public var apps: [ProxyApp]?
    /// Claude Desktop is being quit because its route exits in Iran.
    public var desktopBlocked: Bool?
    /// When the last check completed.
    public var checkedAt: Date?
    /// Heartbeat: daemon rewrites the file periodically. Stale => daemon not running.
    public var updatedAt: Date

    /// If the daemon hasn't written the status for this long, assume it is dead.
    public static let staleAfter: TimeInterval = 90

    public init(state: State, enforcing: Bool, inIran: Bool, message: String,
                ipv4: String? = nil, ipv6: String? = nil, country: String? = nil,
                proxy: ProxyRoute? = nil, desktopBlocked: Bool = false,
                checkedAt: Date? = nil, updatedAt: Date = Date()) {
        self.state = state
        self.enforcing = enforcing
        self.inIran = inIran
        self.message = message
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.country = country
        self.proxy = proxy
        self.desktopBlocked = desktopBlocked
        self.checkedAt = checkedAt
        self.updatedAt = updatedAt
    }

    public var isStale: Bool { Date().timeIntervalSince(updatedAt) > Self.staleAfter }

    /// Equal ignoring the heartbeat timestamp.
    public func sameContent(as other: GuardStatus?) -> Bool {
        guard var o = other else { return false }
        o.updatedAt = updatedAt
        return o == self
    }

    // MARK: persistence

    static var encoder: JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return e
    }

    static var decoder: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }

    public static func load(from path: String = GuardPaths.statusFile) -> GuardStatus? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return try? decoder.decode(GuardStatus.self, from: data)
    }

    public func save(to path: String = GuardPaths.statusFile) throws {
        let data = try Self.encoder.encode(self)
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
    }

    public func jsonString() -> String {
        (try? Self.encoder.encode(self)).map { String(decoding: $0, as: UTF8.self) } ?? "{}"
    }
}

public enum CountryInfo {
    public static func name(_ code: String?) -> String {
        guard let code else { return "Unknown" }
        return Locale(identifier: "en_US").localizedString(forRegionCode: code) ?? code
    }

    public static func flag(_ code: String?) -> String {
        guard let code, code.count == 2 else { return "🌐" }
        var s = ""
        for u in code.uppercased().unicodeScalars {
            if let f = UnicodeScalar(0x1F1E6 + u.value - 65) { s.unicodeScalars.append(f) }
        }
        return s
    }
}
