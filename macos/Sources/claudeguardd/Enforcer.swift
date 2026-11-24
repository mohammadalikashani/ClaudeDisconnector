import Foundation
import Darwin
import ClaudeGuardCore

func log(_ msg: String) {
    let ts = ISO8601DateFormatter().string(from: Date())
    FileHandle.standardError.write("\(ts) \(msg)\n".data(using: .utf8)!)
}

@discardableResult
func sh(_ path: String, _ args: [String]) -> (status: Int32, output: String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = pipe
    do { try p.run() } catch { return (-1, "\(error)") }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(decoding: data, as: UTF8.self))
}

/// Blocks/unblocks Anthropic at two layers:
///  1. /etc/hosts  – Claude domains resolve to 0.0.0.0 / ::
///  2. pf firewall – all traffic to Anthropic's IP ranges is rejected and
///                   already-open connections are killed.
/// pf rules live in the "com.apple/250.ClaudeGuard" anchor, which the stock
/// macOS /etc/pf.conf already evaluates (anchor "com.apple/*"), so pf.conf is never edited.
final class Enforcer {
    static let anchor = "com.apple/250.ClaudeGuard"

    /// Anthropic-owned ranges (api.anthropic.com, claude.ai, claude.com all live here).
    static let ranges = ["160.79.104.0/23", "2607:6bc0::/48"]

    /// Resolved at block time and added to the firewall table too (future-proofing
    /// in case one of them moves outside the ranges above).
    static let coreDomains = ["api.anthropic.com", "claude.ai", "claude.com", "anthropic.com"]

    static let hostsDomains = [
        "anthropic.com", "www.anthropic.com", "api.anthropic.com", "console.anthropic.com",
        "statsig.anthropic.com", "mcp-proxy.anthropic.com", "a-api.anthropic.com",
        "a-cdn.anthropic.com", "s-cdn.anthropic.com", "docs.anthropic.com", "support.anthropic.com",
        "claude.ai", "www.claude.ai", "api.claude.ai", "a.claude.ai", "assets.claude.ai",
        "downloads.claude.ai", "storage.claude.ai",
        "claude.com", "www.claude.com", "code.claude.com", "platform.claude.com",
        "api.claude.com", "docs.claude.com", "support.claude.com",
    ]

    /// pf layer: blocks DIRECT traffic to Anthropic. Traffic through a local proxy (v2ray)
    /// is unaffected, because v2ray connects to its own server - unless v2ray routes
    /// Anthropic "direct", which this also catches.
    private(set) var pfOn = false
    /// hosts layer: dropped while a safe proxy route exists, so v2ray's own domain
    /// resolution can't be poisoned by it.
    private(set) var hostsOn = false

    var isBlocked: Bool { pfOn }

    // MARK: - public

    func block(force: Bool = false) { set(pf: true, hosts: true, force: force) }
    func unblock(force: Bool = false) { set(pf: false, hosts: false, force: force) }

    func set(pf: Bool, hosts: Bool, force: Bool = false) {
        if pf != pfOn || force {
            if pf {
                let extraIPs = resolve(Self.coreDomains)   // before the hosts file points them at 0.0.0.0
                loadFirewall(extraIPs: extraIPs)
                killConnections(extraIPs: extraIPs)
                log("pf block ON (extra IPs: \(extraIPs))")
            } else {
                sh("/sbin/pfctl", ["-a", Self.anchor, "-F", "all"])
                releasePFToken()
                log("pf block OFF")
            }
            pfOn = pf
        }
        if hosts != hostsOn || force {
            HostsFile.apply(block: hosts)
            flushDNS()
            hostsOn = hosts
            log("hosts block \(hosts ? "ON" : "OFF")")
        }
    }

    static func firewallRules(extraIPs: [String]) -> String {
        let entries = (ranges + extraIPs).joined(separator: ", ")
        return """
        # Managed by ClaudeGuard. Rejects all traffic to Anthropic while blocked.
        table <claudeguard> const { \(entries) }
        block return out quick to <claudeguard>
        block drop in quick from <claudeguard>

        """
    }

    // MARK: - firewall

    private func loadFirewall(extraIPs: [String]) {
        try? FileManager.default.createDirectory(atPath: GuardPaths.supportDir, withIntermediateDirectories: true)
        let rules = Self.firewallRules(extraIPs: extraIPs)
        do {
            try rules.write(toFile: GuardPaths.pfRulesFile, atomically: true, encoding: .utf8)
        } catch {
            log("ERROR writing pf rules: \(error)")
        }
        let r = sh("/sbin/pfctl", ["-a", Self.anchor, "-f", GuardPaths.pfRulesFile])
        if r.status != 0 { log("ERROR pfctl load: \(r.output)") }
        enablePF()
    }

    /// `pfctl -E` enables pf with a reference token so we never disable pf for anyone else.
    private func enablePF() {
        if let t = try? String(contentsOfFile: GuardPaths.pfTokenFile), !t.isEmpty { return }
        let r = sh("/sbin/pfctl", ["-E"])
        if let range = r.output.range(of: #"Token\s*:\s*(\d+)"#, options: .regularExpression) {
            let token = r.output[range].components(separatedBy: CharacterSet.decimalDigits.inverted).joined()
            try? token.write(toFile: GuardPaths.pfTokenFile, atomically: true, encoding: .utf8)
        } else {
            log("WARN pfctl -E output: \(r.output)")
        }
    }

    func releasePFToken() {
        guard let t = try? String(contentsOfFile: GuardPaths.pfTokenFile)
            .trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty else { return }
        sh("/sbin/pfctl", ["-X", t])
        try? FileManager.default.removeItem(atPath: GuardPaths.pfTokenFile)
    }

    private func killConnections(extraIPs: [String]) {
        for target in Self.ranges + extraIPs {
            let any = target.contains(":") ? "::/0" : "0.0.0.0/0"
            sh("/sbin/pfctl", ["-k", any, "-k", target])
        }
    }

    // MARK: - DNS

    private func flushDNS() {
        sh("/usr/bin/dscacheutil", ["-flushcache"])
        sh("/usr/bin/killall", ["-HUP", "mDNSResponder"])
    }

    private func resolve(_ hosts: [String]) -> [String] {
        var out = Set<String>()
        for h in hosts {
            var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM,
                                 ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
            var res: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(h, nil, &hints, &res) == 0 else { continue }
            var p = res
            while let ai = p {
                var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &buf, socklen_t(buf.count),
                               nil, 0, NI_NUMERICHOST) == 0 {
                    let ip = String(cString: buf)
                    if !["0.0.0.0", "::", "127.0.0.1", "::1"].contains(ip) { out.insert(ip) }
                }
                p = ai.pointee.ai_next
            }
            freeaddrinfo(res)
        }
        return out.sorted()
    }
}

enum HostsFile {
    static let path = "/etc/hosts"
    static let begin = "# >>> ClaudeGuard (managed automatically - do not edit) >>>"
    static let end = "# <<< ClaudeGuard <<<"

    static func render(_ original: String, block: Bool) -> String {
        var lines: [String] = []
        var inside = false
        for line in original.components(separatedBy: "\n") {
            if line == begin { inside = true; continue }
            if line == end { inside = false; continue }
            if !inside { lines.append(line) }
        }
        while let last = lines.last, last.trimmingCharacters(in: .whitespaces).isEmpty { lines.removeLast() }
        if block {
            lines.append("")
            lines.append(begin)
            for d in Enforcer.hostsDomains {
                lines.append("0.0.0.0 \(d)")
                lines.append(":: \(d)")
            }
            lines.append(end)
        }
        return lines.joined(separator: "\n") + "\n"
    }

    static func apply(block: Bool) {
        let original = (try? String(contentsOfFile: path, encoding: .utf8)) ?? ""
        let updated = render(original, block: block)
        guard updated != original else { return }
        do {
            try updated.write(toFile: path, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
        } catch {
            log("ERROR writing \(path): \(error)")
        }
    }
}
