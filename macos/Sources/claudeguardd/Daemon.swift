import Foundation
import Network
import ClaudeGuardCore

/// Root LaunchDaemon. Fail-closed:
///  - blocks Claude immediately at startup, then checks;
///  - blocks immediately whenever the network changes (VPN drop, Wi-Fi switch), then re-checks;
///  - re-checks every `pollInterval` seconds, when the system proxy changes, and on demand;
///  - lifts the block only after a positive verdict.
///
/// Two routes are checked: DIRECT (Claude Code without proxy env vars) and the SYSTEM
/// PROXY (Claude Desktop; v2ray "system proxy" mode). Direct connections to Anthropic
/// are firewalled whenever the direct route isn't verified; traffic via a proxy that
/// exits abroad keeps working.
final class Daemon {
    let pollInterval: TimeInterval = 15

    private struct Result {
        var direct: Verdict
        var route: DesktopRoute?   // nil when no system proxy / PAC is set
        var proxy: Verdict?        // nil when Claude Desktop's route is DIRECT
        var system: SystemProxy
        var net: NetInfo
        var apps: [ProxyApp]
        var decision: AppDecision
        var physical: String?
    }

    private let q = DispatchQueue(label: "com.claudeguard.daemon")
    private let checker = IPChecker()
    private let enforcer = Enforcer()
    private let monitor = NWPathMonitor()
    private var status: GuardStatus
    private var checking = false
    private var generation = 0
    private var lastPathSignature: String?
    private var lastProxy = SystemProxy.current()
    private var timers: [DispatchSourceTimer] = []

    init() {
        status = GuardStatus(state: .checking, enforcing: true, inIran: false,
                             message: "Starting up - verifying your location…")
    }

    func run() -> Never {
        q.sync {
            try? FileManager.default.createDirectory(atPath: GuardPaths.supportDir,
                                                     withIntermediateDirectories: true,
                                                     attributes: [.posixPermissions: 0o755])
            enforcer.releasePFToken()       // drop a stale reference from a previous run
            enforcer.block(force: true)     // fail closed until proven otherwise
            if let previous = GuardStatus.load() {   // keep showing the Iran banner across restarts
                status.inIran = previous.inIran
                status.desktopBlocked = previous.desktopBlocked
            }
            publish(force: true)
        }

        GuardNotify.observe(GuardNotify.refresh, queue: q) { [weak self] in
            log("refresh requested")
            self?.requestCheck(urgent: true, clearCache: true, message: "Checking your IP…")
        }

        monitor.pathUpdateHandler = { [weak self] path in self?.pathChanged(path) }
        monitor.start(queue: q)

        addTimer(every: pollInterval) { [weak self] in self?.requestCheck(urgent: false, clearCache: false) }
        addTimer(every: 3) { [weak self] in self?.enforceTick() }

        q.async { self.requestCheck(urgent: true, clearCache: false, message: "Starting up - verifying your location…") }
        dispatchMain()
    }

    // MARK: - checks (always on q)

    private func requestCheck(urgent: Bool, clearCache: Bool, message: String = "Checking your IP…") {
        dispatchPrecondition(condition: .onQueue(q))
        if clearCache { checker.clearCache() }
        if urgent {
            generation += 1   // invalidates any in-flight result
            status.state = .checking
            status.message = message
            publish()
        } else if checking {
            publish()  // heartbeat only
            return
        }
        if checking { return }    // completion will notice the generation bump and re-run
        startCheck()
    }

    private func startCheck() {
        checking = true
        let gen = generation
        let system = SystemProxy.current()
        lastProxy = system
        let checker = self.checker
        Task {
            // TUN detection: which interface carries Anthropic's traffic vs the IP-check sites?
            var info = NetInfo.current()
            let bypass = info.anthropicBypassesCheck
            info.bound = bypass
            let net = info

            // Clash / sing-box: read their configs + APIs to see how they route Claude.
            let procs = ProxyApps.processes()
            let apps = await ProxyApps.detect(procs.configs + ProxyApps.candidates(home: ProxyApps.consoleUserHome()),
                                              running: { procs.running.contains($0) })
            var route: DesktopRoute?
            if system.enabled || system.pac != nil {
                route = await PAC.resolveDesktopRoute(system)   // evaluates the PAC file in PAC mode
            }
            let decision = ProxyApps.decide(apps, anthropicInTunnel: net.anthropicIsTunnel == true || net.checkIsTunnel == true,
                                            desktopProxy: route?.proxy)

            // An app that carries Claude sends it DIRECT: in TUN mode its DIRECT outbound
            // uses the real (physical) connection.
            var physicalVerdict: Verdict?
            var physical: String?
            if decision.tunDirect != nil || decision.proxyDirect?.tun == true {
                physical = ProxyApps.physicalInterface()
                physicalVerdict = physical == nil
                    ? Verdict(kind: .unknown, detail: "Couldn't find your physical network connection to verify.")
                    : await checker.check(interface: physical!)
            }

            let direct: Verdict
            if decision.tunDirect != nil {
                direct = physicalVerdict!
            } else if bypass {
                // Anthropic traffic leaves through a different interface (e.g. it bypasses the
                // TUN VPN): check the exit IP of THAT interface.
                direct = await checker.check(interface: net.anthropicIface!)
            } else {
                direct = await checker.check(via: nil)
            }
            var proxy: Verdict?
            if let p = route?.proxy {
                if decision.proxyDirect != nil {
                    proxy = physicalVerdict ?? direct   // non-TUN app: its DIRECT follows the normal route
                } else {
                    proxy = await checker.check(via: p)
                }
            }
            let result = Result(direct: direct, route: route, proxy: proxy, system: system, net: net,
                                apps: apps, decision: decision, physical: physical)
            q.async {
                self.checking = false
                if gen != self.generation {
                    self.startCheck()
                } else {
                    self.apply(result)
                }
            }
        }
    }

    private func apply(_ r: Result) {
        let d = r.direct

        // Claude Desktop's route (manual system proxy, or whatever the PAC file says).
        var route: ProxyRoute?
        var desktopIran = d.kind == .iran
        if let rt = r.route {
            var sys = r.system
            sys.http = rt.http
            if let p = r.proxy {
                route = ProxyRoute(system: sys, mode: rt.mode, checked: rt.proxy, pacResult: rt.pacResult,
                                   kind: p.kind.rawValue, ok: p.kind == .allowed,
                                   ipv4: p.ipv4, ipv6: p.ipv6, country: p.country, detail: p.detail)
                desktopIran = p.kind == .iran
            } else {
                // DIRECT: Claude Desktop shares the direct route's verdict.
                route = ProxyRoute(system: sys, mode: rt.mode, checked: nil, pacResult: rt.pacResult,
                                   kind: d.kind.rawValue, ok: false, ipv4: d.ipv4, ipv6: d.ipv6, country: d.country,
                                   detail: rt.note.map { "The \($0)." } ?? "The PAC file sends Claude traffic DIRECT.")
            }
        }
        let proxyOK = route?.ok == true

        let state: GuardStatus.State
        var msg: String
        if d.kind == .allowed {
            enforcer.unblock()
            state = .allowed
            msg = "\(d.detail) Claude is allowed."
            if desktopIran { msg += " But your system proxy exits in Iran, so Claude Desktop is blocked." }
        } else if proxyOK, let route {
            // Direct route is Iran/unknown: firewall direct access, keep hosts clean for v2ray.
            enforcer.set(pf: true, hosts: false)
            state = .proxyOnly
            msg = "Direct connection: \(d.detail) Direct access to Claude is blocked. " +
                  "Your proxy \(route.describe) exits in \(CountryInfo.name(route.country)), " +
                  "so Claude Desktop works, and Claude Code works when it uses the proxy (HTTPS_PROXY)."
        } else {
            enforcer.block()
            state = .blocked
            msg = d.kind == .iran
                ? "\(d.detail) Claude Code and Claude Desktop are blocked so your Iranian IP is not sent to Anthropic."
                : "\(d.detail) Claude stays blocked until your location can be verified."
            if let route { msg += " System proxy: \(route.detail)" }
        }
        // Clash / sing-box routing rules.
        if let a = r.decision.tunDirect {
            msg = "\(a.name) sends Claude traffic DIRECT (\(a.anthropic.rule ?? "?")), so Claude uses your real connection" +
                  (r.physical.map { " (\($0))" } ?? "") + ". Route anthropic.com and claude.ai through your proxy (group / outbound). " + msg
        } else if let a = r.decision.proxyDirect {
            msg += " \(a.name) (behind your system proxy) sends Claude traffic DIRECT (\(a.anthropic.rule ?? "?")), so Claude Desktop is treated as direct."
        }
        if let a = r.decision.misrouted, state == .blocked {
            msg += " Note: \(a.name) sends Claude through the proxy but the IP-check sites DIRECT, so ClaudeGuard sees your real IP. " +
                   "Add rules sending \(RuleEngine.checkHosts.joined(separator: ", ")) through the same proxy."
        }
        if let a = r.apps.first(where: { $0.anthropic.outcome == .unknown && ($0.tun == true || $0.servesPort(r.route?.proxy)) }) {
            msg += " Warning: can't tell whether \(a.name) sends Claude DIRECT (\(a.anthropic.rule ?? "?"))."
        }

        // TUN VPN context.
        if r.net.bound == true {
            msg = "Your VPN doesn't carry Anthropic traffic (it goes via \(r.net.anthropicIface ?? "?")), so that path was checked. " + msg
        } else if d.kind == .iran && r.net.tunnelActive {
            msg += " Your TUN VPN (\(r.net.tunnelName ?? "?")) is up, but traffic still exits in Iran - is it connected?"
        }
        if desktopIran { quitClaudeDesktop() }

        status = GuardStatus(state: state, enforcing: enforcer.isBlocked, inIran: d.kind == .iran, message: msg,
                             ipv4: d.ipv4, ipv6: d.ipv6, country: d.country, proxy: route,
                             desktopBlocked: desktopIran, checkedAt: Date())
        status.network = r.net
        status.apps = r.apps.isEmpty ? nil : r.apps
        let proxyLog = route.map { "\($0.describe)=\($0.kind)/\($0.country ?? "-")" } ?? "-"
        log("state=\(state.rawValue) direct=\(d.kind.rawValue) v4=\(d.ipv4 ?? "-") v6=\(d.ipv6 ?? "-") country=\(d.country ?? "-") proxy=\(proxyLog) net=[\(r.net.summary)]")
        publish()
    }

    // MARK: - network changes

    private func pathChanged(_ path: NWPath) {
        let sig = "\(path.status)|" + path.availableInterfaces.map { $0.name }.sorted().joined(separator: ",")
        defer { lastPathSignature = sig }
        guard let last = lastPathSignature, last != sig else { return }
        log("network changed: \(last) -> \(sig)")
        // Fail closed: cut Claude off right away, then verify the new network.
        enforcer.block()
        requestCheck(urgent: true, clearCache: false, message: "Network changed - re-verifying your location…")
    }

    // MARK: - helpers

    private func enforceTick() {
        if status.desktopBlocked == true { quitClaudeDesktop() }
        let p = SystemProxy.current()
        if p != lastProxy {
            log("system proxy changed: \(lastProxy) -> \(p)")
            lastProxy = p
            requestCheck(urgent: true, clearCache: false, message: "Proxy settings changed - re-verifying…")
        }
    }

    private func quitClaudeDesktop() {
        // Main process of /Applications/Claude.app is named exactly "Claude".
        let r = sh("/usr/bin/pkill", ["-TERM", "-x", "Claude"])
        if r.status == 0 { log("terminated Claude Desktop") }
    }

    private var lastPublished: GuardStatus?

    private func publish(force: Bool = false) {
        status.enforcing = enforcer.isBlocked
        status.updatedAt = Date()
        do { try status.save() } catch { log("ERROR saving status: \(error)") }
        if force || !status.sameContent(as: lastPublished) {
            GuardNotify.post(GuardNotify.statusChanged)
        }
        lastPublished = status
    }

    private func addTimer(every seconds: TimeInterval, _ block: @escaping () -> Void) {
        let t = DispatchSource.makeTimerSource(queue: q)
        t.schedule(deadline: .now() + seconds, repeating: seconds, leeway: .seconds(1))
        t.setEventHandler(handler: block)
        t.resume()
        timers.append(t)
    }
}
