import Foundation
import ClaudeGuardCore

let usage = """
usage: claudeguardd <command>      (installed as `claudeguard`)

  daemon          run the protection service (root; started by launchd)
  check           check the direct route and Claude Desktop's route (system proxy / PAC) once
  check-via <url> check the route through a specific proxy, e.g. http://127.0.0.1:10809
  check-iface <if> check the exit IP of one network interface, e.g. en0 (bypassing any TUN VPN)
  check-apps [files/dirs] show how Clash / sing-box / Xray / Hiddify / NekoBox route Claude (auto-detected, or given config files)
  check-pac <url> evaluate a PAC file for Claude's hosts and check that route
  status          print the current protection status
  refresh         ask the service to re-check your IP now
  claude-proxy on [url] | off | status
                  route Claude Code through v2ray's HTTP proxy (system-proxy mode).
                  Claude Code ignores the macOS system proxy, so this sets HTTPS_PROXY
                  for it in ~/.claude/settings.json.
  remote-api list | add <host:port> [secret] | remove <host:port>
                  a Clash API on another device you use as your proxy, e.g. Clash Meta
                  for Android with Allow LAN (proxy hosts are probed on 9090/9097 anyway; root)
  hook            Claude Code UserPromptSubmit hook
  cleanup         remove all blocks (root; used by uninstall.sh)
  lookup <ip>     print the country of an IP address (for testing)
  print-rules     print the firewall rules and hosts entries that get applied

"""

func isRoot() -> Bool { getuid() == 0 }

func runAsync(_ body: @escaping () async -> Int32) -> Never {
    var code: Int32 = 0
    let sem = DispatchSemaphore(value: 0)
    Task { code = await body(); sem.signal() }
    sem.wait()
    exit(code)
}

func blockingCheck(via proxy: String?) -> Verdict {
    var v = Verdict(kind: .unknown, detail: "check did not finish")
    let sem = DispatchSemaphore(value: 0)
    Task { v = await IPChecker().check(via: proxy); sem.signal() }
    _ = sem.wait(timeout: .now() + 20)
    return v
}

func printVerdict(_ title: String, _ v: Verdict) {
    print("\(title)")
    print("  verdict : \(v.kind.rawValue)")
    print("  ipv4    : \(v.ipv4 ?? "-")")
    print("  ipv6    : \(v.ipv6 ?? "-")")
    print("  country : \(v.country ?? "-") \(CountryInfo.flag(v.country)) \(CountryInfo.name(v.country))")
    print("  detail  : \(v.detail)")
}

func printApp(_ a: ProxyApp) {
    print("\(a.sendsClaudeDirect ? "⚠️  " : "")\(a.describe)")
    print("    source: \(a.source)\n    mode=\(a.mode ?? "-") tun=\(a.tun ?? false) ports=\(a.ports ?? []) live=\(a.live)" + (a.remote.map { " remote=\($0) (another device: its DIRECT is that device's own connection)" } ?? ""))
    print("    IP-check sites -> \(a.check.outcome.rawValue)\(a.checkMisrouted ? "  (misrouted: checks can't see Claude's exit)" : "")")
    if let n = a.note { print("    note: \(n)") }
}

func stderr(_ s: String) { FileHandle.standardError.write(s.data(using: .utf8)!) }

/// Claude Code hook. Exit 2 = block the prompt and show stderr to the user.
func hook() -> Never {
    _ = FileHandle.standardInput.readDataToEndOfFile()  // hook JSON input; not needed
    let r = Hook.run(HookDeps(
        load: { GuardStatus.load() },
        refresh: { GuardNotify.post(GuardNotify.refresh) },
        checkVia: { blockingCheck(via: $0) },
        env: ProcessInfo.processInfo.environment,
        wait: 7,
        cachePath: NSTemporaryDirectory() + "claudeguard-proxycheck.json",
        cli: "claudeguard"))
    if r.allow { exit(0) }
    stderr(r.message)
    exit(2)
}

/// Edits env.HTTPS_PROXY in ~/.claude/settings.json (python keeps the key order).
func editClaudeProxy(_ value: String?) -> Int32 {
    let script = """
    import json, os, shutil, sys
    p = os.path.expanduser("~/.claude/settings.json")
    value = sys.argv[1] if len(sys.argv) > 1 else None
    data = {}
    if os.path.exists(p):
        shutil.copy2(p, p + ".claudeguard-backup")
        with open(p) as f:
            data = json.load(f)
    env = data.get("env", {})
    if value:
        env["HTTPS_PROXY"] = value
        data["env"] = env
    else:
        for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
            env.pop(k, None)
        if env: data["env"] = env
        else: data.pop("env", None)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\\n")
    """
    return sh("/usr/bin/python3", ["-c", script] + (value.map { [$0] } ?? [])).status
}

func claudeProxy(_ args: [String]) -> Never {
    switch args.first ?? "status" {
    case "on":
        var found = args.dropFirst().first.map(ProxyURL.normalize)
        if found == nil {
            // Manual system proxy, or the PAC file's PROXY entry for Anthropic.
            let sem = DispatchSemaphore(value: 0)
            Task { found = await PAC.resolveDesktopRoute(SystemProxy.current()).http; sem.signal() }
            _ = sem.wait(timeout: .now() + 10)
        }
        guard let proxy = found else {
            print("No HTTP proxy found in the system proxy / PAC settings. Turn on v2ray's system proxy or PAC mode, or pass it: claude-proxy on http://127.0.0.1:10809")
            exit(1)
        }
        if proxy.lowercased().hasPrefix("socks") {
            print("Claude Code doesn't support SOCKS proxies; use v2ray's HTTP port.")
            exit(1)
        }
        let v = blockingCheck(via: proxy)
        print("proxy \(proxy) exits in: \(CountryInfo.name(v.country)) (\(v.kind.rawValue))")
        if v.kind == .iran { print("This proxy exits in Iran - not configuring it."); exit(1) }
        guard editClaudeProxy(proxy) == 0 else { print("failed to edit \(ClaudeSettings.path)"); exit(1) }
        print("Claude Code will use \(proxy) (set in \(ClaudeSettings.path)). Restart Claude Code sessions.")
        print("Keep v2ray running while you use Claude Code; if it's off, Claude Code can't connect (nothing leaks).")
        exit(0)
    case "off":
        guard editClaudeProxy(nil) == 0 else { print("failed to edit \(ClaudeSettings.path)"); exit(1) }
        print("Claude Code proxy removed from \(ClaudeSettings.path). Restart Claude Code sessions.")
        exit(0)
    case "status":
        let sp = SystemProxy.current()
        print("Claude Code proxy (settings.json): \(ClaudeSettings.proxy() ?? "-")")
        print("Claude Code proxy (this shell)   : \(ProxyURL.claudeCode(ProcessInfo.processInfo.environment) ?? "-")")
        print("System proxy (v2ray)             : http=\(sp.http ?? "-") socks=\(sp.socks ?? "-") pac=\(sp.pac ?? "-")")
        if sp.pac != nil {
            let sem = DispatchSemaphore(value: 0)
            var rt: DesktopRoute?
            Task { rt = await PAC.resolveDesktopRoute(sp); sem.signal() }
            _ = sem.wait(timeout: .now() + 10)
            print("PAC answer for claude.ai         : \(rt?.pacResult ?? "-") \(rt?.note ?? "")")
        }
        exit(0)
    default:
        print("usage: claudeguard claude-proxy on [http://host:port] | off | status")
        exit(1)
    }
}

let args = Array(CommandLine.arguments.dropFirst())
switch args.first {
case "daemon":
    guard isRoot() else { print("daemon must run as root"); exit(1) }
    Daemon().run()

case "check":
    runAsync {
        let checker = IPChecker()
        let net = NetInfo.current()
        print("Network: \(net.summary)")
        let procs = ProxyApps.processes()
        let home = ProxyApps.consoleUserHome()
        let sp0 = SystemProxy.current()
        let rt0 = sp0.enabled || sp0.pac != nil ? await PAC.resolveDesktopRoute(sp0) : nil
        let remote = RemoteAPIs.candidates(proxies: [ClaudeSettings.proxy(home: home), rt0?.proxy, rt0?.http],
                                           configured: RemoteAPIs.load())
        let apps = await ProxyApps.detect(ProxyApps.allCandidates(home: home, procs: procs) + remote,
                                          running: { procs.running.contains($0) })
        if apps.isEmpty { print("Apps: no running Clash / sing-box / Xray / V2Ray / Hiddify / NekoBox / FlClash / Karing / Mihomo Party / Nyanpasu / Shadowrocket / Stash / Surge / Quantumult X / Loon / Egern detected") }
        for a in apps { printApp(a) }
        let direct: Verdict
        if net.anthropicBypassesCheck, let iface = net.anthropicIface {
            direct = await checker.check(interface: iface)
            printVerdict("Path Anthropic traffic takes (via \(iface)):", direct)
        } else {
            direct = await checker.check(via: nil)
            printVerdict("Direct route (Claude Code without HTTPS_PROXY):", direct)
        }
        let sp = SystemProxy.current()
        if sp.enabled || sp.pac != nil {
            let rt = await PAC.resolveDesktopRoute(sp)
            if rt.mode == "pac" {
                print("PAC file: \(sp.pac ?? "-")\n  answer for claude.ai: \(rt.pacResult ?? "-") \(rt.note ?? "")")
            }
            if let p = rt.proxy {
                printVerdict("Claude Desktop route via \(p):", await checker.check(via: p))
            } else {
                print("Claude Desktop route: DIRECT (same as above)")
            }
            if let http = rt.http { print("HTTP proxy usable by Claude Code: \(http)") }
        } else {
            print("System proxy: off")
        }
        return direct.kind == .allowed ? 0 : 1
    }

case "check-via":
    guard let url = args.dropFirst().first else { print("usage: claudeguardd check-via <proxy-url>"); exit(1) }
    runAsync {
        let v = await IPChecker().check(via: ProxyURL.normalize(url))
        printVerdict("Via \(ProxyURL.normalize(url)):", v)
        return v.kind == .allowed ? 0 : 1
    }

case "check-iface":
    guard let name = args.dropFirst().first else { print("usage: claudeguardd check-iface <interface, e.g. en0>"); exit(1) }
    runAsync {
        let v = await IPChecker().check(interface: name)
        printVerdict("Exit via interface \(name):", v)
        return v.kind == .allowed ? 0 : 1
    }

case "check-apps":
    // Evaluate specific config files (or the auto-detected ones) without requiring the app to run.
    runAsync {
        let files = Array(args.dropFirst())
        let procs = ProxyApps.processes()
        let cands = files.isEmpty
            ? ProxyApps.allCandidates(home: ProxyApps.consoleUserHome(), procs: procs) + RemoteAPIs.candidates(
                proxies: [ClaudeSettings.proxy(home: ProxyApps.consoleUserHome()), SystemProxy.current().http],
                configured: RemoteAPIs.load())
            : files.map { f -> ConfigCandidate in
                if FileManager.default.fileExists(atPath: f + "/groups") { return ConfigCandidate(kind: "nekoray", path: f) }
                if f.lowercased().contains("egern") && (f.hasSuffix(".yaml") || f.hasSuffix(".yml")) {
                    return ConfigCandidate(kind: "egern", path: f, app: "Egern")
                }
                if f.hasSuffix(".conf") || f.hasSuffix(".txt") || f.hasSuffix(".lcf") {
                    let text = (try? String(contentsOfFile: f, encoding: .utf8))?.lowercased() ?? ""
                    if text.contains("[filter_local]") || text.contains("[policy]") { return ConfigCandidate(kind: "quantumultx", path: f, app: "Quantumult X") }
                    let app = text.contains("[remote rule]") ? "Loon"
                        : text.contains("http-api") || text.contains("#!managed-config") ? "Surge" : "Shadowrocket"
                    return ConfigCandidate(kind: "surge", path: f, app: app)
                }
                return ConfigCandidate(kind: f.hasSuffix(".yaml") || f.hasSuffix(".yml") ? "clash" : "json", path: f)
            }
        let apps = await ProxyApps.detect(cands, running: { !files.isEmpty || procs.running.contains($0) }, probeDefaults: files.isEmpty)
        if apps.isEmpty { print("no Clash / sing-box / Xray config or API found") }
        for a in apps { printApp(a) }
        return apps.contains { $0.sendsClaudeDirect } ? 1 : 0
    }

case "check-pac":
    guard let pac = args.dropFirst().first else { print("usage: claudeguardd check-pac <pac-url>"); exit(1) }
    runAsync {
        let rt = await PAC.resolveDesktopRoute(SystemProxy(pac: pac))
        print("PAC answer for claude.ai: \(rt.pacResult ?? "-") \(rt.note ?? "")")
        guard let p = rt.proxy else { print("Claude Desktop route: DIRECT"); return 1 }
        let v = await IPChecker().check(via: p)
        printVerdict("Claude Desktop route via \(p):", v)
        if let http = rt.http { print("HTTP proxy usable by Claude Code: \(http)") }
        return v.kind == .allowed ? 0 : 1
    }

case "status":
    guard let s = GuardStatus.load() else { print("no status (is the service installed?)"); exit(1) }
    print(s.jsonString())
    if s.isStale { print("WARNING: status is stale - the service doesn't seem to be running") }
    exit(s.enforcing ? 1 : 0)

case "refresh":
    GuardNotify.post(GuardNotify.refresh)
    print("refresh requested")

case "claude-proxy":
    claudeProxy(Array(args.dropFirst()))

case "remote-api":
    do {
        print(try RemoteAPIs.command(Array(args.dropFirst())), terminator: "")
        if args.count > 1 && args[1] != "list" { GuardNotify.post(GuardNotify.refresh) }
    } catch {
        print(error)
        exit(1)
    }

case "hook":
    hook()

case "cleanup":
    guard isRoot() else { print("cleanup must run as root"); exit(1) }
    Enforcer().unblock(force: true)
    try? FileManager.default.removeItem(atPath: GuardPaths.supportDir)
    print("ClaudeGuard blocks removed")

case "lookup":
    guard let ip = args.dropFirst().first else { print("usage: claudeguardd lookup <ip>"); exit(1) }
    runAsync {
        let c = await IPChecker().country(for: ip)
        print("\(ip): \(c ?? "unknown") \(CountryInfo.flag(c)) \(CountryInfo.name(c))\(c == "IR" ? "  -> WOULD BLOCK" : "")")
        return 0
    }

case "print-rules":
    print("# pf anchor \(Enforcer.anchor):")
    print(Enforcer.firewallRules(extraIPs: []))
    print(HostsFile.render("", block: true))

case "selftest":
    exit(selftest())

default:
    print(usage)
    exit(args.isEmpty ? 0 : 1)
}
