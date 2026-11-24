import Foundation
import ClaudeGuardCore

/// `claudeguardd selftest` - offline checks of the decision logic (no root, no network).
func selftest() -> Int32 {
    var failures = 0
    func expect(_ ok: Bool, _ name: String) {
        print("\(ok ? "PASS" : "FAIL")  \(name)")
        if !ok { failures += 1 }
    }

    // Proxy env parsing (Claude Code precedence + NO_PROXY).
    expect(ProxyURL.claudeCode(["HTTPS_PROXY": "127.0.0.1:10809"]) == "http://127.0.0.1:10809", "env HTTPS_PROXY")
    expect(ProxyURL.claudeCode(["https_proxy": "http://a:1", "HTTPS_PROXY": "http://b:2"]) == "http://a:1", "env precedence")
    expect(ProxyURL.claudeCode(["HTTPS_PROXY": "http://a:1", "NO_PROXY": "localhost,.anthropic.com"]) == nil, "NO_PROXY anthropic")
    expect(ProxyURL.claudeCode(["HTTPS_PROXY": "http://a:1", "NO_PROXY": "*"]) == nil, "NO_PROXY *")
    expect(ProxyURL.claudeCode(["HTTPS_PROXY": "http://a:1", "NO_PROXY": "example.com"]) == "http://a:1", "NO_PROXY other")
    expect(ProxyURL.sameEndpoint("http://localhost:10809", "127.0.0.1:10809"), "sameEndpoint localhost")
    expect(!ProxyURL.sameEndpoint("http://127.0.0.1:1", "http://127.0.0.1:2"), "sameEndpoint port")
    expect(ProxyURL.sessionDictionary(nil).isEmpty, "direct = empty proxy dict (bypasses system proxy)")

    // Hook decisions.
    let v2ray = ProxyRoute(system: SystemProxy(http: "http://127.0.0.1:10809"), mode: "manual",
                           checked: "http://127.0.0.1:10809", kind: "allowed", ok: true,
                           country: "DE", detail: "")
    func st(_ state: GuardStatus.State, _ enforcing: Bool, _ iran: Bool, _ proxy: ProxyRoute? = nil) -> GuardStatus {
        GuardStatus(state: state, enforcing: enforcing, inIran: iran, message: "m", ipv4: "2.144.1.1",
                    proxy: proxy, checkedAt: Date())
    }
    let cache = NSTemporaryDirectory() + "claudeguard-selftest-\(getpid()).json"
    defer { try? FileManager.default.removeItem(atPath: cache) }

    func run(_ s: GuardStatus?, _ env: [String: String], _ pv: Verdict.Kind, checks: inout Int) -> (Bool, String) {
        var n = 0
        let r = Hook.run(HookDeps(load: { s }, refresh: {}, checkVia: { _ in n += 1; return Verdict(kind: pv, detail: "x") },
                                  env: env, wait: 0.3, cachePath: cache, cli: "claudeguard"))
        checks = n
        return (r.allow, r.message)
    }
    let cases: [(String, GuardStatus?, [String: String], Verdict.Kind, Bool, String, Int)] = [
        ("service down", nil, [:], .allowed, false, "not running", 0),
        ("direct allowed", st(.allowed, false, false), [:], .allowed, true, "", 0),
        ("direct iran, no proxy", st(.blocked, true, true), [:], .allowed, false, "IRAN", 0),
        ("v2ray system proxy, Claude Code direct", st(.proxyOnly, true, true, v2ray), [:], .allowed, false, "claude-proxy on", 0),
        ("v2ray system proxy, Claude Code via same proxy", st(.proxyOnly, true, true, v2ray), ["HTTPS_PROXY": "http://localhost:10809"], .iran, true, "", 0),
        ("own proxy verified live", st(.blocked, true, true), ["HTTPS_PROXY": "http://10.0.0.5:3128"], .allowed, true, "", 1),
        ("own proxy exits in Iran", st(.allowed, false, false), ["HTTPS_PROXY": "http://10.0.0.6:3128"], .iran, false, "exits in IRAN", 1),
        ("socks env", st(.proxyOnly, true, true, v2ray), ["HTTPS_PROXY": "socks5://127.0.0.1:10808"], .allowed, false, "SOCKS", 0),
        ("NO_PROXY anthropic -> direct", st(.blocked, true, true), ["HTTPS_PROXY": "http://a:1", "NO_PROXY": ".anthropic.com"], .allowed, false, "IRAN", 0),
    ]
    for (name, s, env, pv, allow, has, wantChecks) in cases {
        var checks = 0
        let (a, msg) = run(s, env, pv, checks: &checks)
        expect(a == allow && (has.isEmpty || msg.contains(has)) && checks == wantChecks, "hook: \(name)")
    }
    var checks = 0
    _ = run(st(.blocked, true, true), ["HTTPS_PROXY": "http://10.0.0.5:3128"], .allowed, checks: &checks)
    expect(checks == 0, "hook: proxy check cached")

    // TUN detection.
    expect(NetInfo.isTunnel("utun6") && NetInfo.isTunnel("ipsec0") && !NetInfo.isTunnel("en0"), "TUN: interface names")
    var tun = NetInfo(); tun.checkIface = "utun6"; tun.checkIsTunnel = true; tun.anthropicIface = "utun6"
    tun.anthropicIsTunnel = true; tun.tunnelName = "utun6"
    expect(tun.tunnelActive && !tun.anthropicBypassesCheck && tun.summary.contains("TUN VPN on"), "TUN: active")
    var byp = NetInfo(); byp.checkIface = "utun6"; byp.checkIsTunnel = true; byp.anthropicIface = "en0"
    byp.anthropicIsTunnel = false; byp.tunnelName = "utun6"
    expect(byp.anthropicBypassesCheck && byp.summary.contains("BYPASSES"), "TUN: Anthropic bypasses tunnel")
    var bypSt = st(.blocked, true, true); byp.bound = true; bypSt.network = byp
    var n0 = 0
    expect(run(bypSt, [:], .allowed, checks: &n0).1.contains("BYPASSES"), "hook: TUN bypassed message")
    var tunSt = st(.blocked, true, true); tunSt.network = tun
    expect(run(tunSt, [:], .allowed, checks: &n0).1.contains("is it connected"), "hook: TUN up but Iran message")

    // Clash / sing-box rule evaluation (same cases as the Windows tests).
    func clash(_ yaml: String) -> (HostRoute, HostRoute) {
        let f = ClashFile.parse(yaml)
        return RuleEngine.evalClash(f.rules.compactMap(RuleEngine.parseClashLine), mode: f.mode, resolve: f.resolver())
    }
    let bypassAll = clash("mode: rule\nproxy-groups:\n  - name: Proxy\n    type: select\n    proxies: [de-1]\nrules:\n  - DOMAIN-SUFFIX,google.com,Proxy\n  - GEOIP,IR,DIRECT\n  - MATCH,DIRECT\n")
    expect(bypassAll.0.outcome == .direct && bypassAll.0.rule == "MATCH,DIRECT", "Clash: MATCH,DIRECT sends Claude DIRECT")
    let claudeOnly = clash("rules:\n  - DOMAIN-SUFFIX,anthropic.com,Proxy\n  - DOMAIN-SUFFIX,claude.ai,Proxy\n  - MATCH,DIRECT\nproxy-groups:\n  - {name: Proxy, type: select, proxies: [de-1]}\n")
    expect(claudeOnly.0.outcome == .proxy && claudeOnly.1.outcome == .direct, "Clash: Claude proxied, checks DIRECT (misrouted)")
    let bypassIran = clash("rules:\n  - GEOSITE,category-ir,DIRECT\n  - GEOIP,IR,DIRECT,no-resolve\n  - MATCH,Proxy\nproxy-groups:\n  - {name: Proxy, type: url-test, proxies: [de-1, nl-2]}\n")
    expect(bypassIran.0.outcome == .proxy && bypassIran.1.outcome == .proxy, "Clash: bypass-Iran config proxies Claude + checks")
    let maybeDirect = clash("rules:\n  - MATCH,Proxy\nproxy-groups:\n  - name: Proxy\n    type: select\n    proxies:\n      - de-1\n      - DIRECT\n")
    expect(maybeDirect.0.outcome == .unknown, "Clash: block-style group with DIRECT is uncertain")
    expect(clash("mode: direct\nrules:\n  - MATCH,Proxy\n").0.outcome == .direct, "Clash: mode direct")
    let sbOut: [[String: Any]] = [["type": "selector", "tag": "proxy", "outbounds": ["vless-de"]], ["type": "vless", "tag": "vless-de"],
                                  ["type": "direct", "tag": "direct"]]
    let sbRules = [["action": "sniff"], ["rule_set": ["geosite-ir"], "outbound": "direct"],
                   ["domain_suffix": ["anthropic.com", "claude.ai"], "outbound": "direct"]].map(SingBox.rule)
    let sb = RuleEngine.evalRules(sbRules, final: "proxy", mode: "", resolve: SingBox.resolver(sbOut, api: nil))
    expect(sb.0.outcome == .direct && sb.1.outcome == .proxy, "sing-box: domain_suffix -> direct")
    let app = ProxyApp(kind: "clash", source: "", live: true, tun: true, ports: [7890], anthropic: bypassAll.0, check: bypassAll.1)
    expect(ProxyApps.decide([app], anthropicInTunnel: true, desktopProxy: nil).tunDirect != nil, "decide: TUN app sends Claude DIRECT")
    expect(ProxyApps.decide([app], anthropicInTunnel: false, desktopProxy: nil).tunDirect == nil, "decide: other VPN's tunnel -> irrelevant")
    var appNoTun = app; appNoTun.tun = false
    expect(ProxyApps.decide([appNoTun], anthropicInTunnel: false, desktopProxy: "http://127.0.0.1:7890").proxyDirect != nil,
           "decide: system proxy -> app port")
    var clashSt = st(.blocked, true, true); clashSt.apps = [app]
    expect(run(clashSt, ["HTTPS_PROXY": "http://127.0.0.1:7890"], .allowed, checks: &n0).1.contains("MATCH,DIRECT"),
           "hook: HTTPS_PROXY is Clash sending Claude DIRECT")

    // Xray / V2Ray configs (same cases as windows/internal/core/xray_test.go).
    func xray(_ json: String) -> ProxyApp {
        let d = Data(json.utf8)
        expect(Xray.jsonKind(d) == "xray", "xray: detected as xray")
        let cfg = (try? JSONSerialization.jsonObject(with: Xray.stripComments(d))) as? [String: Any] ?? [:]
        return Xray.evaluate(path: "test", cfg)
    }
    let xBypassIran = xray("""
    {
      // comments are allowed
      "inbounds": [{"tag": "socks", "port": 10808, "protocol": "socks"}, {"tag": "http", "port": "10809", "protocol": "http"},
                   {"tag": "api", "port": 10813, "protocol": "dokodemo-door"}],
      "outbounds": [{"tag": "proxy", "protocol": "vless"}, {"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
      "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
        {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
        {"type": "field", "outboundTag": "block", "domain": ["geosite:category-ads-all"]},
        {"type": "field", "outboundTag": "direct", "domain": ["domain:ir", "geosite:category-ir"]},
        {"type": "field", "outboundTag": "direct", "ip": ["geoip:private", "geoip:ir"]},
        {"type": "field", "port": "0-65535", "outboundTag": "proxy"}]}
    }
    """)
    expect(xBypassIran.anthropic.outcome == .proxy && xBypassIran.check.outcome == .proxy && xBypassIran.ports == [10808, 10809],
           "xray: bypass-Iran proxies Claude + checks")
    let xDirectFirst = xray("""
    {"inbounds": [{"tag": "socks", "port": 10808, "protocol": "socks"}],
     "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"fragment": {"packets": "tlshello"}}}, {"tag": "proxy", "protocol": "trojan"}],
     "routing": {"rules": [{"type": "field", "domain": ["geosite:google", "youtube.com"], "outboundTag": "proxy"}]}}
    """)
    expect(xDirectFirst.sendsClaudeDirect, "xray: first outbound freedom (fragment) -> Claude DIRECT")
    let xClaudeOnly = xray("""
    {"inbounds": [{"tag": "socks", "port": 10808, "protocol": "socks"}],
     "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "proxy", "protocol": "vmess"}],
     "routing": {"rules": [{"type": "field", "domain": ["domain:anthropic.com", "full:claude.ai"], "outboundTag": "proxy"}]}}
    """)
    expect(xClaudeOnly.checkMisrouted, "xray: Claude proxied, checks DIRECT (misrouted)")
    let xBalancer = xray("""
    {"inbounds": [{"tag": "socks", "port": 10808, "protocol": "socks"}],
     "outbounds": [{"tag": "proxy-a", "protocol": "vless"}, {"tag": "proxy-direct", "protocol": "freedom"}],
     "routing": {"balancers": [{"tag": "b", "selector": ["proxy-"]}], "rules": [{"type": "field", "network": "tcp,udp", "balancerTag": "b"}]}}
    """)
    expect(xBalancer.anthropic.outcome == .unknown, "xray: balancer that may pick freedom is uncertain")
    for (strategy, want) in [("AsIs", Outcome.proxy), ("IPIfNonMatch", .direct), ("IPOnDemand", .direct)] {
        let a = xray(#"{"outbounds":[{"tag":"proxy","protocol":"vless"},{"tag":"direct","protocol":"freedom"}],"routing":{"domainStrategy":"\#(strategy)","rules":[{"ip":["160.79.104.0/23"],"outboundTag":"direct"}]}}"#)
        expect(a.anthropic.outcome == want, "xray: IP rule with domainStrategy \(strategy)")
    }
    let sbTun: [[String: Any]] = [["type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 10808], ["type": "direct", "tag": "direct"]]
    let tunRoute = RuleEngine.evalRules([], final: "proxy", mode: "", resolve: SingBox.resolver(sbTun, api: nil))
    var linked = [ProxyApp(kind: "sing-box", source: "", live: false, tun: true, ports: [], anthropic: tunRoute.0, check: tunRoute.1),
                  xDirectFirst]
    Xray.linkLocalForwards(&linked)
    expect(linked[0].sendsClaudeDirect && ProxyApps.decide(linked, anthropicInTunnel: true, desktopProxy: nil).tunDirect != nil,
           "link: v2rayN TUN -> xray SOCKS -> DIRECT")
    let args = Xray.configArgs(kind: "xray", args: ["xray", "run", "-c", "config.json", "-confdir=/etc/x"], bases: ["/a", "/b"])
    expect(args.map(\.path) == ["/a/config.json", "/b/config.json", "/etc/x"], "xray: command-line config paths")
    expect(Xray.configArgs(kind: "xray", args: ["xray", "run", "-c", "stdin:"], bases: []).isEmpty, "xray: stdin config skipped")
    expect(Xray.procKind("/Applications/v2rayN.app/Contents/MacOS/bin/xray/xray") == "xray" && Xray.procKind("v2ray") == "xray"
           && Xray.procKind("mihomo-darwin-arm64") == "clash" && Xray.procKind("v2rayN") == nil, "process kinds")

    // V2Ray v5 format (same cases as TestV2RayV5).
    let v5Bypass = xray("""
    {"router": {"domainStrategy": "IpIfNonMatch", "rule": [
        {"tag": "direct", "geoDomain": [{"code": "category-ir"}], "domain": [{"type": "RootDomain", "value": "ir"}]},
        {"tag": "direct", "geoip": [{"code": "private"}, {"code": "ir"}]},
        {"tag": "proxy", "portList": "0-65535"}]},
     "inbounds": [{"protocol": "socks", "port": 10808, "tag": "socks"}],
     "outbounds": [{"protocol": "vmess", "tag": "proxy"}, {"protocol": "freedom", "tag": "direct"}]}
    """)
    expect(v5Bypass.anthropic.outcome == .proxy && v5Bypass.check.outcome == .proxy, "v5: bypass-Iran proxies Claude + checks")
    let v5Default = xray("""
    {"router": {"domain_strategy": "AsIs", "rule": [
        {"tag": "proxy", "domain": [{"type": "Full", "value": "www.google.com"}, {"type": "Regex", "value": "^.*youtube\\\\.com$"}]}]},
     "inbounds": [{"protocol": "http", "port": "10809", "tag": "http"}],
     "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "trojan", "tag": "proxy"}]}
    """)
    expect(v5Default.sendsClaudeDirect && v5Default.ports == [10809], "v5: first outbound freedom -> Claude DIRECT")
    let v5Cidr = xray("""
    {"router": {"domainStrategy": 3, "rule": [
        {"tag": "direct", "geoip": [{"cidr": [{"ipAddr": "160.79.104.0", "prefix": 23}]}]},
        {"tag": "direct", "geoip": [{"code": "ir", "inverseMatch": true}], "networks": "udp"}]},
     "inbounds": [{"protocol": "socks", "port": 1080}],
     "outbounds": [{"protocol": "shadowsocks", "tag": "proxy"}, {"protocol": "freedom", "tag": "direct"}]}
    """)
    expect(v5Cidr.sendsClaudeDirect && v5Cidr.check.outcome == .unknown, "v5: Anthropic CIDR -> DIRECT (IpOnDemand)")
    let v5Bal = xray("""
    {"router": {"rule": [{"balancingTag": "b", "networks": "tcp,udp"}], "balancingRule": [{"tag": "b", "outboundSelector": ["node-"]}]},
     "inbounds": [{"protocol": "socks", "port": 1080}],
     "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "vless", "tag": "node-a"}, {"protocol": "vless", "tag": "node-b"}]}
    """)
    expect(v5Bal.anthropic.outcome == .proxy, "v5: balancer of proxy nodes")
    let v5r = Xray.v5Rule(["tag": "x", "geo_domain": [["country_code": "CN"]],
                           "geoip": [["cidr": [["ip": "oE9oAA==", "prefix": 23]]]]])
    expect(v5r["domain"] as? [String] == ["geosite:cn"] && v5r["ip"] as? [String] == ["160.79.104.0/23"], "v5: snake_case + base64 CIDR")

    // PAC evaluation (CFNetwork) - shaped like v2rayN / V2rayU PAC files.
    let v2rayPAC = """
    var proxy = "PROXY 127.0.0.1:10809; SOCKS5 127.0.0.1:10808; DIRECT;";
    var domains = { "google.com": 1, "anthropic.com": 1, "claude.ai": 1 };
    function FindProxyForURL(url, host) {
      if (shExpMatch(host, "*.ir") || isPlainHostName(host)) return "DIRECT";
      var pos = host.lastIndexOf('.'); pos = host.lastIndexOf('.', pos - 1);
      while (1) {
        if (pos <= 0) return Object.hasOwnProperty.call(domains, host) ? proxy : "DIRECT";
        if (Object.hasOwnProperty.call(domains, host.substring(pos + 1))) return proxy;
        pos = host.lastIndexOf('.', pos - 1);
      }
    }
    """
    expect(PAC.evaluate(v2rayPAC, url: "https://claude.ai/")?.first == "http://127.0.0.1:10809", "PAC: claude.ai -> PROXY")
    expect(PAC.evaluate(v2rayPAC, url: "https://api.anthropic.com/")?.first == "http://127.0.0.1:10809", "PAC: api.anthropic.com -> PROXY")
    expect(PAC.evaluate(v2rayPAC, url: "https://x.ir/")?.first == .some(nil), "PAC: *.ir -> DIRECT")

    let dir = NSTemporaryDirectory() + "claudeguard-pac-\(getpid())"
    try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: dir) }
    func route(_ script: String?) -> DesktopRoute {
        var url = "http://127.0.0.1:1/unreachable.pac"
        if let script {
            url = "file://\(dir)/\(UUID().uuidString).pac"
            try? script.write(to: URL(string: url)!, atomically: true, encoding: .utf8)
        }
        let sem = DispatchSemaphore(value: 0)
        var r: DesktopRoute!
        Task { r = await PAC.resolveDesktopRoute(SystemProxy(pac: url)); sem.signal() }
        sem.wait()
        return r
    }
    let r1 = route(v2rayPAC)
    expect(r1.mode == "pac" && r1.proxy == "http://127.0.0.1:10809" && r1.http == "http://127.0.0.1:10809", "PAC route: v2ray file")
    let r2 = route(#"function FindProxyForURL(u, h) { return h == "claude.ai" ? "PROXY 1.1.1.1:8080" : "DIRECT"; }"#)
    expect(r2.proxy == nil, "PAC route: mixed answers -> DIRECT")
    let r3 = route(nil)
    expect(r3.proxy == nil && r3.note?.contains("DIRECT") == true, "PAC route: unreachable PAC -> DIRECT")
    let r4 = route(#"function FindProxyForURL(u, h) { return "SOCKS5 127.0.0.1:10808"; }"#)
    expect(r4.proxy == "socks5://127.0.0.1:10808" && r4.http == nil, "PAC route: SOCKS only (no HTTP for Claude Code)")

    print(failures == 0 ? "\nall passed" : "\n\(failures) failed")
    return failures == 0 ? 0 : 1
}
