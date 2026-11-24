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

    // Hiddify / NekoBox / NekoRay (same cases as windows/internal/core/guiapps_test.go).
    let gdir = NSTemporaryDirectory() + "claudeguard-gui-\(getpid())"
    defer { try? FileManager.default.removeItem(atPath: gdir) }
    func put(_ rel: String, _ text: String) {
        let p = gdir + "/" + rel
        try? FileManager.default.createDirectory(atPath: (p as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try? text.write(toFile: p, atomically: true, encoding: .utf8)
    }
    func detectSync(_ cands: [ConfigCandidate]) -> [ProxyApp] {
        let sem = DispatchSemaphore(value: 0)
        var out: [ProxyApp] = []
        Task { out = await ProxyApps.detect(cands, running: { _ in true }, probeDefaults: false); sem.signal() }
        sem.wait()
        return out
    }
    let neko = [ConfigCandidate(kind: "nekoray", path: gdir + "/nekobox/config")]
    put("nekobox/config/groups/nekobox.json", #"{"inbound_socks_port": 2080, "active_routing": "Iran"}"#)
    put("nekobox/config/routes_box/Iran", #"{"block_domain": "geosite:category-ads-all", "direct_domain": "geosite:category-ir\ndomain:ir\n# c", "direct_ip": "geoip:ir\ngeoip:private", "def_outbound": "proxy", "domain_strategy": "AsIs", "custom": "{\"rules\": []}"}"#)
    var na = detectSync(neko)
    expect(na.count == 1 && na[0].name == "NekoBox" && na[0].anthropic.outcome == .proxy && na[0].check.outcome == .proxy
           && na[0].ports == [2080], "NekoBox: bypass-Iran profile proxies Claude")
    put("nekobox/config/routes_box/Iran", #"{"proxy_domain": "geosite:google\ndomain:youtube.com", "def_outbound": "bypass"}"#)
    na = detectSync(neko)
    expect(na.first?.sendsClaudeDirect == true && na.first?.anthropic.rule == "final: bypass", "NekoBox: default bypass -> Claude DIRECT")
    put("nekobox/config/routes_box/Iran", #"{"def_outbound": "proxy", "custom": "{\"rules\": [{\"domain_suffix\": [\"anthropic.com\", \"claude.ai\"], \"outbound\": \"bypass\"}]}"}"#)
    na = detectSync(neko)
    expect(na.first?.sendsClaudeDirect == true && na.first?.check.outcome == .proxy, "NekoBox: custom rule sends Claude DIRECT")
    put("nekoray/config/groups/nekoray.json", #"{"inbound_socks_port": 2081}"#)
    put("nekoray/config/routes/Default", #"{"direct_ip": "160.79.104.0/23", "def_outbound": "proxy", "domain_strategy": "UseIP"}"#)
    let nr = detectSync([ConfigCandidate(kind: "nekoray", path: gdir + "/nekoray/config")])
    expect(nr.first?.name == "NekoRay" && nr.first?.sendsClaudeDirect == true, "NekoRay: IP rule with UseIP -> DIRECT")
    put("nekobox/config/routes_box/Iran", #"{"def_outbound": "bypass"}"#)
    put("nekobox/config/vpn/sing-box-vpn.json", #"{"inbounds":[{"type":"tun","tag":"tun-in"}],"outbounds":[{"type":"socks","tag":"nekoray-socks","server":"127.0.0.1","server_port":2080},{"type":"direct","tag":"direct"}],"route":{"final":"nekoray-socks"}}"#)
    let vpnArgs = ["nekobox_core", "run", "-c", gdir + "/nekobox/config/vpn/sing-box-vpn.json"]
    let tunApps = detectSync(Xray.configArgs(kind: Xray.procKind(vpnArgs[0]) ?? "", args: vpnArgs, bases: []) + neko)
    expect(tunApps.count == 2 && tunApps[0].tun == true && tunApps[0].sendsClaudeDirect
           && ProxyApps.decide(tunApps, anthropicInTunnel: true, desktopProxy: nil).tunDirect != nil, "NekoBox TUN -> SOCKS 2080 -> bypass")
    put("Support/Hiddify/hiddify/data/current-config.json", #"{"outbounds":[{"type":"selector","tag":"select","outbounds":["vless-1"]},{"type":"vless","tag":"vless-1"},{"type":"direct","tag":"direct"}],"route":{"rules":[{"rule_set":["geosite-ir"],"outbound":"direct"}],"final":"select"}}"#)
    put("Support/Other/current-config.json", "{}")
    put("Prefs/app.hiddify.com.plist", #"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>flutter.mixed-port</key><integer>12334</integer><key>flutter.service-mode</key><string>tun</string><key>flutter.clash-api-port</key><integer>16757</integer></dict></plist>"#)
    let hid = GUIApps.findHiddify(roots: [gdir + "/Support"], plists: [gdir + "/Prefs/app.hiddify.com.plist"])
    expect(hid.configs.count == 2 && hid.configs.contains { $0.kind == "api" && $0.path == "127.0.0.1:16757" } && hid.tun,
           "Hiddify: config + plist preferences found")
    let ha = detectSync(hid.configs.filter { $0.kind != "api" })
    expect(ha.first?.name == "Hiddify" && ha.first?.tun == true && ha.first?.ports == [12334] && ha.first?.anthropic.outcome == .proxy,
           "Hiddify: current-config.json evaluated with port/TUN from preferences")
    expect(Xray.procKind("/Applications/NekoBox.app/Contents/MacOS/nekobox") == "nekoray" && Xray.procKind("nekobox_core") == "sing-box"
           && Xray.procKind("nekoray_core") == "xray" && Xray.procKind("Hiddify") == "sing-box", "GUI process kinds")

    // FlClash / Karing (same cases as TestFlClash / TestKaring).
    put("fl/com.follow.clash/profiles/1712.yaml", "mixed-port: 7890\nmode: global\nexternal-controller: 127.0.0.1:1\nproxy-groups:\n  - {name: Proxy, type: select, proxies: [de-1]}\nrules:\n  - GEOSITE,category-ir,DIRECT\n  - MATCH,Proxy\n")
    put("fl/com.follow.clash/profiles/999.yaml", "rules:\n  - MATCH,DIRECT\n")
    put("fl/com.follow.clash/config.json", #"{"currentProfileId": "1712", "profiles": [{"id": "1712"}], "patchClashConfig": {"mixed-port": 7897, "mode": "rule", "tun": {"enable": true}, "external-controller": ""}}"#)
    let flCands = GUIApps.flClashCandidates([gdir + "/fl"])
    var fl = detectSync(flCands)
    expect(fl.count == 1 && fl[0].name == "FlClash" && fl[0].mode == "rule" && fl[0].tun == true && fl[0].ports == [7897]
           && fl[0].anthropic.outcome == .proxy && fl[0].note == nil, "FlClash: profile + FlClash settings")
    put("fl/com.follow.clash/config.json", #"{"currentProfileId": "1712", "profiles": [{"id": "1712", "overrideData": {"enable": true, "rule": {"type": "added", "addedRules": ["DOMAIN-SUFFIX,anthropic.com,DIRECT", "DOMAIN,claude.ai,DIRECT"]}}}], "patchClashConfig": {"mode": "rule", "external-controller": ""}}"#)
    fl = detectSync(flCands)
    expect(fl.first?.sendsClaudeDirect == true, "FlClash: profile override adds Claude DIRECT rules")
    try? FileManager.default.removeItem(atPath: gdir + "/fl/com.follow.clash/config.json")
    put("fl/com.follow.clash/shared_preferences.json", #"{"flutter.config": "{\"currentProfileId\":\"1712\"}", "flutter.clashConfig": "{\"mode\":\"direct\",\"external-controller\":\"\"}"}"#)
    fl = detectSync(flCands)
    expect(fl.first?.sendsClaudeDirect == true && fl.first?.anthropic.rule == "mode: direct", "FlClash: old prefs format, mode direct")
    put("karing/karing/profiles/sub1.json", #"{"outbounds":[{"type":"vless","tag":"a"}]}"#)
    put("karing/karing/service_core_config.json", #"{"inbounds":[{"type":"mixed","tag":"in","listen_port":3067},{"type":"tun","tag":"tun-in"}],"outbounds":[{"type":"selector","tag":"select","outbounds":["a"]},{"type":"vless","tag":"a"},{"type":"direct","tag":"direct"}],"route":{"rules":[{"rule_set":["geosite-ir"],"outbound":"direct"},{"domain_suffix":["anthropic.com","claude.ai"],"outbound":"direct"}],"final":"select"}}"#)
    let kc = GUIApps.karingCandidates([gdir + "/karing"])
    let ka = detectSync(kc)
    expect(kc.count == 1 && kc[0].path.hasSuffix("service_core_config.json") && ka.first?.name == "Karing" && ka.first?.tun == true
           && ka.first?.ports == [3067] && ka.first?.sendsClaudeDirect == true && ka.first?.check.outcome == .proxy,
           "Karing: newest runnable sing-box config, Claude DIRECT")
    expect(Xray.procKind("FlClash") == "clash" && Xray.procKind("FlClashCore") == "clash" && Xray.procKind("Karing") == "sing-box",
           "FlClash / Karing process kinds")

    // Shadowrocket / Stash (Mac only).
    let srIran = """
    [General]
    bypass-system = true
    dns-server = system
    [Rule]
    DOMAIN-SUFFIX,ir,DIRECT
    RULE-SET,https://raw.githubusercontent.com/x/iran-rules/main/Iran.list,DIRECT
    RULE-SET,SYSTEM,DIRECT
    DOMAIN-SET,https://example.com/ads.txt,REJECT
    GEOIP,IR,DIRECT
    FINAL,PROXY,dns-failed
    [Host]
    localhost = 127.0.0.1
    """
    put("Containers/com.liguangming.Shadowrocket/Data/Documents/old.conf", "[Rule]\nFINAL,DIRECT\n")
    Thread.sleep(forTimeInterval: 0.05)
    put("Containers/com.liguangming.Shadowrocket/Data/Documents/iran.conf", srIran)
    let srC = AppleApps.shadowrocketCandidates([gdir + "/Containers"])
    var sr = detectSync(srC)
    expect(srC.count == 1 && srC[0].path.hasSuffix("iran.conf") && sr.first?.name == "Shadowrocket" && sr.first?.tun == true
           && sr.first?.anthropic.outcome == .proxy && sr.first?.check.outcome == .proxy && sr.first?.note?.contains("newest of 2") == true,
           "Shadowrocket: newest .conf, bypass-Iran proxies Claude")
    put("Containers/com.liguangming.Shadowrocket/Data/Documents/iran.conf", srIran.replacingOccurrences(of: "FINAL,PROXY,dns-failed",
        with: "DOMAIN-SUFFIX,google.com,Proxy\nFINAL,DIRECT\n[Proxy Group]\nProxy = select,de-1,nl-2,interval=600\n[Proxy]\nde-1 = vless,1.2.3.4,443"))
    sr = detectSync(AppleApps.shadowrocketCandidates([gdir + "/Containers"]))
    expect(sr.first?.sendsClaudeDirect == true && sr.first?.anthropic.rule == "MATCH,DIRECT", "Shadowrocket: FINAL,DIRECT -> Claude DIRECT")
    let srGroup = AppleApps.parseSurge("[Rule]\nFINAL,Auto\n[Proxy Group]\nAuto = select,PROXY,DIRECT\n")
    expect(RuleEngine.evalRules(srGroup.rules.compactMap(RuleEngine.parseClashLine), final: "PROXY", mode: "",
                                resolve: AppleApps.surgeResolver(srGroup)).0.outcome == .unknown, "Shadowrocket: group with DIRECT is uncertain")
    put("Group Containers/group.ws.stash.app/Documents/profiles/main.yaml", "mode: rule\nproxy-groups:\n  - {name: Proxy, type: select, proxies: [de-1]}\nrules:\n  - GEOIP,IR,DIRECT\n  - MATCH,DIRECT\n")
    let stC = AppleApps.stashCandidates([gdir + "/Group Containers"])
    let st = detectSync(stC)
    expect(st.first?.name == "Stash" && st.first?.tun == true && st.first?.sendsClaudeDirect == true
           && ProxyApps.decide(st, anthropicInTunnel: true, desktopProxy: nil).tunDirect != nil, "Stash: MATCH,DIRECT profile -> Claude DIRECT")
    expect(Xray.procKind("/private/var/folders/x/Wrapper/Shadowrocket.app/Shadowrocket") == "shadowrocket"
           && Xray.procKind("/Applications/Stash.app/Contents/MacOS/Stash") == "clash" && Xray.procKind("stashd") == nil,
           "Shadowrocket / Stash process kinds")

    // Surge (Mac) / Quantumult X.
    let surgeConf = """
    #!MANAGED-CONFIG https://example.com/surge.conf
    [General]
    http-listen = 127.0.0.1:6152
    socks5-listen = 127.0.0.1:6153
    [Proxy]
    de-1 = vmess, 1.2.3.4, 443
    [Proxy Group]
    Proxy = select, de-1, nl-2
    Home = subnet, default = Proxy, "SSID:MyWifi" = DIRECT
    [Rule]
    RULE-SET,SYSTEM,DIRECT
    RULE-SET,LAN,DIRECT
    GEOIP,IR,DIRECT
    DOMAIN-SUFFIX,openai.com,Home
    FINAL,Proxy,dns-failed
    """
    put("Group Containers/group.com.nssurge.surge-mac/Profiles/main.conf", surgeConf)
    let sgC = AppleApps.surgeCandidates([gdir + "/Group Containers"])
    var sg = detectSync(sgC)
    expect(sgC.count == 1 && sg.first?.name == "Surge" && sg.first?.ports == [6152, 6153] && sg.first?.anthropic.outcome == .proxy
           && sg.first?.anthropic.chain == ["Proxy", "de-1?"], "Surge: profile proxies Claude via group Proxy")
    put("Group Containers/group.com.nssurge.surge-mac/Profiles/main.conf",
        surgeConf.replacingOccurrences(of: "GEOIP,IR,DIRECT", with: "DOMAIN-SUFFIX,anthropic.com,Home\nDOMAIN,claude.ai,Home"))
    sg = detectSync(sgC)
    expect(sg.first?.anthropic.outcome == .unknown, "Surge: subnet group that can pick DIRECT is uncertain")
    let qx = """
    [general]
    network_check_url=http://www.google.com/generate_204
    [policy]
    static=Proxy, de-1, nl-2, img-url=https://x/y.png
    static=Maybe, Proxy, direct
    [filter_remote]
    https://raw.githubusercontent.com/x/Iran.list, tag=Iran, force-policy=direct, update-interval=86400, enabled=true
    https://example.com/ads.list, tag=Ads, force-policy=reject, enabled=false
    [filter_local]
    host-suffix, ir, direct
    geoip, ir, direct
    final, Proxy
    """
    put("Containers/com.crossutility.quantumult-x/Data/Documents/Profiles/QuantumultX.conf", qx)
    let qC = AppleApps.quantumultXCandidates([gdir + "/Containers"])
    var q = detectSync(qC)
    expect(qC.count == 1 && q.first?.name == "Quantumult X" && q.first?.tun == true && q.first?.anthropic.outcome == .proxy
           && q.first?.check.outcome == .proxy, "Quantumult X: Iran filters direct, final Proxy")
    put("Containers/com.crossutility.quantumult-x/Data/Documents/Profiles/QuantumultX.conf",
        qx.replacingOccurrences(of: "host-suffix, ir, direct", with: "host-suffix, anthropic.com, direct\nhost, claude.ai, direct"))
    q = detectSync(qC)
    expect(q.first?.sendsClaudeDirect == true && q.first?.check.outcome == .proxy, "Quantumult X: host-suffix anthropic.com -> direct")
    put("Containers/com.crossutility.quantumult-x/Data/Documents/Profiles/QuantumultX.conf", qx.replacingOccurrences(of: "final, Proxy", with: "final, Maybe"))
    q = detectSync(qC)
    expect(q.first?.anthropic.outcome == .unknown, "Quantumult X: policy with direct is uncertain")
    put("Containers/com.crossutility.quantumult-x/Data/Documents/Profiles/QuantumultX.conf",
        qx.replacingOccurrences(of: "force-policy=direct, update", with: "update"))
    q = detectSync(qC)
    expect(q.first?.anthropic.outcome == .proxy && q.first?.check.outcome == .proxy, "Quantumult X: remote list named Iran doesn't hold Claude")
    expect(Xray.procKind("/Applications/Surge.app/Contents/MacOS/Surge") == "surge" && Xray.procKind("Quantumult X") == "quantumultx",
           "Surge / Quantumult X process kinds")

    // MiniYAML (used for Egern).
    let y = MiniYAML.parse("""
    # comment
    general:
      tun: true   # trailing comment
      name: "a # not a comment"
    list:
    - one
    - {k: v, url: "http://x:1/y", n: 3}
    - key: value
      other: [a, 'b c', 2]
    nested:
      - select:
          name: Proxy
          policies:
            - de-1
            - DIRECT
    text: |
      line1
      line2
    """) as? [String: Any]
    let yl = y?["list"] as? [Any]
    let yflow = yl?[1] as? [String: Any]
    let ymap = yl?[2] as? [String: Any]
    let ysel = ((y?["nested"] as? [[String: Any]])?.first?["select"] as? [String: Any])
    expect((y?["general"] as? [String: Any])?["tun"] as? Bool == true
           && (y?["general"] as? [String: Any])?["name"] as? String == "a # not a comment"
           && yl?.first as? String == "one" && yflow?["url"] as? String == "http://x:1/y" && yflow?["n"] as? Int == 3
           && ymap?["key"] as? String == "value" && (ymap?["other"] as? [Any])?[1] as? String == "b c"
           && ysel?["name"] as? String == "Proxy" && ysel?["policies"] as? [String] == ["de-1", "DIRECT"]
           && y?["text"] as? String == "line1\nline2", "MiniYAML: maps, lists, flow, comments, block text")

    // Loon / Egern.
    let loon = """
    [General]
    ipv6 = false
    [Proxy Group]
    Proxy = select,de-1,nl-2,img-url=https://x/y.png
    Net = ssid,default=Proxy,cellular=DIRECT,"Home"=DIRECT
    [Rule]
    GEOIP,IR,DIRECT
    FINAL,Proxy
    [Remote Rule]
    https://raw.githubusercontent.com/x/Iran.list, policy=DIRECT, tag=Iran, enabled=true
    https://example.com/ai.list, policy=Net, tag=AI, enabled=false
    """
    put("Containers/com.ruikq.decar/Data/Documents/Config/main.conf", loon)
    let lC = AppleApps.loonCandidates([gdir + "/Containers"])
    var lo = detectSync(lC)
    expect(lC.count == 1 && lo.first?.name == "Loon" && lo.first?.tun == true && lo.first?.anthropic.outcome == .proxy
           && lo.first?.anthropic.rule == "final: Proxy", "Loon: local + remote Iran rules, FINAL Proxy")
    put("Containers/com.ruikq.decar/Data/Documents/Config/main.conf", loon.replacingOccurrences(of: "tag=AI, enabled=false", with: "tag=Anthropic, enabled=true"))
    lo = detectSync(lC)
    expect(lo.first?.anthropic.outcome == .unknown, "Loon: remote Anthropic list -> ssid group that can pick DIRECT is uncertain")
    put("Containers/com.ruikq.decar/Data/Documents/Config/main.conf", loon.replacingOccurrences(of: "FINAL,Proxy", with: "DOMAIN-SUFFIX,anthropic.com,DIRECT\nFINAL,Proxy"))
    lo = detectSync(lC)
    expect(lo.first?.sendsClaudeDirect == true, "Loon: local rule sends Claude DIRECT")
    let egern = """
    proxies:
      - vless:
          name: de-1
          server: 1.2.3.4
          port: 443
    policy_groups:
      - select:
          name: Proxy
          policies: [de-1, nl-2]
      - select:
          name: AI
          policies:
            - Proxy
            - DIRECT
    rules:
      - rule_set:
          match: https://raw.githubusercontent.com/x/iran.yaml
          policy: DIRECT
      - geoip:
          match: IR
          policy: DIRECT
          no_resolve: true
      - domain_suffix: {match: openai.com, policy: AI}
      - default:
          policy: Proxy
    """
    put("Group Containers/group.egernapp.egern/Profiles/default.yaml", egern)
    let eC = AppleApps.egernCandidates([gdir + "/Group Containers"])
    var eg = detectSync(eC)
    expect(eC.count == 1 && eg.first?.name == "Egern" && eg.first?.anthropic.outcome == .proxy && eg.first?.check.outcome == .proxy
           && eg.first?.anthropic.chain == ["Proxy", "de-1?"], "Egern: Iran rules DIRECT, default Proxy")
    put("Group Containers/group.egernapp.egern/Profiles/default.yaml", egern.replacingOccurrences(of: "match: openai.com, policy: AI", with: "match: anthropic.com, policy: DIRECT"))
    eg = detectSync(eC)
    expect(eg.first?.sendsClaudeDirect == true && eg.first?.check.outcome == .proxy, "Egern: domain_suffix anthropic.com -> DIRECT")
    put("Group Containers/group.egernapp.egern/Profiles/default.yaml", egern.replacingOccurrences(of: "match: openai.com", with: "match: claude.ai"))
    eg = detectSync(eC)
    expect(eg.first?.anthropic.outcome == .unknown, "Egern: group that can pick DIRECT is uncertain")
    expect(Xray.procKind("Loon") == "loon" && Xray.procKind("/Applications/Egern.app/Contents/MacOS/Egern") == "egern", "Loon / Egern process kinds")

    // Mihomo Party / Clash Nyanpasu.
    put("mp/mihomo-party/work/config.yaml", "mixed-port: 7890\nexternal-controller-unix: /nonexistent/mp.sock\nproxy-groups:\n  - {name: Proxy, type: select, proxies: [de-1]}\nrules:\n  - GEOIP,IR,DIRECT\n  - MATCH,Proxy\n")
    put("mp/mihomo-party/profiles/abc.yaml", "rules:\n  - MATCH,DIRECT\n")
    put("mp/Clash Nyanpasu/config/clash-config.yaml", "mixed-port: 7899\nproxy-groups:\n  - {name: Proxy, type: select, proxies: [de-1]}\nrules:\n  - DOMAIN-SUFFIX,anthropic.com,DIRECT\n  - MATCH,Proxy\n")
    let mpC = GUIApps.mihomoGUICandidates([gdir + "/mp"])
    let mp = detectSync(mpC)
    let party = mp.first { $0.name == "Mihomo Party" }, nyan = mp.first { $0.name == "Clash Nyanpasu" }
    expect(mpC.count == 2 && party?.anthropic.outcome == .proxy && party?.ports == [7890] && party?.note?.contains("unix:") == true,
           "Mihomo Party: work/config.yaml (not the stale profile), unix API noted")
    expect(nyan?.sendsClaudeDirect == true, "Clash Nyanpasu: clash-config.yaml sends Claude DIRECT")
    expect(GUIApps.appLabel("/Users/x/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml") == "Clash Verge",
           "app label from path")

    // ClashX Meta / Clash Verge Rev.
    put("home/.config/clash.meta/config.yaml", "rules:\n  - MATCH,DIRECT\n")
    put("home/.config/clash.meta/work-sub.yaml", "mixed-port: 7890\nproxy-groups:\n  - {name: Proxy, type: select, proxies: [de-1]}\nrules:\n  - GEOIP,IR,DIRECT\n  - MATCH,Proxy\n")
    put("home/Library/Preferences/com.metacubex.ClashX.meta.plist", #"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>selectConfigName</key><string>work-sub</string></dict></plist>"#)
    let cx = detectSync(ProxyApps.allCandidates(home: gdir + "/home", procs: ProxyApps.ProcInfo()))
    expect(cx.count == 1 && cx[0].name == "ClashX Meta" && cx[0].source.hasSuffix("work-sub.yaml") && cx[0].anthropic.outcome == .proxy,
           "ClashX Meta: only the selected profile (selectConfigName) is evaluated")
    put("verge/io.github.clash-verge-rev.clash-verge-rev/config.yaml", "mixed-port: 7897\nexternal-controller: 127.0.0.1:1\n")
    put("verge/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml", "mixed-port: 7897\ntun:\n  enable: true\nproxy-groups:\n  - {name: Proxy, type: select, proxies: [de-1, DIRECT]}\nrules:\n  - MATCH,Proxy\n")
    let vC = GUIApps.mihomoGUICandidates([gdir + "/verge"])
    expect(vC.count == 1 && vC[0].path.hasSuffix("clash-verge.yaml") && vC[0].app == "Clash Verge", "Clash Verge Rev: runtime clash-verge.yaml, not the partial config.yaml")
    let vArgs = Xray.configArgs(kind: "clash", args: ["verge-mihomo", "-d", "/v", "-f", "/v/clash-verge.yaml",
                                                       "-ext-ctl-unix", "/tmp/verge/verge-mihomo.sock", "-secret", "abc"], bases: [])
    expect(vArgs.count == 1 && vArgs[0].path == "/v/clash-verge.yaml" && vArgs[0].extCtlUnix == "/tmp/verge/verge-mihomo.sock"
           && vArgs[0].secret == "abc", "Clash Verge Rev: API from the core's command line; -f wins over -d")

    // ClashX Pro / Clash for Windows (also on macOS).
    put("pro/.config/clash/config.yaml", "rules:\n  - MATCH,DIRECT\n")
    put("pro/.config/clash/Dler.yaml", "mixed-port: 7890\nproxy-groups:\n  - {name: Proxy, type: select, proxies: [de-1]}\nrules:\n  - DOMAIN-SUFFIX,anthropic.com,DIRECT\n  - MATCH,Proxy\n")
    put("pro/Library/Preferences/com.west2online.ClashXPro.plist", #"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>selectConfigName</key><string>Dler</string></dict></plist>"#)
    let pro = detectSync(ProxyApps.allCandidates(home: gdir + "/pro", procs: ProxyApps.ProcInfo()))
    expect(pro.count == 1 && pro[0].name == "ClashX Pro" && pro[0].source.hasSuffix("Dler.yaml") && pro[0].sendsClaudeDirect,
           "ClashX Pro: selected profile only, sends Claude DIRECT")
    put("cfw/.config/clash/config.yaml", "mixed-port: 7890\nmode: rule\nexternal-controller: 127.0.0.1:1\n")
    put("cfw/.config/clash/profiles/1690000000001.yml", "rules:\n  - MATCH,DIRECT\n")
    put("cfw/.config/clash/profiles/1690000000002.yml", "mixed-port: 1234\nproxy-groups:\n  - {name: Proxy, type: select, proxies: [de-1, DIRECT]}\nrules:\n  - GEOIP,IR,DIRECT\n  - MATCH,Proxy\n")
    func cfwList(_ now: String) -> String {
        "files:\n  - time: 1690000000001.yml\n    name: old\n  - time: 1690000000002.yml\n    name: sub\n    selected:\n      - name: Proxy\n        now: \(now)\nindex: 1\n"
    }
    put("cfw/.config/clash/profiles/list.yml", cfwList("de-1"))
    var cfwApps = detectSync(ProxyApps.allCandidates(home: gdir + "/cfw", procs: ProxyApps.ProcInfo()))
    expect(cfwApps.count == 1 && cfwApps[0].name == "Clash for Windows" && cfwApps[0].ports == [7890]
           && cfwApps[0].anthropic.outcome == .proxy && cfwApps[0].anthropic.chain == ["Proxy", "de-1"],
           "Clash for Windows: selected profile + settings + saved selection")
    put("cfw/.config/clash/profiles/list.yml", cfwList("DIRECT"))
    cfwApps = detectSync(ProxyApps.allCandidates(home: gdir + "/cfw", procs: ProxyApps.ProcInfo()))
    expect(cfwApps.first?.sendsClaudeDirect == true, "Clash for Windows: saved selection DIRECT -> Claude DIRECT")
    let cfwArgs = Xray.configArgs(kind: "clash", args: ["clash-darwin", "-d", gdir + "/cfw/.config/clash", "-ext-ctl", "127.0.0.1:1", "-secret", "rnd"], bases: [])
    var cfwProcs = ProxyApps.ProcInfo(); cfwProcs.configs = cfwArgs
    let cfwCands = ProxyApps.allCandidates(home: gdir + "/cfw", procs: cfwProcs)
    expect(cfwCands.first?.kind == "cfw" && cfwCands.first?.secret == "rnd"
           && !cfwCands.contains { $0.kind == "clash" && $0.path.hasSuffix("/.config/clash/config.yaml") },
           "Clash for Windows: core's command-line API handed over, base config.yaml not evaluated alone")
    let ruleless = detectSync([ConfigCandidate(kind: "clash", path: gdir + "/cfw/.config/clash/config.yaml")])
    expect(ruleless.first?.anthropic.outcome == .unknown && ruleless.first?.sendsClaudeDirect == false, "rule-less config is uncertain, not DIRECT")

    // Remote Clash (Clash Meta for Android used as this Mac's proxy).
    let rc = RemoteAPIs.candidates(proxies: ["http://192.168.1.5:7890", "http://127.0.0.1:10809", nil],
                                   configured: [("192.168.1.5:9999", "s3")])
    expect(rc.map(\.path) == ["192.168.1.5:9999", "192.168.1.5:9090", "192.168.1.5:9097"] && rc[0].secret == "s3"
           && rc[1].app == "Clash on 192.168.1.5", "remote API candidates: proxy host + configured, not localhost")
    var phone = ProxyApp(kind: "clash", source: "API http://192.168.1.5:9090", live: true, tun: false, ports: [7890],
                         anthropic: bypassAll.0, check: bypassAll.1)
    phone.app = "Clash on 192.168.1.5"
    phone.remote = "192.168.1.5"
    expect(phone.servesPort("http://192.168.1.5:7890") && !phone.servesPort("http://127.0.0.1:7890")
           && app.servesPort("http://127.0.0.1:7890") && !app.servesPort("http://192.168.1.5:7890"), "servesPort is host-aware")
    expect(ProxyApps.decide([phone], anthropicInTunnel: false, desktopProxy: "http://192.168.1.5:7890").proxyDirect?.remote == "192.168.1.5",
           "decide: phone proxy sends Claude DIRECT")
    var phoneSt = GuardStatus(state: .allowed, enforcing: false, inIran: false, message: "m", ipv4: "5.1.1.1", proxy: nil, checkedAt: Date())
    phoneSt.apps = [phone]
    let phoneHook = run(phoneSt, ["HTTPS_PROXY": "http://192.168.1.5:7890"], .allowed, checks: &n0)
    expect(!phoneHook.0 && phoneHook.1.contains("192.168.1.5's own internet connection"), "hook: Claude Code via phone proxy sending DIRECT is blocked")
    let rfile = gdir + "/remote-apis.txt"
    _ = try? RemoteAPIs.command(["add", "192.168.1.5:9090", "s3"], path: rfile)
    let rlist = (try? RemoteAPIs.command(["list"], path: rfile)) ?? ""
    expect(RemoteAPIs.load(rfile).first?.secret == "s3" && rlist.contains("(with secret)") && !rlist.contains("s3")
           && (try? RemoteAPIs.command(["add", "nonsense"], path: rfile)) == nil, "remote-api add / list (secret not printed)")

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
