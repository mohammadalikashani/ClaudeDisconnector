# ClaudeGuard (macOS)

Blocks Claude Code and Claude Desktop whenever your public IP is in Iran, so no Iranian IP reaches Anthropic.

## Install / uninstall

```bash
cd macos
./install.sh      # run as your normal user; asks for your admin password
./uninstall.sh    # removes everything and lifts all blocks
```

Requires the Xcode Command Line Tools (`xcode-select --install`). macOS 13+.

## How it works

| Piece | What it does |
|---|---|
| `claudeguardd daemon` (root LaunchDaemon) | Checks your public IPv4 and IPv6 and their country. **Fail-closed:** it blocks at boot and on every network change (VPN drop, Wi-Fi switch), then unblocks only after a successful "not Iran" check. It re-checks every 15s. |
| Block | 1. `/etc/hosts` points Claude/Anthropic domains to `0.0.0.0`. 2. A pf firewall anchor (`com.apple/250.ClaudeGuard`) rejects all traffic to Anthropic's IP ranges (`160.79.104.0/23`, `2607:6bc0::/48`) and kills open connections. 3. On an Iranian IP, Claude Desktop is quit and kept closed. |
| `ClaudeGuard.app` (menu bar) | Shield icon with your status, IP and country, plus a **Refresh** button. Pops up a "You are in Iran" window when an Iranian IP is detected. |
| Claude Code hook | A `UserPromptSubmit` hook in `~/.claude/settings.json` shows the "you are in Iran" error inside Claude Code and blocks the prompt. If blocked, it first triggers a re-check, so after you turn on the VPN, resending the prompt works. |

### v2ray "system proxy" mode

Two routes are checked separately, because Claude's two apps use different routes:

| Route | Used by | Checked how |
|---|---|---|
| **Direct** | Claude Code (it **ignores the macOS system proxy**; it only uses `HTTPS_PROXY`/`HTTP_PROXY`) | IP check that bypasses every proxy |
| **System proxy / PAC** | Claude Desktop (Chromium follows the system proxy) | IP check through the system proxy, or through the proxy the PAC file picks for Anthropic |

| Direct | System proxy | Result |
|---|---|---|
| abroad | – | **Allowed** (green) |
| Iran / unknown | exits abroad | **Allowed via proxy only** (blue). Direct connections to Anthropic stay firewalled. Traffic through v2ray is unaffected, because v2ray connects to its own server. Claude Desktop works. Claude Code works once it uses the proxy. |
| Iran / unknown | off / Iran / dead | **Blocked** (red/orange) |

To make Claude Code use v2ray, click **Route Claude Code through http://127.0.0.1:…** in the menu, or run `claudeguard claude-proxy on`. Then restart Claude Code. This writes `env.HTTPS_PROXY` into `~/.claude/settings.json`. If v2ray is off later, Claude Code simply can't connect (nothing leaks). `claudeguard claude-proxy off` undoes it.

**PAC mode** (v2rayN/V2rayU "PAC" or "auto-config" setting) is supported too:
- ClaudeGuard downloads the PAC file and evaluates `FindProxyForURL` for `claude.ai` and `api.anthropic.com`, the same way Claude Desktop's Chromium does.
- It then checks the exit IP of the route the PAC chose, forcing the check through that proxy even if the PAC sends the IP-check sites `DIRECT`.
- If the PAC sends Claude `DIRECT`, can't be loaded, or the script fails, Claude Desktop is treated as going direct (Chromium's behaviour), and the direct verdict applies.
- `PROXY host:port` from the PAC is offered to Claude Code as its HTTP proxy.
- To test a PAC file by hand: `claudeguard check-pac http://127.0.0.1:10810/pac`.

The Claude Code hook looks at the proxy variables Claude Code is *actually* running with:
- **Proxy set:** it allows the prompt only if that proxy exits outside Iran. It reuses the service's check, or checks live and caches the result for 60s.
- **No proxy set:** it allows the prompt only if the direct route is verified.
- **SOCKS-only proxies:** Claude Code can't use them, so the hook says so.

### TUN mode (v2rayN/V2Box/sing-box/Clash TUN, WireGuard, OpenVPN…)

ClaudeGuard asks the OS which network interface carries Anthropic's traffic (it only looks up the route to `160.79.104.10`, it never contacts Anthropic) and which one carries the IP-check traffic:

| What it finds | What it does |
|---|---|
| Both go through a TUN interface | Shows **"TUN VPN on: …"**. The normal check sees the tunnel's exit IP, which is the one Claude uses. |
| Anthropic **bypasses** the tunnel (split tunnel, excluded routes, partial VPN) | Shows **"Anthropic traffic BYPASSES it"**. The check is **bound to Anthropic's interface**, so it sees the IP Claude would really use. Without this, the check would go through the TUN, see a foreign IP, and unblock while Claude leaks from your real IP. |
| TUN is up but still exits in Iran | Blocked, with "is your VPN connected?" |

The bound check does its own DNS lookups over that interface, so TUN "fake-ip" DNS can't confuse it. Test any interface by hand with `claudeguard check-iface en0`.

### Clash / sing-box routing rules (Clash Verge, mihomo, ClashX Meta, sing-box, Hiddify, v2rayN…)

TUN and proxy apps route by **rules**, so the OS can't tell where Claude's traffic really goes. A common Iranian setup such as "proxy only blocked sites, `MATCH,DIRECT` for the rest" sends Claude **DIRECT** while the IP-check sites go through the proxy. ClaudeGuard would then see a foreign IP while Claude leaks your real one. So ClaudeGuard reads the apps' own configuration:

1. **Finds them.** It checks the usual config locations (Clash Verge Rev, mihomo/Clash, ClashX Meta, sing-box, Hiddify, v2rayN's generated core config), the config files named on running processes' command lines (macOS) (Windows reads them too, with relative paths tried against the app's folders), and the default API ports `9090`, `9097` and `16756`. Configs of apps that aren't running are ignored.
2. **Asks the running app.** It uses the Clash external-controller API, or sing-box's Clash-compatible API, with the `secret` from the config. That gives the live mode, the loaded rules, the **currently selected** node of every selector, and live connections. Without an API it falls back to the rules in the config file.
3. **Evaluates the rules** for `claude.ai`/`api.anthropic.com` and for the IP-check sites, then follows groups/selectors down to DIRECT, REJECT or a proxy node. Clash handles `DOMAIN*`, `GEOIP`, `IP-CIDR`, `DST-PORT`, `NETWORK`, `PROCESS-*`, `MATCH`, modes and logical rules. sing-box handles `domain*`, `ip_cidr`, `geoip`, `port`, `network`, `protocol`, `clash_mode`, `invert`, `action: route/reject/sniff`, selectors and `final`. `GEOSITE`/`RULE-SET` are judged by name (`category-ir`, `cn`, `private` don't contain Claude; `anthropic`, `claude`, `category-ai-!cn` do). Anything it can't decide is reported as **uncertain**.
4. **Acts, only if that app actually carries Claude:** its TUN is on and Anthropic goes into a tunnel, the system proxy / PAC points at its port, or Claude Code's `HTTPS_PROXY` does.

| What it finds | What it does |
|---|---|
| The app sends Claude **DIRECT** (a rule, `mode: direct`, a selector set to DIRECT, or a **live Claude connection going DIRECT**) | Checks the exit IP of your **physical** connection (the one under the TUN) and blocks if it's Iranian. The message names the rule, e.g. *"Clash sends Claude traffic DIRECT (MATCH,DIRECT)"*. |
| Claude is proxied, but the IP-check sites go DIRECT | Warns that ClaudeGuard sees your real IP and may block needlessly, and tells you to route the IP-check sites through the same group. |
| Can't tell (a selector without an API that could pick DIRECT, unknown rule-set…) | Warning only. |

The tray/menu shows a line per app, e.g. `Clash: Claude -> PROXY [Proxy > DE-1] via rule DOMAIN-SUFFIX,anthropic.com,Proxy`.

When it decides:
- Any address geolocates to Iran → **blocked**.
- No IP found, or the country can't be determined → **blocked** (can't verify).
- Otherwise → **allowed**.

It asks three geo services (ipinfo.io, ipapi.co, country.is). If any one says IR, you're treated as being in Iran.


### Xray / V2Ray routing rules (v2rayN, V2rayU, V2RayXS, Qv2ray, plain xray/v2ray)

Xray has no Clash-style API, so ClaudeGuard reads the core's JSON config: the file named on the running `xray`/`v2ray` command line (`-c`, `-config`, `-confdir`; relative paths are resolved against the process's folder), or the usual locations (v2rayN `binConfigs`/`guiConfigs`, `~/.V2rayU`, V2RayXS, Qv2ray `config.gen.json`, `/usr/local/etc/xray`…). JSON files are recognised as sing-box or Xray by their content, and comments are allowed.

- **Rules:** `domain` (`domain:`, `full:`, `regexp:`, `keyword:`, plain keyword, `geosite:`, `ext:`), `ip` (CIDR, `geoip:`, `geoip:!xx`), `port`, `network`, `protocol`, `inboundTag`, balancers (`balancerTag`), and rules that are turned off.
- **`domainStrategy`:** `AsIs` ignores IP rules for domain requests. `IPIfNonMatch` re-checks IP rules after the domain rules miss. `IPOnDemand` resolves at the first IP rule.
- **Default route:** when no rule matches, traffic goes to the **first outbound**. If that is `freedom` (including `fragment` configs), Claude goes out on your real IP.
- **Outbounds:** `freedom` means DIRECT and `blackhole` means REJECT. A balancer that can pick a `freedom` outbound is uncertain.
- **Chained apps:** when an app hands traffic to a local SOCKS/HTTP port of another app, the chain is followed. Example: v2rayN's TUN (sing-box) forwards to xray on `127.0.0.1:10808`, and xray then sends Claude DIRECT. The result is reported on the TUN app, so the block applies.
- **V2Ray v5 format** (`"router": {"rule": [...]}`) is read too. It handles `domain` (`Plain`/`Regex`/`RootDomain`/`Full`), `geoDomain`, `geoip` (codes, `cidr`, `inverseMatch`), `portList`/`portRange`, `networks`, `inboundTag`, `balancingTag`/`balancingRule` and `domainStrategy` (`AsIs`, `UseIp`, `IpIfNonMatch`, `IpOnDemand`). Field names can be camelCase or snake_case, and enums can be names or numbers.


### Hiddify and NekoRay / NekoBox / Throne

- **Hiddify** is a sing-box client. ClaudeGuard looks through Hiddify's data folders for the generated core config (`current-config.json`) and evaluates it like any sing-box config. It also reads Hiddify's preferences (`shared_preferences.json`, or the `app.hiddify.com` plist on macOS) for:
  - the Clash API port, which is asked for live selections and live Claude connections;
  - the mixed port;
  - TUN mode.

  On macOS, Hiddify keeps its data in a protected group container (`group.apple.hiddify.com`). ClaudeGuard can read it only if `/Library/PrivilegedHelperTools/claudeguardd` has **Full Disk Access** (System Settings → Privacy & Security). Without that, ClaudeGuard still checks Hiddify through its live API (port `16756`) while Hiddify is running.
- **NekoRay / NekoBox / Throne** give their core its config over gRPC, so it never exists as a file. ClaudeGuard rebuilds the routing from the app's own settings in its `config` folder. That folder is next to the executable (portable Windows installs) or under `~/.config/nekoray`, `~/.config/nekobox` or `~/.config/Throne`.
  - **Settings read** from `groups/nekobox.json` (or `nekoray.json`): the SOCKS port (default `2080`), the active route profile, and the optional Clash API.
  - **The active route profile** is in `routes_box/<name>` (sing-box core) or `routes/<name>` (Xray core). It is evaluated in NekoRay's order:
    1. custom rules;
    2. block, proxy, then direct domains;
    3. block, proxy, then direct IPs;
    4. the default outbound (`proxy`, or `bypass`, which means DIRECT).
  - **TUN mode:** NekoBox runs a separate sing-box TUN core that forwards to the SOCKS port. ClaudeGuard follows that chain, so a profile that sends Claude to `bypass` gets blocked in TUN mode too.


### FlClash and Karing

- **FlClash** is a mihomo (Clash) GUI. ClaudeGuard finds its data folder (`com.follow.clash`, or `com.follow\clash` on Windows) and evaluates the **current profile** (`profiles/<id>.yaml`) the way FlClash runs it. FlClash's own settings are applied on top: mode, mixed port, TUN, external controller and secret. Rules added or replaced through the profile's override settings are applied too. Settings are read from `config.json`, or from older versions' Flutter preferences (`shared_preferences.json`, or a plist on macOS). If FlClash's API is on, its live selections and connections are used as for any Clash.
- **Karing** is a sing-box GUI. ClaudeGuard searches Karing's folders for the newest full sing-box config (one with inbounds, outbounds and a route, not a subscription file) and evaluates it like any sing-box config, including its Clash API if it has one.
- On macOS, App Store builds keep their data in protected containers. To read them, give `claudeguardd` Full Disk Access, as for Hiddify.



### Mihomo Party, Clash Nyanpasu, Clash Verge Rev and ClashX Meta

- **Which file is read:** both apps write the **runtime config** the core actually runs before starting it. ClaudeGuard searches their data folders (`mihomo-party`, `Clash Nyanpasu` / `clash-nyanpasu`, including portable folders next to the executable) and reads the newest one:
  - Mihomo Party: `work/config.yaml`;
  - Clash Nyanpasu: `clash-config.yaml`.

  Profile files are ignored because they aren't what the core runs. When the core is running, the config named on its command line (`mihomo -d … -f …`) is used too.
- **Live API:** these apps often expose the mihomo API on a **unix socket** (`external-controller-unix`, macOS/Linux/Windows) or a **Windows named pipe** (`external-controller-pipe`) rather than a TCP port. ClaudeGuard talks to all three, with the `secret`. Through the API it sees the node **currently selected** and live Claude connections, as for any Clash.
- **App names:** configs are named after the app they belong to (Mihomo Party, Clash Nyanpasu, Clash Verge, ClashX, v2rayN…), so messages say which app to fix.

- **Clash Verge Rev** (and the original Clash Verge): ClaudeGuard reads the runtime `clash-verge.yaml` from its data folder (`io.github.clash-verge-rev.clash-verge-rev`, also portable `.config` folders). The `config.yaml` beside it is only a partial override with no rules, so it's ignored. Verge Rev 2.x starts its core with the API on the command line (`-ext-ctl-unix /tmp/verge/verge-mihomo.sock`, or `-ext-ctl-pipe \\.\pipe\verge-mihomo` on Windows, plus `-secret`). ClaudeGuard reads those flags from the running core, so it sees the live selection even though the file doesn't name the API. Any mihomo started with `-ext-ctl*` / `-secret` benefits.
- **ClashX Meta** (and ClashX / ClashX Pro, macOS): profiles live in `~/.config/clash.meta/` (`~/.config/clash/` for ClashX). The **selected** profile is read from the app's preferences (`selectConfigName` in `~/Library/Preferences/com.metacubex.ClashX.meta.plist`), and other yaml files in that folder are ignored. The API comes from the profile's `external-controller`, or ClashX's default `127.0.0.1:9090`.

- **Clash for Windows** (also its macOS / Linux builds): ClaudeGuard reads `~/.config/clash/` the way CFW uses it.
  - **Which profile:** the one selected in `profiles/list.yml` (`index`) is evaluated, with CFW's general settings from `config.yaml` (ports, mode, controller, secret) applied on top.
  - **Saved selections:** each group's selection saved in `list.yml` is used, so a group CFW has set to DIRECT is caught even without the API.
  - **API:** CFW starts its core with a random controller and secret on the command line. ClaudeGuard reads those from the running core and uses the live API instead.
  - **Parsers:** if profile parsers are on (`cfw-settings.yaml`), the menu notes that the rules may differ from the file.
- **Files with no rules:** a Clash config with no rules (usually a GUI's partial settings file, like CFW's or Verge's `config.yaml`) is reported as **uncertain**, never as "Claude goes DIRECT".
- **ClashX Pro** (macOS): profiles live in `~/.config/clash/`. The selected one is read from `com.west2online.ClashXPro.plist` (`selectConfigName`), and only that profile is evaluated. The API comes from the profile's `external-controller`, or the default `127.0.0.1:9090`.


### Clash Meta for Android (or any Clash on another device) used as your proxy

A common setup is a phone running **Clash Meta for Android** with *Allow LAN*, and this computer's system proxy, PAC or `HTTPS_PROXY` pointing at it (`192.168.x.x:7890`). The app's files are in Android's private app storage, so they can't be read from a computer, even over USB. What ClaudeGuard can do is ask its **Clash API over the LAN**:

- **Where it looks:** whenever the system proxy, the PAC answer or Claude Code's proxy is another device, ClaudeGuard probes that host's API on ports `9090` and `9097`. For a different port, or an API with a secret, add it yourself:
  `sudo claudeguard remote-api add 192.168.1.5:9090 <secret>` (also `list` / `remove`). In CMFA, enable the API under *Override → External controller* with `0.0.0.0:9090`.
- **If that device sends Claude DIRECT:** Claude would leave through **the phone's own connection**, usually your Iranian mobile IP, which can't be checked from this computer. So Claude Desktop is blocked, and Claude Code's prompt is blocked when its `HTTPS_PROXY` is that device. This is the case even when this computer's own direct connection is fine.
- **If it proxies Claude:** the normal check through the proxy applies.
- **Hotspot / USB tethering is different:** the phone's VPN doesn't carry tethered traffic, and that case is already covered, because this computer's exit IP is then the phone's mobile IP.

### Shadowrocket and Stash (macOS only)

These are iOS / Mac App Store apps and run as a VPN (TUN).

- **Shadowrocket:** ClaudeGuard reads its Surge-style `.conf` files: the `[Rule]` section, `[Proxy Group]` and `FINAL`. `PROXY` means the server picked in the app. `RULE-SET`/`DOMAIN-SET` lists are judged by name: `Iran`, `SYSTEM`, `LAN` and ad lists don't contain Claude. A group that can pick `DIRECT` is reported as uncertain.
- **Stash:** ClaudeGuard reads its Clash-format profiles and uses Stash's Clash API (`external-controller`) when it is on.
- **Which profile:** each app keeps the active profile in its private settings, so ClaudeGuard takes the **most recently modified** config. When there are several, the note in the menu says so.
- **Where the files are:** they live in the apps' sandbox / group containers or in iCloud Drive (`~/Library/Mobile Documents`). Reading the containers needs **Full Disk Access** for `/Library/PrivilegedHelperTools/claudeguardd`.


### Surge and Quantumult X (macOS only)

- **Surge (Mac):** ClaudeGuard reads the profile (`.conf`), using the same parser as Shadowrocket: rules, `[Proxy Group]` including `subnet` groups, and `FINAL`. It also reads `http-listen` and `socks5-listen` for the ports. If the profile turns on Surge's **HTTP API** (`http-api = key@127.0.0.1:port`), ClaudeGuard also reads, using the key:
  - the outbound mode (direct / global proxy / rule);
  - the policy **currently selected** in each group;
  - whether Enhanced Mode (TUN) is on;
  - live connections, which catches a live Claude connection going DIRECT.

  Without the API, a group that can pick DIRECT is reported as uncertain.
- **Quantumult X:** ClaudeGuard reads its own syntax:
  - **`[filter_local]` rules:** `host`, `host-suffix`, `host-keyword`, `host-wildcard`, `host-regex`, `ip-cidr`, `geoip` and `final`.
  - **`[filter_remote]` lists:** enabled ones only; `force-policy` is respected, and lists without it are judged by tag and URL.
  - **`[policy]` groups:** `static`, `available`, `round-robin`, `url-latency-benchmark` and `ssid`. A group that can pick `direct` is uncertain.
  - **Built-in policies:** `direct`, `reject*`, and `proxy` (the server you selected).
- As with Shadowrocket and Stash, the **most recently modified** profile is taken as the active one. Profiles in protected containers need **Full Disk Access** for `claudeguardd`. Surge's own folder (`~/Library/Application Support/com.nssurge.surge-mac`) and iCloud Drive are readable without it.


### Loon and Egern (macOS only)

- **Loon:** ClaudeGuard reads its Surge-like `.conf` with the same parser.
  - **Rule order:** local `[Rule]` entries, then `[Remote Rule]` lists, then `FINAL`. Disabled lists are skipped. A list's `policy=` is respected, and the list is judged by its tag and URL.
  - **Groups:** `[Proxy Group]`, including `ssid` groups such as `cellular=DIRECT`. A group that can pick DIRECT is reported as uncertain.
- **Egern:** ClaudeGuard reads its YAML profile with a small built-in YAML reader.
  - **`policy_groups`:** `select`, `auto_test`, `ssid` and the others.
  - **`rules`:** `domain*`, `ip_cidr*`, `geoip` (with `no_resolve`), `dst_port`, `rule_set` and `domain_set`, judged by name, plus `default`. Other types are reported as uncertain.
- As with the other Apple-only apps, the **most recently modified** profile is taken as the active one. Profiles in protected containers need **Full Disk Access** for `claudeguardd`.

## CLI

```bash
claudeguard check          # one-off check of direct route + system proxy, changes nothing
claudeguard check-via http://127.0.0.1:10809
claudeguard check-pac http://127.0.0.1:10810/pac
claudeguard check-iface en0   # exit IP of one interface, bypassing any TUN
claudeguard check-apps [config files]   # how Clash / sing-box / Xray / Hiddify / NekoBox route Claude
claudeguard claude-proxy on|off|status
claudeguard status         # current state (JSON)
claudeguard refresh        # same as the Refresh button
claudeguard lookup 2.144.1.1
claudeguard print-rules    # firewall + hosts entries that get applied
tail -f /var/log/claudeguard.log
```

## Limitations

- **Routing rules inside VPN apps** are read for Clash, sing-box, Xray/V2Ray (v4 and v5 JSON formats), Hiddify, NekoRay/NekoBox/Throne, FlClash, Karing, Mihomo Party, Clash Nyanpasu, Shadowrocket, Stash, Surge, Quantumult X, Loon and Egern (see above).
- **Network changes:** each one blocks Claude for about 1–3s while it re-checks, so in-flight requests get cut.
- **IPv6:** if your ISP gives you an Iranian IPv6 address while your VPN only tunnels IPv4, you stay blocked. This is on purpose.
- **Root can undo it:** anyone with admin rights can remove it. It protects you from accidents, not from yourself.
