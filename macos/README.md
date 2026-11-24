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

## CLI

```bash
claudeguard check          # one-off check of direct route + system proxy, changes nothing
claudeguard check-via http://127.0.0.1:10809
claudeguard check-pac http://127.0.0.1:10810/pac
claudeguard check-iface en0   # exit IP of one interface, bypassing any TUN
claudeguard check-apps [config files]   # how Clash / sing-box / Xray route Claude
claudeguard claude-proxy on|off|status
claudeguard status         # current state (JSON)
claudeguard refresh        # same as the Refresh button
claudeguard lookup 2.144.1.1
claudeguard print-rules    # firewall + hosts entries that get applied
tail -f /var/log/claudeguard.log
```

## Limitations

- **Routing rules inside VPN apps** are read for Clash, sing-box and Xray/V2Ray (v4 and v5 JSON formats; see above).
- **Network changes:** each one blocks Claude for about 1–3s while it re-checks, so in-flight requests get cut.
- **IPv6:** if your ISP gives you an Iranian IPv6 address while your VPN only tunnels IPv4, you stay blocked. This is on purpose.
- **Root can undo it:** anyone with admin rights can remove it. It protects you from accidents, not from yourself.
