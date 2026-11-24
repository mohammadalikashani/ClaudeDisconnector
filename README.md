# ClaudeGuard

Blocks Claude Code and Claude Desktop whenever your public IP is in Iran, so no Iranian IP reaches Anthropic.

It runs as a background service. It checks your public IP every 15 seconds and on every network change, and allows Claude only after a successful "not Iran" check. Until then, Claude stays blocked.

| Platform | Folder | Requirements |
|---|---|---|
| macOS | [`macos/`](macos/README.md) | macOS 13+, Xcode Command Line Tools |
| Windows | [`windows/`](windows/README.md) | Windows 10/11, x64 or ARM64 (Go 1.22+ to build) |

## What it does

- **Checks every route Claude uses.** It looks at your direct connection, the system proxy and PAC files. It also detects TUN VPNs and split tunnels, and reads the routing rules of proxy apps (v2rayN, Xray, sing-box, Clash/mihomo, Hiddify, NekoRay…) to find the real exit IP for Anthropic traffic.
- **Blocks at several layers.** It edits the hosts file, adds a firewall rule for Anthropic's IP ranges (`160.79.104.0/23`, `2607:6bc0::/48`) and quits Claude Desktop while you're blocked.
- **Status icon.** A menu bar icon (macOS) or tray icon (Windows) shows your IP, your country and whether Claude is allowed, with a **Refresh** button.
- **Claude Code hook.** It stops prompts inside Claude Code with a clear "you are in Iran" message, and re-checks right away so resending works once your VPN is on.
- **Routes Claude Code through your proxy.** Claude Code ignores the system proxy, so `claudeguard claude-proxy on` sets `HTTPS_PROXY` for it.

## Quick start

**macOS**

```bash
cd macos
./install.sh      # run as your normal user; asks for your admin password
./uninstall.sh    # removes everything and lifts all blocks
```

**Windows**

```bash
cd windows
./build.sh        # outputs dist/ClaudeGuard-windows-{amd64,arm64}.zip
```

Unzip the archive for your CPU on the Windows PC and double-click `install.cmd`. Approve the admin prompt. `uninstall.cmd` removes everything.

See the platform READMEs for how each piece works, the CLI commands, supported VPN/proxy setups and limitations.

## Limitations

An administrator can stop the service or remove the rules. ClaudeGuard protects you from accidents, not from yourself. Each network change blocks Claude for a few seconds while it re-checks.

## License

[MIT](LICENSE)
