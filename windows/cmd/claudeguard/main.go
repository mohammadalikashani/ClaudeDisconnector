//go:build windows

// claudeguard.exe - ClaudeGuard service + command-line tool.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"claudeguard/internal/core"
	"claudeguard/internal/win"

	"golang.org/x/sys/windows/svc"
)

const usage = `usage: claudeguard <command>

  install        install ClaudeGuard (service, tray icon, Claude Code hook)
  uninstall      remove everything and lift all blocks
  check          check your IP/country once and print the verdict (changes nothing)
  check-pac <url> evaluate a PAC file for Claude's hosts and check that route
  status         print the current protection status
  refresh        ask the service to re-check your IP now
  lookup <ip>    print the country of an IP address (for testing)
  claude-proxy on [url] | off | status
                 route Claude Code through v2ray's HTTP proxy (system-proxy mode);
                 Claude Code ignores the Windows system proxy, so this sets HTTPS_PROXY for it
  hook           Claude Code UserPromptSubmit hook (used by Claude Code)
  service        run the protection service (started by Windows; foreground if run by hand as admin)
  cleanup        remove all blocks without uninstalling (admin)
  print-rules    print the firewall targets and hosts entries that get applied
`

func main() {
	args := os.Args[1:]
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "service":
		if isSvc, _ := svc.IsWindowsService(); isSvc {
			if err := svc.Run(core.ServiceName, svcHandler{}); err != nil {
				os.Exit(1)
			}
			return
		}
		if !win.IsElevated() {
			fail("run from an Administrator terminal")
		}
		stop := make(chan struct{})
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		go func() { <-sig; close(stop) }()
		fmt.Println("running in foreground; log:", core.LogFile(), "(Ctrl+C to stop)")
		runDaemon(stop)

	case "install":
		cmdInstall(args[1:])
	case "install-system": // elevated half of install
		os.Setenv("CLAUDEGUARD_GUI_ERRORS", "1")
		self, _ := os.Executable()
		installSystem(dirOf(self))
	case "uninstall":
		cmdUninstall(args[1:])
	case "uninstall-system":
		os.Setenv("CLAUDEGUARD_GUI_ERRORS", "1")
		uninstallSystem()

	case "check":
		if runCheck() != core.VerdictAllowed {
			os.Exit(1)
		}
	case "check-pac":
		if len(args) < 2 {
			fail("usage: claudeguard check-pac <pac-url>")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		rt := core.ResolveDesktopRoute(ctx, core.SystemProxy{PAC: args[1]})
		fmt.Printf("PAC answer for claude.ai: %s %s\n", orDash(rt.PACResult), rt.Note)
		if rt.Proxy == "" {
			fmt.Println("Claude Desktop route: DIRECT")
			os.Exit(1)
		}
		v := core.NewChecker().CheckVia(ctx, rt.Proxy)
		fmt.Printf("Claude Desktop route via %s: %s, %s %s (%s)\n", rt.Proxy, v.Kind, orDash(v.IPv4), core.CountryName(v.Country), v.Detail)
		if rt.HTTP != "" {
			fmt.Println("HTTP proxy usable by Claude Code:", rt.HTTP)
		}
		if v.Kind != core.VerdictAllowed {
			os.Exit(1)
		}
	case "status":
		runStatus()
	case "refresh":
		if err := win.SignalEvent(core.RefreshEvent); err != nil {
			fail("service not reachable: %v", err)
		}
		fmt.Println("refresh requested")
	case "lookup":
		if len(args) < 2 {
			fail("usage: claudeguard lookup <ip>")
		}
		c := core.NewChecker().Country(context.Background(), args[1])
		verdict := ""
		if c == "IR" {
			verdict = "  -> WOULD BLOCK"
		}
		fmt.Printf("%s: %s %s%s\n", args[1], orDash(c), core.CountryName(c), verdict)
	case "hook":
		hook()
	case "claude-proxy":
		claudeProxy(args[1:])
	case "cleanup":
		if !win.IsElevated() {
			fail("run from an Administrator terminal")
		}
		(&Enforcer{}).Unblock(true)
		fmt.Println("ClaudeGuard blocks removed (the service will re-apply them if it is still installed)")
	case "print-rules":
		fmt.Printf("Firewall rule %q blocks (in+out): %v\n\n", win.FirewallRule, core.AnthropicRanges)
		fmt.Print(core.RenderHosts("", true))
	default:
		fmt.Print(usage)
		if cmd != "" && cmd != "help" && cmd != "-h" && cmd != "--help" {
			os.Exit(1)
		}
	}
}

func runCheck() core.VerdictKind {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ni, local := win.NetInfo()
	fmt.Printf("network : %s\n", ni.Summary())
	home, appData := win.UserDirs()
	procs := win.ProxyProcesses()
	apps := core.DetectProxyApps(ctx, append(procs.Configs, core.CandidateConfigs(home, appData, procs.Dirs)...), procs.IsRunning)
	if len(apps) == 0 {
		fmt.Println("apps    : no running Clash / sing-box / Xray / V2Ray detected")
	}
	for _, a := range apps {
		fmt.Printf("apps    : %s\n          source=%s mode=%s tun=%v ports=%v\n          IP-check sites -> %s\n",
			a.Describe(), a.Source, a.Mode, a.TUN, a.Ports, a.Check.Outcome)
		if a.Note != "" {
			fmt.Printf("          note: %s\n", a.Note)
		}
	}
	var v core.Verdict
	if ni.AnthropicBypassesCheck() && local != nil {
		fmt.Printf("          (checking the path Anthropic traffic takes, via %s / %s)\n", ni.AnthropicIface, local)
		v = core.NewChecker().CheckBound(ctx, local)
	} else {
		v = core.NewChecker().Check(ctx)
	}
	fmt.Printf("verdict : %s\nipv4    : %s\nipv6    : %s\ncountry : %s %s\ndetail  : %s\n",
		v.Kind, orDash(v.IPv4), orDash(v.IPv6), orDash(v.Country), core.CountryName(v.Country), v.Detail)
	return v.Kind
}

func runStatus() {
	s := core.LoadStatus()
	if s == nil {
		fmt.Println("no status (is the service installed?)")
		os.Exit(1)
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	fmt.Println(string(b))
	if s.IsStale() {
		fmt.Println("WARNING: status is stale - the service doesn't seem to be running")
	}
}

// hook is the Claude Code UserPromptSubmit hook. Exit 2 = block the prompt and show stderr.
func hook() {
	_, _ = io.Copy(io.Discard, os.Stdin)
	allow, msg := core.RunHook(core.HookDeps{
		Load:    core.LoadStatus,
		Refresh: func() error { return win.SignalEvent(core.RefreshEvent) },
		CheckVia: func(proxy string) core.Verdict {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return core.NewChecker().CheckVia(ctx, proxy)
		},
		Getenv:    os.Getenv,
		Wait:      7 * time.Second,
		CachePath: filepath.Join(os.TempDir(), "claudeguard-proxycheck.json"),
		Where:     "tray icon",
		CLI:       `"C:/Program Files/ClaudeGuard/claudeguard.exe"`,
	})
	if !allow {
		fmt.Fprint(os.Stderr, msg)
		os.Exit(2)
	}
}

// claudeProxy routes Claude Code through an HTTP proxy via ~/.claude/settings.json env.HTTPS_PROXY.
func claudeProxy(args []string) {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "on":
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		proxy := ""
		if len(args) > 1 {
			proxy = args[1]
		} else if rt := core.ResolveDesktopRoute(ctx, win.SystemProxy()); rt.HTTP != "" {
			proxy = rt.HTTP // manual system proxy, or the PAC file's PROXY entry for Anthropic
		} else {
			fail("no HTTP proxy found in the system proxy / PAC settings. Turn on v2ray's system proxy or PAC mode, or pass it: claude-proxy on http://127.0.0.1:10809")
		}
		v := core.NewChecker().CheckVia(ctx, proxy)
		fmt.Printf("proxy %s exits in: %s (%s)\n", core.NormalizeProxyURL(proxy), core.CountryName(v.Country), v.Kind)
		if v.Kind == core.VerdictIran {
			fail("this proxy exits in Iran - not configuring it")
		}
		msg, err := core.SetClaudeProxy(proxy)
		if err != nil {
			fail("%v", err)
		}
		fmt.Println(msg)
	case "off":
		msg, err := core.SetClaudeProxy("")
		if err != nil {
			fail("%v", err)
		}
		fmt.Println(msg)
	case "", "status":
		fmt.Printf("Claude Code proxy (settings.json): %s\n", orDash(core.ClaudeSettingsProxy()))
		fmt.Printf("Claude Code proxy (this shell)   : %s\n", orDash(core.ClaudeCodeProxy(os.Getenv)))
		sp := win.SystemProxy()
		fmt.Printf("System proxy (v2ray)             : %+v\n", sp)
		if sp.PAC != "" {
			rt := core.ResolveDesktopRoute(context.Background(), sp)
			fmt.Printf("PAC answer for claude.ai         : %s %s\n", orDash(rt.PACResult), rt.Note)
		}
	default:
		fail("usage: claudeguard claude-proxy on [http://host:port] | off | status")
	}
}

type svcHandler struct{}

func (svcHandler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { runDaemon(stop); close(done) }()
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			s <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			s <- svc.Status{State: svc.StopPending}
			close(stop)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
			return false, 0
		}
	}
	return false, 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}
