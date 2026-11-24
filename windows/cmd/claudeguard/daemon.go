//go:build windows

package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"claudeguard/internal/core"
	"claudeguard/internal/win"

	"golang.org/x/sys/windows"
)

const pollInterval = 15 * time.Second

type checkResult struct {
	gen    int
	direct core.Verdict
	route  *core.DesktopRoute // nil when no system proxy / PAC is set
	proxy  *core.Verdict      // nil when Claude Desktop's route is DIRECT
	sp     core.SystemProxy
	net    core.NetInfo
	apps   []core.ProxyApp
	dec    core.AppDecision
	physIF string // physical interface checked because an app sends Claude DIRECT
}

// runDaemon is the protection loop. Fail-closed:
//   - blocks Claude immediately at start, then checks;
//   - blocks immediately on any network change (VPN drop, Wi-Fi switch), then re-checks;
//   - re-checks every 15s, when the system proxy changes, and when the refresh event is signalled;
//   - lifts the block only after a positive verdict.
//
// Two routes are checked: DIRECT (Claude Code without proxy env vars) and the
// SYSTEM PROXY (Claude Desktop; v2ray "system proxy" mode). Direct connections to
// Anthropic are firewalled whenever the direct route isn't verified; traffic via a
// proxy that exits abroad keeps working.
func runDaemon(stop <-chan struct{}) {
	setupLogging()
	log.Printf("ClaudeGuard service starting")

	if err := os.MkdirAll(core.DataDir(), 0o755); err != nil {
		log.Printf("ERROR data dir: %v", err)
	}
	if err := win.SecureDir(core.DataDir()); err != nil {
		log.Printf("WARN securing data dir: %v", err)
	}

	checker := core.NewChecker()
	enf := &Enforcer{}
	enf.Block(true) // fail closed until proven otherwise

	status := core.Status{State: core.StateChecking, Enforcing: true,
		Message: "Starting up - verifying your location..."}
	if prev := core.LoadStatus(); prev != nil {
		status.InIran = prev.InIran // keep the Iran banner across restarts
		status.DesktopBlocked = prev.DesktopBlocked
	}
	var lastPublished *core.Status
	publish := func() {
		status.Enforcing = enf.Blocked()
		status.UpdatedAt = core.Now()
		if err := status.Save(); err != nil {
			log.Printf("ERROR saving status: %v", err)
		}
		s := status
		lastPublished = &s
	}
	publish()

	refreshCh := make(chan struct{}, 1)
	if ev, err := win.CreateRefreshEvent(core.RefreshEvent); err != nil {
		log.Printf("ERROR refresh event: %v", err)
	} else {
		go func() {
			for {
				if r, _ := windows.WaitForSingleObject(ev, windows.INFINITE); r == windows.WAIT_OBJECT_0 {
					select {
					case refreshCh <- struct{}{}:
					default:
					}
				}
			}
		}()
	}

	netCh := make(chan struct{}, 1)
	win.WatchNetwork(netCh)

	results := make(chan checkResult, 4)
	checking := false
	gen := 0
	lastProxy := win.SystemProxy()

	start := func() {
		checking = true
		g := gen
		sp := win.SystemProxy()
		lastProxy = sp
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			// TUN detection: which interface carries Anthropic's traffic vs the IP-check sites?
			ni, anthropicLocal := win.NetInfo()
			r := checkResult{gen: g, sp: sp}
			bypass := ni.AnthropicBypassesCheck()
			ni.Bound = bypass && anthropicLocal != nil

			if sp.Enabled() || sp.PAC != "" {
				route := core.ResolveDesktopRoute(ctx, sp) // evaluates the PAC file in PAC mode
				r.route = &route
			}
			// Clash / sing-box / ...: read their configs + APIs to see how they route Claude,
			// including a Clash on ANOTHER device used as the proxy (Clash Meta for Android).
			home, appData, localAppData := win.UserDirs3()
			procs := win.ProxyProcesses()
			cands := core.AllCandidates(home, appData, localAppData, procs)
			proxies := []string{core.ClaudeSettingsProxyIn(home)}
			if r.route != nil {
				proxies = append(proxies, r.route.Proxy, r.route.HTTP)
			}
			cands = append(cands, core.RemoteAPICandidates(proxies, core.LoadRemoteAPIs(core.RemoteAPIsFile()))...)
			r.apps = core.DetectProxyApps(ctx, cands, procs.IsRunning)
			desktopProxy := ""
			if r.route != nil {
				desktopProxy = r.route.Proxy
			}
			r.dec = core.DecideApps(r.apps, ni.AnthropicIsTunnel || ni.CheckIsTunnel, desktopProxy)

			// An app that carries Claude sends it DIRECT: its DIRECT outbound uses the real
			// (physical) connection when the app runs in TUN mode.
			var physical *core.Verdict
			if a := r.dec.TUNDirect; a != nil || (r.dec.ProxyDirect != nil && r.dec.ProxyDirect.TUN) {
				local, name := win.PhysicalIPv4()
				r.physIF = name
				v := core.Verdict{Kind: core.VerdictUnknown, Detail: "Couldn't find your physical network connection to verify."}
				if local != nil {
					v = checker.CheckBound(ctx, local)
				}
				physical = &v
			}
			r.net = ni

			switch {
			case r.dec.TUNDirect != nil:
				r.direct = *physical
			case ni.Bound:
				// Anthropic traffic leaves through a different interface (e.g. it bypasses
				// the TUN VPN): check the exit IP of THAT interface.
				r.direct = checker.CheckBound(ctx, anthropicLocal)
			case bypass:
				r.direct = core.Verdict{Kind: core.VerdictUnknown,
					Detail: "Anthropic traffic goes via " + ni.AnthropicIface + ", which has no IPv4 address to verify."}
			default:
				r.direct = checker.Check(ctx)
			}
			if r.route != nil && r.route.Proxy != "" {
				switch {
				case r.dec.ProxyDirect != nil && r.dec.ProxyDirect.Remote != "":
					// The proxy is another device whose rules send Claude DIRECT: Claude leaves
					// through that device's own connection, which can't be checked from here.
					v := core.Verdict{Kind: core.VerdictUnknown, Detail: r.dec.ProxyDirect.Name() +
						" sends Claude DIRECT through " + r.dec.ProxyDirect.Remote + "'s own internet connection, which can't be verified from this computer."}
					r.proxy = &v
				case r.dec.ProxyDirect != nil && physical != nil:
					r.proxy = physical
				case r.dec.ProxyDirect != nil:
					v := r.direct // non-TUN app: its DIRECT follows the normal OS route
					r.proxy = &v
				default:
					v := checker.CheckVia(ctx, r.route.Proxy)
					r.proxy = &v
				}
			}
			results <- r
		}()
	}
	urgent := func(msg string) {
		gen++ // invalidates any in-flight result
		status.State = core.StateChecking
		status.Message = msg
		publish()
		if !checking {
			start()
		}
	}
	killDesktop := func() {
		if n := win.KillClaudeDesktop(); n > 0 {
			log.Printf("terminated %d Claude Desktop process(es)", n)
		}
	}

	apply := func(r checkResult) {
		now := core.Now()
		d := r.direct

		// Claude Desktop's route (manual system proxy, or whatever the PAC file says).
		var route *core.ProxyRoute
		desktopIran := d.Kind == core.VerdictIran
		if rt := r.route; rt != nil {
			pr := core.ProxyRoute{SystemProxy: r.sp, Mode: rt.Mode, Checked: rt.Proxy, PACResult: rt.PACResult}
			pr.HTTP = rt.HTTP
			if p := r.proxy; p != nil {
				pr.Kind, pr.OK = p.Kind, p.Kind == core.VerdictAllowed
				pr.IPv4, pr.IPv6, pr.Country, pr.Detail = p.IPv4, p.IPv6, p.Country, p.Detail
				desktopIran = p.Kind == core.VerdictIran
			} else {
				// DIRECT: Claude Desktop shares the direct route's verdict.
				pr.Kind, pr.IPv4, pr.IPv6, pr.Country = d.Kind, d.IPv4, d.IPv6, d.Country
				pr.Detail = "The PAC file sends Claude traffic DIRECT."
				if rt.Note != "" {
					pr.Detail = "The " + rt.Note + "."
				}
			}
			route = &pr
		}
		proxyOK := route != nil && route.OK

		var state core.State
		var msg string
		switch {
		case d.Kind == core.VerdictAllowed:
			enf.Unblock(false)
			state, msg = core.StateAllowed, d.Detail+" Claude is allowed."
			if desktopIran {
				msg += " But your system proxy exits in Iran, so Claude Desktop is blocked."
			}
		case proxyOK:
			// Direct route is Iran/unknown: firewall direct access, keep hosts clean for v2ray.
			enf.Set(true, false, false)
			state = core.StateProxyOnly
			msg = "Direct connection: " + d.Detail + " Direct access to Claude is blocked. " +
				"Your proxy " + route.Describe() + " exits in " + core.CountryName(route.Country) +
				", so Claude Desktop works, and Claude Code works when it uses the proxy (HTTPS_PROXY)."
		default:
			enf.Set(true, true, false)
			state = core.StateBlocked
			if d.Kind == core.VerdictIran {
				msg = d.Detail + " Claude Code and Claude Desktop are blocked so your Iranian IP is not sent to Anthropic."
			} else {
				msg = d.Detail + " Claude stays blocked until your location can be verified."
			}
			if route != nil {
				msg += " System proxy: " + route.Detail
			}
		}
		// Clash / sing-box routing rules.
		if a := r.dec.TUNDirect; a != nil {
			msg = a.Name() + " sends Claude traffic DIRECT (" + a.Anthropic.Rule + "), so Claude uses your real connection" +
				physNote(r.physIF) + ". Route anthropic.com and claude.ai through your proxy (group / outbound). " + msg
		} else if a := r.dec.ProxyDirect; a != nil {
			if a.Remote != "" {
				msg += " " + a.Name() + " (your proxy on " + a.Remote + ") sends Claude traffic DIRECT (" + a.Anthropic.Rule +
					"), so Claude Desktop would use that device's own connection - blocked. Route anthropic.com and claude.ai through a proxy group there."
			} else {
				msg += " " + a.Name() + " (behind your system proxy) sends Claude traffic DIRECT (" + a.Anthropic.Rule + "), so Claude Desktop is treated as direct."
			}
		}
		if a := r.dec.Misrouted; a != nil && state == core.StateBlocked {
			msg += " Note: " + a.Name() + " sends Claude through the proxy but the IP-check sites DIRECT, so ClaudeGuard sees your real IP. " +
				"Add rules sending " + strings.Join(core.CheckHosts, ", ") + " through the same proxy."
		}
		for _, a := range r.apps {
			if a.Anthropic.Outcome == core.OutUnknown && (a.TUN || (r.route != nil && a.ServesPort(r.route.Proxy))) {
				msg += " Warning: can't tell whether " + a.Name() + " sends Claude DIRECT (" + a.Anthropic.Rule + ")."
				break
			}
		}

		// TUN VPN context.
		if n := r.net; n.Bound {
			msg = "Your VPN doesn't carry Anthropic traffic (it goes via " + n.AnthropicIface +
				"), so that path was checked. " + msg
		} else if d.Kind == core.VerdictIran && n.TunnelActive() {
			msg += " Your TUN VPN (" + n.TunnelName + ") is up, but traffic still exits in Iran - is it connected?"
		}
		if desktopIran {
			killDesktop()
		}
		if enf.Warning != "" && enf.Blocked() {
			msg += " WARNING: " + enf.Warning
		}

		ni := r.net
		status = core.Status{State: state, InIran: d.Kind == core.VerdictIran, Message: msg,
			IPv4: d.IPv4, IPv6: d.IPv6, Country: d.Country, Proxy: route, Network: &ni, Apps: r.apps,
			DesktopBlocked: desktopIran, CheckedAt: &now}
		proxyLog := "-"
		if route != nil {
			proxyLog = route.Describe() + "=" + string(route.Kind) + "/" + route.Country
		}
		log.Printf("state=%s direct=%s v4=%s v6=%s country=%s proxy=%s net=[%s]", state, d.Kind, d.IPv4, d.IPv6, d.Country, proxyLog, r.net.Summary())
		publish()
	}

	poll := time.NewTicker(pollInterval)
	enforceTick := time.NewTicker(3 * time.Second)
	defer poll.Stop()
	defer enforceTick.Stop()
	urgent("Starting up - verifying your location...")

	for {
		select {
		case <-stop:
			// Deliberately NOT unblocking: the block stays until the service verifies again.
			log.Printf("ClaudeGuard service stopping (block left in place)")
			return

		case <-refreshCh:
			log.Printf("refresh requested")
			checker.ClearCache()
			urgent("Checking your IP...")

		case <-netCh:
			log.Printf("network changed - blocking and re-verifying")
			enf.Block(false)
			urgent("Network changed - re-verifying your location...")

		case <-poll.C:
			if checking {
				publish() // heartbeat
			} else {
				start()
			}

		case <-enforceTick.C:
			if status.DesktopBlocked {
				killDesktop()
			}
			if sp := win.SystemProxy(); sp != lastProxy {
				log.Printf("system proxy changed: %+v -> %+v", lastProxy, sp)
				lastProxy = sp
				urgent("Proxy settings changed - re-verifying...")
			}
			if lastPublished != nil && time.Since(lastPublished.UpdatedAt) > pollInterval*2 {
				publish()
			}

		case r := <-results:
			checking = false
			if r.gen != gen {
				start()
			} else {
				apply(r)
			}
		}
	}
}

func physNote(name string) string {
	if name == "" {
		return ""
	}
	return " (" + name + ")"
}

func setupLogging() {
	_ = os.MkdirAll(core.DataDir(), 0o755)
	if fi, err := os.Stat(core.LogFile()); err == nil && fi.Size() > 2<<20 {
		_ = os.Rename(core.LogFile(), core.LogFile()+".old")
	}
	if f, err := os.OpenFile(core.LogFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		log.SetOutput(f)
	}
	log.SetFlags(log.LstdFlags)
}
