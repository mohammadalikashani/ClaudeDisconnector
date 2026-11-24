//go:build windows

// ClaudeGuardTray.exe - system-tray icon: status, Refresh, the "You are in Iran"
// dialog, and the "route Claude Code through v2ray" toggle.
// Build with -ldflags "-H windowsgui" so no console window appears.
package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"claudeguard/internal/core"
	"claudeguard/internal/win"

	"fyne.io/systray"
)

func main() {
	if !win.SingleInstance(`Local\ClaudeGuardTray`) {
		return
	}
	systray.Run(onReady, func() {})
}

type tray struct {
	mu          sync.Mutex
	refreshing  bool
	refreshAt   time.Time
	lastAlarm   bool
	firstUpdate bool

	mState, mVPN, mDirect, mProxy, mDesktop, mChecked, mRefresh, mClaudeCode *systray.MenuItem
	mApps                                                                    [2]*systray.MenuItem
}

var dialogOpen atomic.Bool

const refreshTitle = "Refresh (check my IP again)"

func onReady() {
	t := &tray{firstUpdate: true}
	systray.SetIcon(iconChecking)
	systray.SetTitle("ClaudeGuard")
	systray.SetTooltip("ClaudeGuard")

	disabled := func(title string) *systray.MenuItem {
		m := systray.AddMenuItem(title, "")
		m.Disable()
		return m
	}
	t.mState = disabled("ClaudeGuard: loading...")
	t.mVPN = disabled("VPN: -")
	for i := range t.mApps {
		t.mApps[i] = disabled("")
		t.mApps[i].Hide()
	}
	t.mDirect = disabled("Direct: -")
	t.mProxy = disabled("System proxy: off")
	t.mDesktop = disabled("Claude Desktop: -")
	t.mChecked = disabled("Checked: -")
	systray.AddSeparator()
	t.mRefresh = systray.AddMenuItem(refreshTitle, "")
	t.mClaudeCode = systray.AddMenuItem("Route Claude Code through system proxy", "")
	t.mClaudeCode.Hide()
	mDetails := systray.AddMenuItem("Show status...", "")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Hide tray icon", "Protection keeps running in the background")

	systray.SetOnTapped(func() { go showDetails() })

	t.update()
	ticker := time.NewTicker(2 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				t.update()
			case <-t.mRefresh.ClickedCh:
				t.refresh()
			case <-t.mClaudeCode.ClickedCh:
				go t.toggleClaudeCodeProxy()
			case <-mDetails.ClickedCh:
				go showDetails()
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func (t *tray) refresh() {
	t.mu.Lock()
	t.refreshing = true
	t.refreshAt = core.Now()
	t.mu.Unlock()
	t.mRefresh.SetTitle("Checking...")
	t.mRefresh.Disable()
	if err := win.SignalEvent(core.RefreshEvent); err != nil {
		t.mu.Lock()
		t.refreshing = false
		t.mu.Unlock()
		t.mRefresh.SetTitle(refreshTitle)
		t.mRefresh.Enable()
		go win.MessageBox("ClaudeGuard", "The ClaudeGuard service isn't running.\n\n"+err.Error(), win.MB_OK|win.MB_ICONWARNING)
	}
	t.update()
}

func routeLine(prefix, country, ip string, kind core.VerdictKind) string {
	if ip == "" && country == "" {
		return prefix + "unknown"
	}
	mark := "OK"
	switch kind {
	case core.VerdictIran:
		mark = "IRAN"
	case core.VerdictUnknown:
		mark = "unverified"
	}
	return fmt.Sprintf("%s%s  %s  (%s)", prefix, core.CountryName(country), orDash(ip), mark)
}

func (t *tray) update() {
	s := core.LoadStatus()
	running := s != nil && !s.IsStale()

	switch {
	case !running:
		systray.SetIcon(iconDown)
		t.mState.SetTitle("Service not running - Claude can't be verified")
		systray.SetTooltip("ClaudeGuard: service not running")
	case s.State == core.StateAllowed:
		systray.SetIcon(iconAllowed)
		t.mState.SetTitle("Claude allowed")
		systray.SetTooltip("ClaudeGuard: Claude allowed (" + core.CountryName(s.Country) + ")")
	case s.State == core.StateProxyOnly:
		systray.SetIcon(iconProxy)
		t.mState.SetTitle("Allowed via proxy only (direct connection blocked)")
		systray.SetTooltip("ClaudeGuard: allowed via proxy (" + core.CountryName(s.Proxy.Country) + ")")
	case s.State == core.StateChecking:
		systray.SetIcon(iconChecking)
		t.mState.SetTitle("Checking your IP...")
		systray.SetTooltip("ClaudeGuard: checking...")
	case s.InIran:
		systray.SetIcon(iconIran)
		t.mState.SetTitle("BLOCKED: you are on an Iranian IP")
		systray.SetTooltip("ClaudeGuard: BLOCKED - Iranian IP")
	default:
		systray.SetIcon(iconUnknown)
		t.mState.SetTitle("BLOCKED: location can't be verified")
		systray.SetTooltip("ClaudeGuard: BLOCKED - location not verified")
	}

	ccProxy := core.ClaudeSettingsProxy()
	if s != nil {
		directKind := core.VerdictAllowed
		if s.InIran {
			directKind = core.VerdictIran
		} else if s.Enforcing {
			directKind = core.VerdictUnknown
		}
		ip := s.IPv4
		if ip == "" {
			ip = s.IPv6
		}
		if s.Network != nil {
			t.mVPN.SetTitle("VPN: " + s.Network.Summary())
		}
		for i, m := range t.mApps {
			if i < len(s.Apps) {
				prefix := ""
				if s.Apps[i].SendsClaudeDirect() {
					prefix = "WARNING "
				}
				m.SetTitle(prefix + s.Apps[i].Describe())
				m.Show()
			} else {
				m.Hide()
			}
		}
		directLabel := "Direct: "
		if s.Network != nil && s.Network.TunnelActive() && !s.Network.Bound {
			directLabel = "Direct (through TUN): "
		} else if s.Network != nil && s.Network.Bound {
			directLabel = "Anthropic path (" + s.Network.AnthropicIface + "): "
		}
		t.mDirect.SetTitle(routeLine(directLabel, s.Country, ip, directKind))
		if s.Proxy != nil {
			pip := s.Proxy.IPv4
			if pip == "" {
				pip = s.Proxy.IPv6
			}
			t.mProxy.SetTitle(routeLine("Claude Desktop route "+s.Proxy.Describe()+": ", s.Proxy.Country, pip, s.Proxy.Kind))
		} else {
			t.mProxy.SetTitle("System proxy: off")
		}
		if s.DesktopBlocked {
			t.mDesktop.SetTitle("Claude Desktop: blocked")
		} else {
			t.mDesktop.SetTitle("Claude Desktop: allowed")
		}
		t.mChecked.SetTitle("Checked: " + ago(s.CheckedAt))

		// Claude Code ignores the system proxy: offer to route it through v2ray's HTTP port.
		switch {
		case ccProxy != "":
			t.mClaudeCode.SetTitle("Claude Code uses proxy " + ccProxy + " (click to remove)")
			t.mClaudeCode.Check()
			t.mClaudeCode.Show()
		case s.Proxy != nil && s.Proxy.HTTP != "":
			t.mClaudeCode.SetTitle("Route Claude Code through " + s.Proxy.HTTP)
			t.mClaudeCode.Uncheck()
			t.mClaudeCode.Show()
		default:
			t.mClaudeCode.Hide()
		}
	}

	t.mu.Lock()
	finished := false
	if t.refreshing {
		if s != nil && s.State != core.StateChecking && s.CheckedAt != nil && !s.CheckedAt.Before(t.refreshAt) {
			t.refreshing, finished = false, true
		} else if time.Since(t.refreshAt) > 30*time.Second {
			t.refreshing = false
		}
		if !t.refreshing {
			t.mRefresh.SetTitle(refreshTitle)
			t.mRefresh.Enable()
		}
	}
	// Alarm = in Iran with no safe route at all.
	alarm := running && s.InIran && s.State == core.StateBlocked
	newAlarm := alarm && (!t.lastAlarm || t.firstUpdate)
	t.lastAlarm = alarm
	t.firstUpdate = false
	t.mu.Unlock()

	if newAlarm || (finished && alarm) {
		go iranDialog()
	}
}

func (t *tray) toggleClaudeCodeProxy() {
	if cur := core.ClaudeSettingsProxy(); cur != "" {
		msg, err := core.SetClaudeProxy("")
		if err != nil {
			msg = err.Error()
		}
		win.MessageBox("ClaudeGuard", msg, win.MB_OK|win.MB_ICONINFORMATION)
		t.update()
		return
	}
	s := core.LoadStatus()
	if s == nil || s.Proxy == nil || s.Proxy.HTTP == "" {
		win.MessageBox("ClaudeGuard", "No HTTP system proxy found. Turn on v2ray's system proxy first.", win.MB_OK|win.MB_ICONWARNING)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	v := core.NewChecker().CheckVia(ctx, s.Proxy.HTTP)
	if v.Kind == core.VerdictIran {
		win.MessageBox("ClaudeGuard", "Your proxy exits in Iran - not routing Claude Code through it.", win.MB_OK|win.MB_ICONERROR)
		return
	}
	msg, err := core.SetClaudeProxy(s.Proxy.HTTP)
	if err != nil {
		msg = err.Error()
	} else {
		msg += "\n\nKeep v2ray running while you use Claude Code. If v2ray is off, Claude Code can't connect (nothing leaks)."
	}
	win.MessageBox("ClaudeGuard", msg, win.MB_OK|win.MB_ICONINFORMATION)
	t.update()
}

// iranDialog shows "You are in Iran" with Retry (= refresh) / Cancel.
func iranDialog() {
	if !dialogOpen.CompareAndSwap(false, true) {
		return
	}
	defer dialogOpen.Store(false)

	for {
		s := core.LoadStatus()
		if s == nil || !s.InIran || s.State != core.StateBlocked {
			return
		}
		ip := s.IPv4
		if ip == "" {
			ip = s.IPv6
		}
		text := fmt.Sprintf("You are in Iran.\n\n"+
			"Your IP address (%s) is located in Iran, so Claude Code and Claude Desktop "+
			"are blocked and can't connect. Your Iranian IP is not sent to Anthropic.\n\n"+
			"Connect your VPN (TUN, system-proxy or PAC mode), then press Retry to check again.", orDash(ip))
		if s.Proxy != nil && s.Proxy.Detail != "" {
			text += "\n\nSystem proxy: " + s.Proxy.Detail
		}
		if win.MessageBox("ClaudeGuard - You are in Iran", text, win.MB_RETRYCANCEL|win.MB_ICONERROR) != win.IDRETRY {
			return
		}

		asked := core.Now()
		if err := win.SignalEvent(core.RefreshEvent); err != nil {
			win.MessageBox("ClaudeGuard", "The ClaudeGuard service isn't running.", win.MB_OK|win.MB_ICONWARNING)
			return
		}
		r := waitForCheck(asked, 30*time.Second)
		switch {
		case r == nil:
			win.MessageBox("ClaudeGuard", "The check timed out. Claude stays blocked; try Refresh again.", win.MB_OK|win.MB_ICONWARNING)
			return
		case r.State == core.StateAllowed:
			win.MessageBox("ClaudeGuard",
				"You're no longer on an Iranian IP ("+core.CountryName(r.Country)+").\n\n"+
					"Claude Code and Claude Desktop are unblocked.", win.MB_OK|win.MB_ICONINFORMATION)
			return
		case r.State == core.StateProxyOnly:
			text := "Your v2ray proxy exits in " + core.CountryName(r.Proxy.Country) + ".\n\n" +
				"Claude Desktop is unblocked. Direct connections stay blocked."
			if core.ClaudeSettingsProxy() == "" && r.Proxy.HTTP != "" {
				text += "\n\nClaude Code ignores the system proxy. Use \"Route Claude Code through " +
					r.Proxy.HTTP + "\" in the tray menu, then restart Claude Code."
			}
			win.MessageBox("ClaudeGuard", text, win.MB_OK|win.MB_ICONINFORMATION)
			return
		case !r.InIran:
			win.MessageBox("ClaudeGuard", "Claude is still blocked:\n\n"+r.Message, win.MB_OK|win.MB_ICONWARNING)
			return
		}
		// still Iran -> loop and show the dialog again
	}
}

func waitForCheck(asked time.Time, timeout time.Duration) *core.Status {
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); {
		time.Sleep(500 * time.Millisecond)
		if s := core.LoadStatus(); s != nil && s.State != core.StateChecking &&
			s.CheckedAt != nil && !s.CheckedAt.Before(asked) {
			return s
		}
	}
	return nil
}

func showDetails() {
	s := core.LoadStatus()
	if s == nil || s.IsStale() {
		win.MessageBox("ClaudeGuard", "The ClaudeGuard service isn't running, so your location can't be verified.\n\n"+
			"Start the \"ClaudeGuard\" service (services.msc) or reinstall.", win.MB_OK|win.MB_ICONWARNING)
		return
	}
	if s.InIran && s.State == core.StateBlocked {
		iranDialog()
		return
	}
	direct := "Allowed"
	if s.Enforcing {
		direct = "Blocked"
	}
	proxy := "off"
	if s.Proxy != nil {
		proxy = fmt.Sprintf("%s -> %s %s (%s)", s.Proxy.Describe(), core.CountryName(s.Proxy.Country), orDash(s.Proxy.IPv4), s.Proxy.Kind)
		if s.Proxy.PACResult != "" {
			proxy += "\nPAC answer for claude.ai: " + s.Proxy.PACResult
		}
	}
	desktop := "Allowed"
	if s.DesktopBlocked {
		desktop = "Blocked"
	}
	vpn := "-"
	if s.Network != nil {
		vpn = s.Network.Summary()
	}
	for _, a := range s.Apps {
		vpn += "\n" + a.Describe() + "  [" + a.Source + "]"
	}
	text := fmt.Sprintf("%s\n\nVPN: %s\nDirect: %s  IPv4 %s  IPv6 %s  -> %s\nSystem proxy: %s\nClaude Desktop: %s\nClaude Code proxy (settings.json): %s\nChecked: %s",
		s.Message, vpn, core.CountryName(s.Country), orDash(s.IPv4), orDash(s.IPv6), direct, proxy, desktop,
		orDash(core.ClaudeSettingsProxy()), ago(s.CheckedAt))
	icon := uint32(win.MB_ICONINFORMATION)
	if s.State == core.StateBlocked {
		icon = win.MB_ICONWARNING
	}
	win.MessageBox("ClaudeGuard status", text, win.MB_OK|icon)
}

func ago(t *time.Time) string {
	if t == nil {
		return "never"
	}
	d := time.Since(*t).Round(time.Second)
	switch {
	case d < 5*time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	default:
		return t.Local().Format("15:04")
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
