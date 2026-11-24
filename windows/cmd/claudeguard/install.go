//go:build windows

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"claudeguard/internal/core"
	"claudeguard/internal/win"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	trayExe = "ClaudeGuardTray.exe"
	mainExe = "claudeguard.exe"
	runKey  = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
)

func installDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "ClaudeGuard")
}

func confirm(q string) bool {
	fmt.Print(q + " [y/N] ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

func fail(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, "ERROR: "+msg)
	if os.Getenv("CLAUDEGUARD_GUI_ERRORS") != "" {
		win.MessageBox("ClaudeGuard setup", msg, win.MB_OK|win.MB_ICONERROR)
	}
	os.Exit(1)
}

// ------------------------------------------------------------------ install

func cmdInstall(args []string) {
	self, _ := os.Executable()
	srcDir := filepath.Dir(self)
	if _, err := os.Stat(filepath.Join(srcDir, trayExe)); err != nil {
		fail("%s must be in the same folder as %s", trayExe, mainExe)
	}

	fmt.Println("==> Current location check")
	runCheck()
	fmt.Println()
	fmt.Println("NOTE: Protection starts in BLOCKED mode and unblocks after the check (a few seconds).")
	fmt.Println("      If you are on an Iranian IP right now, Claude (including open Claude Code sessions) will be cut off.")
	if !contains(args, "--yes") && !confirm("Continue?") {
		os.Exit(1)
	}

	// Per-user part (runs as you, so it edits YOUR ~/.claude/settings.json).
	if msg, err := core.InstallHook(); err != nil {
		fmt.Println("WARN could not add Claude Code hook:", err)
	} else {
		fmt.Println("==> " + msg)
	}

	// Machine part (needs admin).
	if win.IsElevated() {
		installSystem(srcDir)
	} else {
		fmt.Println("==> Installing service (approve the Windows admin prompt)")
		code, err := win.RunElevated(self, "install-system")
		if err != nil {
			fail("%v", err)
		}
		if code != 0 {
			fail("service install failed (exit %d); see %s", code, core.LogFile())
		}
	}

	tray := filepath.Join(installDir(), trayExe)
	if win.IsElevated() {
		_ = win.StartAsShellUser(tray)
	} else {
		_ = exec.Command(tray).Start()
	}

	fmt.Println("==> Waiting for first check...")
	for i := 0; i < 20; i++ {
		time.Sleep(time.Second)
		if s := core.LoadStatus(); s != nil && s.State != core.StateChecking {
			break
		}
	}
	runStatus()
	fmt.Printf("\nDone. Look for the shield icon in the system tray (it may be under the ^ arrow).\n")
	fmt.Printf("CLI: \"%s\" status|check|refresh   Log: %s\n", filepath.Join(installDir(), mainExe), core.LogFile())
}

// installSystem runs elevated: copies binaries, (re)creates the service, autostarts the tray.
func installSystem(srcDir string) {
	m, err := mgr.Connect()
	if err != nil {
		fail("service manager: %v", err)
	}
	defer m.Disconnect()

	// Stop old service / tray so files can be replaced.
	if s, err := m.OpenService(core.ServiceName); err == nil {
		stopService(s)
		s.Close()
	}
	win.KillByName(trayExe)

	dst := installDir()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		fail("create %s: %v", dst, err)
	}
	for _, f := range []string{mainExe, trayExe} {
		if err := copyFile(filepath.Join(srcDir, f), filepath.Join(dst, f)); err != nil {
			fail("copy %s: %v", f, err)
		}
	}
	_ = os.MkdirAll(core.DataDir(), 0o755)
	_ = win.SecureDir(core.DataDir())

	exe := filepath.Join(dst, mainExe)
	cfg := mgr.Config{
		DisplayName: "ClaudeGuard",
		Description: "Blocks Claude Code / Claude Desktop while your public IP is in Iran.",
		StartType:   mgr.StartAutomatic,
	}
	s, err := m.OpenService(core.ServiceName)
	if err == nil {
		cur, _ := s.Config()
		cur.BinaryPathName = `"` + exe + `" service`
		cur.StartType = mgr.StartAutomatic
		cur.DisplayName, cur.Description = cfg.DisplayName, cfg.Description
		if err := s.UpdateConfig(cur); err != nil {
			fail("update service: %v", err)
		}
	} else {
		s, err = m.CreateService(core.ServiceName, exe, cfg, "service")
		if err != nil {
			fail("create service: %v", err)
		}
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400)

	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE); err == nil {
		_ = k.SetStringValue("ClaudeGuard", `"`+filepath.Join(dst, trayExe)+`"`)
		k.Close()
	}

	if err := s.Start("service"); err != nil {
		fail("start service: %v", err)
	}
	fmt.Println("==> Service installed and started")
}

// ------------------------------------------------------------------ uninstall

func cmdUninstall(args []string) {
	if msg, err := core.UninstallHook(); err != nil {
		fmt.Println("WARN:", err)
	} else {
		fmt.Println("==> " + msg)
	}
	win.KillByName(trayExe)

	self, _ := os.Executable()
	if win.IsElevated() {
		uninstallSystem()
	} else {
		fmt.Println("==> Removing service and blocks (approve the Windows admin prompt)")
		code, err := win.RunElevated(self, "uninstall-system")
		if err != nil {
			fail("%v", err)
		}
		if code != 0 {
			fail("uninstall failed (exit %d)", code)
		}
	}
	fmt.Println("ClaudeGuard uninstalled.")
}

func uninstallSystem() {
	if m, err := mgr.Connect(); err == nil {
		if s, err := m.OpenService(core.ServiceName); err == nil {
			stopService(s)
			if err := s.Delete(); err != nil {
				fmt.Println("WARN delete service:", err)
			}
			s.Close()
		}
		m.Disconnect()
	}
	(&Enforcer{}).Unblock(true)
	win.KillByName(trayExe)
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue("ClaudeGuard")
		k.Close()
	}
	_ = os.RemoveAll(core.DataDir())

	// We may be running from the install dir: delete it after we exit.
	dir := installDir()
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/c",
		`ping -n 3 127.0.0.1 >nul & rmdir /s /q "`+dir+`"`)
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	_ = cmd.Start()
	fmt.Println("==> Service removed, hosts entries and firewall rule deleted")
}

// ------------------------------------------------------------------ helpers

func stopService(s *mgr.Service) {
	st, err := s.Control(svc.Stop)
	if err != nil {
		return
	}
	deadline := time.Now().Add(15 * time.Second)
	for st.State != svc.Stopped && time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return
		}
	}
}

func copyFile(src, dst string) error {
	if strings.EqualFold(filepath.Clean(src), filepath.Clean(dst)) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	var out *os.File
	for i := 0; i < 10; i++ { // the old process may take a moment to release the file
		if out, err = os.Create(dst); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
