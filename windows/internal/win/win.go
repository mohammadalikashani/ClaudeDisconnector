//go:build windows

// Package win wraps the Windows APIs ClaudeGuard needs.
package win

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"claudeguard/internal/core"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	iphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetTcpTable       = iphlpapi.NewProc("GetTcpTable")
	procSetTcpEntry       = iphlpapi.NewProc("SetTcpEntry")
	procNotifyAddrChange  = iphlpapi.NewProc("NotifyAddrChange")
	procNotifyRouteChange = iphlpapi.NewProc("NotifyRouteChange")
	shell32               = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW   = shell32.NewProc("ShellExecuteExW")
)

func system32(exe string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", exe)
}

// Run executes a program without flashing a console window.
func Run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ---------------------------------------------------------------- refresh event

// CreateRefreshEvent creates the global auto-reset event; any logged-in user may signal it.
func CreateRefreshEvent(name string) (windows.Handle, error) {
	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100002;;;AU)")
	if err != nil {
		return 0, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	n, _ := windows.UTF16PtrFromString(name)
	return windows.CreateEvent(sa, 0, 0, n)
}

func SignalEvent(name string) error {
	n, _ := windows.UTF16PtrFromString(name)
	h, err := windows.OpenEvent(0x0002 /*EVENT_MODIFY_STATE*/, false, n)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.SetEvent(h)
}

// ---------------------------------------------------------------- ACLs

// SecureDir makes dir writable only by SYSTEM/Administrators, readable by Users.
func SecureDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// ---------------------------------------------------------------- hosts + DNS

func HostsPath() string { return filepath.Join(system32(""), "drivers", "etc", "hosts") }

func FlushDNS() { Run(system32("ipconfig.exe"), "/flushdns") }

// ---------------------------------------------------------------- firewall

const FirewallRule = "ClaudeGuard-Block"

func AddFirewallBlock(targets []string) error {
	RemoveFirewallBlock()
	ips := strings.Join(targets, ",")
	for _, dir := range []string{"out", "in"} {
		out, err := Run(system32("netsh.exe"), "advfirewall", "firewall", "add", "rule",
			"name="+FirewallRule, "dir="+dir, "action=block", "remoteip="+ips, "profile=any", "enable=yes")
		if err != nil {
			return fmt.Errorf("netsh add %s rule: %v: %s", dir, err, strings.TrimSpace(out))
		}
	}
	return nil
}

func RemoveFirewallBlock() {
	Run(system32("netsh.exe"), "advfirewall", "firewall", "delete", "rule", "name="+FirewallRule)
}

// FirewallDisabledProfiles lists firewall profiles that are switched off (rules don't apply there).
func FirewallDisabledProfiles() []string {
	var off []string
	for _, p := range []struct{ key, name string }{
		{"DomainProfile", "Domain"}, {"StandardProfile", "Private"}, {"PublicProfile", "Public"},
	} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`+p.key, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := k.GetIntegerValue("EnableFirewall")
		k.Close()
		if err == nil && v == 0 {
			off = append(off, p.name)
		}
	}
	return off
}

// ---------------------------------------------------------------- TCP

type mibTcpRow struct {
	State, LocalAddr, LocalPort, RemoteAddr, RemotePort uint32
}

// KillTCP resets open IPv4 TCP connections to the given networks (needs admin).
func KillTCP(nets []*net.IPNet) int {
	var size uint32
	procGetTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if size == 0 {
		return 0
	}
	buf := make([]byte, size+1024)
	size = uint32(len(buf))
	if r, _, _ := procGetTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0); r != 0 {
		return 0
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	killed := 0
	for i := uint32(0); i < n; i++ {
		off := 4 + i*20
		if int(off+20) > len(buf) {
			break
		}
		row := (*mibTcpRow)(unsafe.Pointer(&buf[off]))
		var ip [4]byte
		binary.LittleEndian.PutUint32(ip[:], row.RemoteAddr)
		remote := net.IP(ip[:])
		for _, nw := range nets {
			if nw.Contains(remote) {
				kill := *row
				kill.State = 12 // MIB_TCP_STATE_DELETE_TCB
				if r, _, _ := procSetTcpEntry.Call(uintptr(unsafe.Pointer(&kill))); r == 0 {
					killed++
				}
				break
			}
		}
	}
	return killed
}

// ---------------------------------------------------------------- network change

// WatchNetwork sends on ch (non-blocking, coalesced) whenever IP addresses or routes change.
func WatchNetwork(ch chan<- struct{}) {
	watch := func(p *windows.LazyProc) {
		for {
			r, _, _ := p.Call(0, 0) // synchronous: blocks until a change
			if r != 0 {
				time.Sleep(5 * time.Second)
				continue
			}
			time.Sleep(700 * time.Millisecond) // let a burst of changes settle
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
	go watch(procNotifyAddrChange)
	go watch(procNotifyRouteChange)
}

// ---------------------------------------------------------------- processes

type proc struct {
	pid  uint32
	name string
	path string
}

func listProcs() []proc {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []proc
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		p := proc{pid: pe.ProcessID, name: windows.UTF16ToString(pe.ExeFile[:])}
		if h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.pid); e == nil {
			buf := make([]uint16, windows.MAX_LONG_PATH)
			n := uint32(len(buf))
			if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
				p.path = windows.UTF16ToString(buf[:n])
			}
			windows.CloseHandle(h)
		}
		out = append(out, p)
	}
	return out
}

func terminate(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1) == nil
}

// KillClaudeDesktop terminates all Claude Desktop processes. Returns how many.
func KillClaudeDesktop() int {
	n := 0
	for _, p := range listProcs() {
		if core.IsClaudeDesktop(p.name, p.path) && terminate(p.pid) {
			n++
		}
	}
	return n
}

// KillByName terminates processes with the given exe name (e.g. the tray app during upgrades).
func KillByName(exe string) {
	self := uint32(os.Getpid())
	for _, p := range listProcs() {
		if p.pid != self && strings.EqualFold(p.name, exe) {
			terminate(p.pid)
		}
	}
}

// ---------------------------------------------------------------- elevation / UI

func IsElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

type shellExecuteInfo struct {
	cbSize         uint32
	fMask          uint32
	hwnd           uintptr
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       uintptr
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      uintptr
	dwHotKey       uint32
	hIconOrMonitor uintptr
	hProcess       windows.Handle
}

// RunElevated starts exe with args via the UAC prompt and waits for it. Returns its exit code.
func RunElevated(exe string, args string) (uint32, error) {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(args)
	info := shellExecuteInfo{
		fMask:        0x40 | 0x100, // SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		nShow:        windows.SW_SHOWNORMAL,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if r, _, err := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		return 1, fmt.Errorf("elevation failed or was cancelled: %v", err)
	}
	if info.hProcess == 0 {
		return 0, nil
	}
	defer windows.CloseHandle(info.hProcess)
	windows.WaitForSingleObject(info.hProcess, windows.INFINITE)
	var code uint32
	windows.GetExitCodeProcess(info.hProcess, &code)
	return code, nil
}

// StartAsShellUser launches a program as the normal (non-elevated) desktop user.
func StartAsShellUser(exe string) error {
	return exec.Command(filepath.Join(os.Getenv("SystemRoot"), "explorer.exe"), exe).Start()
}

const (
	MB_OK              = 0x00000000
	MB_RETRYCANCEL     = 0x00000005
	MB_YESNO           = 0x00000004
	MB_ICONERROR       = 0x00000010
	MB_ICONWARNING     = 0x00000030
	MB_ICONINFORMATION = 0x00000040
	MB_SETFOREGROUND   = 0x00010000
	MB_TOPMOST         = 0x00040000
	IDRETRY            = 4
	IDYES              = 6
)

func MessageBox(title, text string, flags uint32) int {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString(title)
	r, _ := windows.MessageBox(0, t, c, flags|MB_SETFOREGROUND|MB_TOPMOST)
	return int(r)
}

// SingleInstance returns false if another process already holds the named mutex.
func SingleInstance(name string) bool {
	n, _ := windows.UTF16PtrFromString(name)
	_, err := windows.CreateMutex(nil, false, n)
	return err != windows.ERROR_ALREADY_EXISTS
}

// ---------------------------------------------------------------- system proxy

const internetSettings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// SystemProxy reads the logged-in console user's WinINET proxy (what v2rayN sets in
// "system proxy" mode). The service runs as SYSTEM, so it reads HKEY_USERS\<user SID>.
func SystemProxy() core.SystemProxy {
	root, path := registry.CURRENT_USER, internetSettings
	if sid := consoleUserSID(); sid != "" {
		root, path = registry.USERS, sid+`\`+internetSettings
	}
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return core.SystemProxy{}
	}
	defer k.Close()
	var p core.SystemProxy
	if en, _, err := k.GetIntegerValue("ProxyEnable"); err == nil && en == 1 {
		if s, _, err := k.GetStringValue("ProxyServer"); err == nil {
			p = core.ParseWinProxyServer(s)
		}
	}
	if pac, _, err := k.GetStringValue("AutoConfigURL"); err == nil && pac != "" {
		p.PAC = pac
	}
	return p
}

func consoleUserSID() string {
	sess := windows.WTSGetActiveConsoleSessionId()
	if sess == 0xFFFFFFFF {
		return ""
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(sess, &tok); err != nil {
		return "" // not SYSTEM (e.g. foreground debug run) -> caller falls back to HKCU
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	return u.User.Sid.String()
}
