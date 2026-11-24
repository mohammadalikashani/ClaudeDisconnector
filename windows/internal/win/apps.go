//go:build windows

package win

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"claudeguard/internal/core"
)

// UserDirs returns the logged-in console user's profile folder and Roaming AppData
// (the service runs as SYSTEM, so its own %USERPROFILE% is the wrong one).
func UserDirs() (home, appData string) {
	home, appData, _ = UserDirs3()
	return
}

// UserDirs3 also returns Local AppData.
func UserDirs3() (home, appData, localAppData string) {
	if sid := consoleUserSID(); sid != "" {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid, registry.QUERY_VALUE)
		if err == nil {
			defer k.Close()
			if p, _, err := k.GetStringValue("ProfileImagePath"); err == nil {
				if exp, err := registry.ExpandString(p); err == nil {
					p = exp
				}
				return p, filepath.Join(p, "AppData", "Roaming"), filepath.Join(p, "AppData", "Local")
			}
		}
	}
	return os.Getenv("USERPROFILE"), os.Getenv("APPDATA"), os.Getenv("LOCALAPPDATA")
}

// ProxyProcesses finds running Clash / sing-box / Xray / V2Ray style apps, the
// folders of their executables (v2rayN keeps its generated core config in
// <dir>\binConfigs or <dir>\guiConfigs) and the config files their command lines name.
func ProxyProcesses() core.ProcInfo {
	info := core.ProcInfo{Running: map[string]bool{}}
	seen := map[string]bool{}
	addDir := func(d string) {
		if !seen[d] {
			seen[d] = true
			info.Dirs = append(info.Dirs, d)
		}
	}
	for _, p := range listProcs() {
		n := strings.ToLower(strings.TrimSuffix(strings.ToLower(p.name), ".exe"))
		kind := core.ProcKind(p.name)
		if kind == "" && n != "v2rayn" && !strings.Contains(n, "hiddify") {
			continue
		}
		if kind != "" {
			info.Running[kind] = true
		}
		if p.path == "" {
			continue
		}
		d := filepath.Dir(p.path)
		// cores often live in <app>\bin\ or <app>\bin\xray\
		bases := []string{d, filepath.Dir(d), filepath.Dir(filepath.Dir(d))}
		for _, dd := range bases[:2] {
			addDir(dd)
		}
		if kind == "" || kind == "nekoray" {
			continue // GUIs: no config on their command line
		}
		if args := commandLine(p.pid); len(args) > 1 {
			// Relative config paths: the cwd of another process isn't readable cheaply,
			// so try the exe folder, its parents and v2rayN's config folders.
			var tries []string
			for _, b := range bases {
				tries = append(tries, b, filepath.Join(b, "binConfigs"), filepath.Join(b, "guiConfigs"))
			}
			info.Configs = append(info.Configs, core.ConfigArgs(kind, args, tries)...)
		}
	}
	return info
}

// commandLine returns another process's argv (needs PROCESS_QUERY_LIMITED_INFORMATION).
func commandLine(pid uint32) []string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)
	var need uint32
	_ = windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, nil, 0, &need)
	if need == 0 || need > 1<<20 {
		return nil
	}
	buf := make([]byte, need)
	if windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), need, &need) != nil {
		return nil
	}
	us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	args, err := windows.DecomposeCommandLine(us.String())
	if err != nil {
		return nil
	}
	return args
}
