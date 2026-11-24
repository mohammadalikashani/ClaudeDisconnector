package core

import (
	"bufio"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Remote Clash: a proxy app on ANOTHER device that this computer uses as its proxy -
// typically Clash Meta for Android (CMFA) with "Allow LAN", the computer's system proxy
// / PAC / HTTPS_PROXY pointing at the phone (192.168.x.x:7890). Its files are in the
// app's private storage (unreadable from here), but its Clash API can be enabled on the
// LAN (CMFA: Override > External controller 0.0.0.0:9090, optional secret). If it sends
// Claude DIRECT, Claude leaves through the PHONE's own connection, which ClaudeGuard
// can't check from this computer, so that is treated as unverifiable (blocked).

// DefaultRemoteAPIPorts are tried on a remote proxy host.
var DefaultRemoteAPIPorts = []string{"9090", "9097"}

// RemoteAPIsFile lists extra controllers: one "host:port [secret]" per line.
func RemoteAPIsFile() string { return filepath.Join(DataDir(), "remote-apis.txt") }

// RemoteAPI is a configured remote controller.
type RemoteAPI struct{ Addr, Secret string }

func LoadRemoteAPIs(path string) []RemoteAPI {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []RemoteAPI
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		r := RemoteAPI{Addr: strings.TrimPrefix(strings.TrimPrefix(parts[0], "http://"), "https://")}
		if len(parts) > 1 {
			r.Secret = parts[1]
		}
		out = append(out, r)
	}
	return out
}

// SaveRemoteAPIs writes the list (used by the CLI).
func SaveRemoteAPIs(path string, list []RemoteAPI) error {
	var b strings.Builder
	b.WriteString("# Remote Clash APIs (e.g. Clash Meta for Android with Allow LAN): host:port [secret]\n")
	for _, r := range list {
		b.WriteString(r.Addr)
		if r.Secret != "" {
			b.WriteString(" " + r.Secret)
		}
		b.WriteString("\n")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

// ProxyHostPort splits a proxy URL ("http://192.168.1.5:7890", "socks5://[::1]:1080",
// "192.168.1.5:7890") into host and port.
func ProxyHostPort(proxyURL string) (host, port string) {
	u, err := url.Parse(NormalizeProxyURL(proxyURL))
	if err != nil {
		return "", ""
	}
	return strings.ToLower(u.Hostname()), u.Port()
}

// RemoteAPICandidates: the Clash API candidates for every non-local proxy host in
// proxies (system proxy, PAC answer, Claude Code's proxy), plus configured ones.
func RemoteAPICandidates(proxies []string, configured []RemoteAPI) []ConfigCandidate {
	var out []ConfigCandidate
	seen := map[string]bool{}
	add := func(addr, secret string) {
		if !seen[addr] {
			seen[addr] = true
			host, _, _ := net.SplitHostPort(addr)
			out = append(out, ConfigCandidate{Kind: "api", Path: addr, App: "Clash on " + host, API: APIOverride{Secret: secret}})
		}
	}
	for _, r := range configured {
		add(r.Addr, r.Secret)
	}
	for _, p := range proxies {
		host, _ := ProxyHostPort(p)
		if host == "" || isLocalAddr(host) {
			continue
		}
		for _, port := range DefaultRemoteAPIPorts {
			add(net.JoinHostPort(host, port), "")
		}
	}
	return out
}

// ClaudeSettingsProxyIn reads env.HTTPS_PROXY / HTTP_PROXY from <home>/.claude/settings.json.
func ClaudeSettingsProxyIn(home string) string {
	data, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		return ""
	}
	var s struct {
		Env map[string]string `json:"env"`
	}
	if json.Unmarshal(data, &s) != nil {
		return ""
	}
	return ClaudeCodeProxy(func(k string) string { return s.Env[k] })
}

// RemoteAPICommand implements "claudeguard remote-api list | add <host:port> [secret] | remove <host:port>".
func RemoteAPICommand(args []string, path string) (string, error) {
	list := LoadRemoteAPIs(path)
	cmd := "list"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "list":
		if len(list) == 0 {
			return "no remote Clash APIs configured (proxy hosts are still probed on ports 9090 / 9097)\n", nil
		}
		var b strings.Builder
		for _, r := range list {
			b.WriteString(r.Addr)
			if r.Secret != "" {
				b.WriteString("  (with secret)")
			}
			b.WriteString("\n")
		}
		return b.String(), nil
	case "add":
		if len(args) < 2 {
			return "", errUsage
		}
		addr := strings.TrimPrefix(strings.TrimPrefix(args[1], "http://"), "https://")
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return "", errUsage
		}
		r := RemoteAPI{Addr: addr}
		if len(args) > 2 {
			r.Secret = args[2]
		}
		var out []RemoteAPI
		for _, x := range list {
			if x.Addr != addr {
				out = append(out, x)
			}
		}
		if err := SaveRemoteAPIs(path, append(out, r)); err != nil {
			return "", err
		}
		return "added " + addr + " - click Refresh (or run refresh) to check it\n", nil
	case "remove":
		if len(args) < 2 {
			return "", errUsage
		}
		var out []RemoteAPI
		for _, x := range list {
			if x.Addr != args[1] {
				out = append(out, x)
			}
		}
		if err := SaveRemoteAPIs(path, out); err != nil {
			return "", err
		}
		return "removed " + args[1] + "\n", nil
	}
	return "", errUsage
}

var errUsage = errorString("usage: remote-api list | add <host:port> [secret] | remove <host:port>")

type errorString string

func (e errorString) Error() string { return string(e) }
