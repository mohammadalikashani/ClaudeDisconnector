package core

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func lanIPv4() string {
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLinkLocalUnicast() {
				return n.IP.String()
			}
		}
	}
	return ""
}

// Clash Meta for Android used as the computer's proxy (Allow LAN), API on the LAN.
func TestRemoteCMFA(t *testing.T) {
	ip := lanIPv4()
	if ip == "" {
		t.Skip("no LAN address")
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Skip(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer phone" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/version":
			w.Write([]byte(`{"meta":true,"version":"alpha-cmfa"}`))
		case "/configs":
			w.Write([]byte(`{"mode":"rule","mixed-port":7890,"allow-lan":true,"tun":{"enable":true}}`))
		case "/proxies":
			w.Write([]byte(`{"proxies":{"Proxy":{"type":"Selector","now":"de-1"},"de-1":{"type":"Vless"}}}`))
		case "/rules":
			w.Write([]byte(`{"rules":[{"type":"GeoSite","payload":"google","proxy":"Proxy"},{"type":"Match","payload":"","proxy":"DIRECT"}]}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// Configured with its secret (the default 9090/9097 probes answer nothing here).
	sysProxy := "http://" + ip + ":7890"
	cands := RemoteAPICandidates([]string{sysProxy, "http://127.0.0.1:10809"}, []RemoteAPI{{Addr: ip + ":" + port, Secret: "phone"}})
	if len(cands) != 3 || cands[0].Path != ip+":"+port || cands[1].Path != ip+":9090" {
		t.Fatalf("candidates: %+v", cands)
	}
	start := time.Now()
	apps := DetectProxyApps(t.Context(), cands[:1], func(string) bool { return false })
	if len(apps) != 1 {
		t.Fatalf("apps: %+v", apps)
	}
	a := apps[0]
	if a.Remote != ip || a.TUN || a.Name() != "Clash on "+ip || !a.SendsClaudeDirect() {
		t.Fatalf("remote app: %+v", a)
	}
	if !a.ServesPort(sysProxy) || a.ServesPort("http://127.0.0.1:7890") {
		t.Error("remote app must serve only its own host's port")
	}
	d := DecideApps(apps, true, sysProxy)
	if d.ProxyDirect == nil || d.TUNDirect != nil {
		t.Errorf("decide: %+v", d)
	}
	t.Logf("%s (%v)", a.Describe(), time.Since(start))

	// Claude Code's HTTPS_PROXY is the phone: blocked even though this computer is "allowed".
	st := &Status{State: StateAllowed, UpdatedAt: time.Now(), Apps: []ProxyApp{a}}
	allow, msg := RunHook(HookDeps{Load: func() *Status { return st }, Refresh: func() error { return nil },
		CheckVia: func(string) Verdict { return Verdict{Kind: VerdictAllowed, Country: "DE"} },
		Getenv:   func(k string) string { return map[string]string{"HTTPS_PROXY": sysProxy}[k] }, Wait: time.Millisecond})
	if allow || !strings.Contains(msg, ip+"'s own internet connection") {
		t.Errorf("hook: allow=%v msg=%s", allow, msg)
	}
}

func TestLocalAppServesOnlyLocal(t *testing.T) {
	a := ProxyApp{Kind: "clash", Ports: []int{7890}}
	if !a.ServesPort("127.0.0.1:7890") || !a.ServesPort("http://localhost:7890") || a.ServesPort("http://192.168.1.5:7890") {
		t.Error("local ServesPort")
	}
}

func TestRemoteAPICommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "remote-apis.txt")
	if _, err := RemoteAPICommand([]string{"add", "192.168.1.5:9090", "s3"}, path); err != nil {
		t.Fatal(err)
	}
	if _, err := RemoteAPICommand([]string{"add", "nonsense"}, path); err == nil {
		t.Error("bad address accepted")
	}
	l := LoadRemoteAPIs(path)
	if len(l) != 1 || l[0].Secret != "s3" {
		t.Fatalf("saved: %+v", l)
	}
	out, _ := RemoteAPICommand(nil, path)
	if !strings.Contains(out, "192.168.1.5:9090  (with secret)") || strings.Contains(out, "s3") {
		t.Errorf("list must not print the secret: %q", out)
	}
	RemoteAPICommand([]string{"remove", "192.168.1.5:9090"}, path)
	if len(LoadRemoteAPIs(path)) != 0 {
		t.Error("remove")
	}
}
