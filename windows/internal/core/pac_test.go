package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Shaped like the PAC files v2rayN / V2rayU generate: a domain table + suffix walk.
const v2rayPAC = `
var proxy = "PROXY 127.0.0.1:10809; SOCKS5 127.0.0.1:10808; DIRECT;";
var direct = "DIRECT;";
var domains = { "google.com": 1, "anthropic.com": 1, "claude.ai": 1, "openai.com": 1 };
var hasOwnProperty = Object.hasOwnProperty;
function FindProxyForURL(url, host) {
  var suffix; var pos = host.lastIndexOf('.'); pos = host.lastIndexOf('.', pos - 1);
  while (1) {
    if (pos <= 0) { if (hasOwnProperty.call(domains, host)) return proxy; else return direct; }
    suffix = host.substring(pos + 1);
    if (hasOwnProperty.call(domains, suffix)) return proxy;
    pos = host.lastIndexOf('.', pos - 1);
  }
}`

// A "bypass Iran / proxy the rest" style PAC using the helper functions.
const helperPAC = `
function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || shExpMatch(host, "*.ir") || dnsDomainIs(host, ".local")) return "DIRECT";
  if (isInNet("10.1.2.3", "10.0.0.0", "255.0.0.0") && localHostOrDomainIs("www", "www.x.com") && dnsDomainLevels("a.b.c") == 2)
    return "PROXY 127.0.0.1:2080";
  return "DIRECT";
}`

func TestParsePACResult(t *testing.T) {
	got := ParsePACResult("PROXY 127.0.0.1:10809; SOCKS5 127.0.0.1:10808; DIRECT;")
	want := []string{"http://127.0.0.1:10809", "socks5://127.0.0.1:10808", ""}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("%q", got)
	}
	if g := ParsePACResult(""); len(g) != 1 || g[0] != "" {
		t.Errorf("empty -> DIRECT, got %q", g)
	}
	if g := ParsePACResult("SOCKS 1.2.3.4:1080"); g[0] != "socks5://1.2.3.4:1080" {
		t.Errorf("%q", g)
	}
}

func TestEvalPAC(t *testing.T) {
	for host, want := range map[string]string{"claude.ai": "PROXY", "api.anthropic.com": "PROXY", "example.ir": "DIRECT"} {
		got, err := EvalPAC(v2rayPAC, "https://"+host+"/", host)
		if err != nil || !strings.HasPrefix(got, want) {
			t.Errorf("v2ray PAC %s = %q, %v", host, got, err)
		}
	}
	if got, err := EvalPAC(helperPAC, "https://claude.ai/", "claude.ai"); err != nil || got != "PROXY 127.0.0.1:2080" {
		t.Errorf("helper PAC = %q, %v", got, err)
	}
	if got, _ := EvalPAC(helperPAC, "https://x.ir/", "x.ir"); got != "DIRECT" {
		t.Errorf("shExpMatch *.ir = %q", got)
	}
	if _, err := EvalPAC(`function FindProxyForURL(u,h){ while(true){} }`, "https://claude.ai/", "claude.ai"); err == nil {
		t.Error("infinite loop should time out")
	}
	if _, err := EvalPAC(`syntax error (`, "https://claude.ai/", "claude.ai"); err == nil {
		t.Error("syntax error should fail")
	}
}

func TestResolveDesktopRoute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Write([]byte(v2rayPAC))
	}))
	defer srv.Close()
	ctx := context.Background()

	r := ResolveDesktopRoute(ctx, SystemProxy{PAC: srv.URL + "/pac/?t=123", HTTP: "http://ignored:1"})
	if r.Mode != "pac" || r.Proxy != "http://127.0.0.1:10809" || r.HTTP != "http://127.0.0.1:10809" || r.Note != "" {
		t.Errorf("pac route: %+v", r)
	}

	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`function FindProxyForURL(u,h){ return h == "claude.ai" ? "PROXY 1.1.1.1:8080" : "DIRECT"; }`))
	}))
	defer direct.Close()
	if r := ResolveDesktopRoute(ctx, SystemProxy{PAC: direct.URL}); r.Proxy != "" {
		t.Errorf("mixed answers should resolve to DIRECT: %+v", r)
	}

	if r := ResolveDesktopRoute(ctx, SystemProxy{PAC: "http://127.0.0.1:1/pac"}); r.Proxy != "" || !strings.Contains(r.Note, "DIRECT") {
		t.Errorf("unreachable PAC: %+v", r)
	}

	f := filepath.Join(t.TempDir(), "proxy.pac")
	os.WriteFile(f, []byte(v2rayPAC), 0o644)
	if r := ResolveDesktopRoute(ctx, SystemProxy{PAC: "file://" + f}); r.Proxy != "http://127.0.0.1:10809" {
		t.Errorf("file PAC: %+v", r)
	}

	if r := ResolveDesktopRoute(ctx, SystemProxy{HTTP: "http://127.0.0.1:10809", SOCKS: "socks5://x:1"}); r.Mode != "manual" || r.Proxy != "http://127.0.0.1:10809" {
		t.Errorf("manual: %+v", r)
	}
}
