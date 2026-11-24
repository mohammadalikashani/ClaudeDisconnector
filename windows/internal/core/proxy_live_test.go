package core

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
)

// A minimal HTTP CONNECT proxy, like v2ray's HTTP inbound.
func connectProxy(t *testing.T, tunnels *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", 405)
			return
		}
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		atomic.AddInt32(tunnels, 1)
		w.WriteHeader(200)
		conn, _, _ := w.(http.Hijacker).Hijack()
		go func() { io.Copy(up, conn); up.Close() }()
		go func() { io.Copy(conn, up); conn.Close() }()
	}))
}

// CLAUDEGUARD_NET=1 go test ./internal/core -run LiveProxy -v
func TestLiveProxyRoute(t *testing.T) {
	if os.Getenv("CLAUDEGUARD_NET") == "" {
		t.Skip("set CLAUDEGUARD_NET=1")
	}
	var tunnels int32
	px := connectProxy(t, &tunnels)
	defer px.Close()

	c := NewChecker()
	v := c.CheckVia(context.Background(), px.URL)
	t.Logf("via proxy %s: %+v (tunnels=%d)", px.URL, v, tunnels)
	if v.Kind != VerdictAllowed || atomic.LoadInt32(&tunnels) == 0 {
		t.Fatalf("proxy route not used or failed")
	}

	before := atomic.LoadInt32(&tunnels)
	c.ClearCache()
	d := c.Check(context.Background())
	if atomic.LoadInt32(&tunnels) != before {
		t.Fatalf("direct check went through the proxy")
	}
	t.Logf("direct: %+v", d)

	dead := c.CheckVia(context.Background(), "http://127.0.0.1:1")
	if dead.Kind != VerdictUnknown {
		t.Fatalf("dead proxy should be unknown, got %+v", dead)
	}
	t.Logf("dead proxy: %s", dead.Detail)
}

// PAC end-to-end: PAC file -> route for claude.ai -> exit-IP check through that proxy.
func TestLivePACRoute(t *testing.T) {
	if os.Getenv("CLAUDEGUARD_NET") == "" {
		t.Skip("set CLAUDEGUARD_NET=1")
	}
	var tunnels int32
	px := connectProxy(t, &tunnels)
	defer px.Close()
	addr := px.Listener.Addr().String()
	// The PAC proxies only Anthropic and sends everything else (incl. IP-check sites) DIRECT,
	// so the check must be forced through the PAC's proxy to see Claude's real exit.
	pac := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`function FindProxyForURL(u, h) {
		  if (dnsDomainIs(h, "claude.ai") || dnsDomainIs(h, ".anthropic.com")) return "PROXY ` + addr + `; DIRECT";
		  return "DIRECT"; }`))
	}))
	defer pac.Close()

	ctx := context.Background()
	rt := ResolveDesktopRoute(ctx, SystemProxy{PAC: pac.URL + "/pac"})
	if rt.Proxy != "http://"+addr {
		t.Fatalf("route: %+v", rt)
	}
	v := NewChecker().CheckVia(ctx, rt.Proxy)
	t.Logf("PAC %q -> %s -> %+v (tunnels=%d)", rt.PACResult, rt.Proxy, v, atomic.LoadInt32(&tunnels))
	if v.Kind != VerdictAllowed || atomic.LoadInt32(&tunnels) == 0 {
		t.Fatal("PAC route not checked through its proxy")
	}
}

// Bound check: pin the check to this machine's primary interface address.
func TestLiveBoundCheck(t *testing.T) {
	if os.Getenv("CLAUDEGUARD_NET") == "" {
		t.Skip("set CLAUDEGUARD_NET=1")
	}
	c, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		t.Skip(err)
	}
	local := c.LocalAddr().(*net.UDPAddr).IP
	c.Close()
	v := NewChecker().CheckBound(context.Background(), local)
	t.Logf("bound to %s: %+v", local, v)
	if v.Kind != VerdictAllowed || v.IPv4 == "" {
		t.Fatal("bound check failed")
	}
}
