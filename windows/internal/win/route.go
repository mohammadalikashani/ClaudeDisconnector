//go:build windows

package win

import (
	"net"
	"unsafe"

	"claudeguard/internal/core"

	"golang.org/x/sys/windows"
)

type adapter struct {
	index   uint32
	name    string // friendly name, e.g. "Wi-Fi", "v2rayN"
	desc    string // e.g. "Wintun Userspace Tunnel"
	typ     uint32
	ipv4    net.IP
	gateway bool
	up      bool
	metric  uint32
}

func adapters() map[uint32]adapter {
	out := map[uint32]adapter{}
	size := uint32(16 << 10)
	for i := 0; i < 3; i++ {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|
			windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER|0x80, /*INCLUDE_GATEWAYS*/ 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return out
		}
		for a := aa; a != nil; a = a.Next {
			ad := adapter{index: a.IfIndex, name: windows.UTF16PtrToString(a.FriendlyName),
				desc: windows.UTF16PtrToString(a.Description), typ: a.IfType,
				gateway: a.FirstGatewayAddress != nil, up: a.OperStatus == windows.IfOperStatusUp, metric: a.Ipv4Metric}
			for u := a.FirstUnicastAddress; u != nil; u = u.Next {
				if ip := u.Address.IP(); ip != nil && ip.To4() != nil && !ip.IsLinkLocalUnicast() {
					ad.ipv4 = ip.To4()
					break
				}
			}
			out[a.IfIndex] = ad
		}
		return out
	}
	return out
}

func routeIndex(ip net.IP) (uint32, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	sa := &windows.SockaddrInet4{}
	copy(sa.Addr[:], ip4)
	var idx uint32
	if err := windows.GetBestInterfaceEx(sa, &idx); err != nil {
		return 0, false
	}
	return idx, true
}

// NetInfo finds which interfaces carry Anthropic's traffic and the IP-check traffic.
// It also returns the IPv4 address of Anthropic's interface (for a bound check).
func NetInfo() (core.NetInfo, net.IP) {
	var n core.NetInfo
	ads := adapters()

	checkIP := net.ParseIP("1.1.1.1")
	if ips, err := net.LookupIP(core.CheckProbeHost); err == nil {
		for _, ip := range ips {
			if ip.To4() != nil {
				checkIP = ip // may be a TUN "fake-ip" (198.18.x.x): that's the real path too
				break
			}
		}
	}
	var anthropicLocal net.IP
	if idx, ok := routeIndex(checkIP); ok {
		a := ads[idx]
		n.CheckIface, n.CheckIsTunnel = a.name, core.IsTunnelAdapter(a.name, a.desc, a.typ)
		if n.CheckIsTunnel {
			n.TunnelName = a.name + " (" + a.desc + ")"
		}
	}
	if idx, ok := routeIndex(net.ParseIP(core.AnthropicProbeIP)); ok {
		a := ads[idx]
		n.AnthropicIface, n.AnthropicIsTunnel = a.name, core.IsTunnelAdapter(a.name, a.desc, a.typ)
		anthropicLocal = a.ipv4
		if n.AnthropicIsTunnel {
			n.TunnelName = a.name + " (" + a.desc + ")"
		}
	}
	return n, anthropicLocal
}

// PhysicalIPv4 is the IPv4 address of the best physical (non-tunnel) adapter with a
// gateway - the connection your real IP comes from, underneath any VPN.
func PhysicalIPv4() (net.IP, string) {
	var best *adapter
	for _, a := range adapters() {
		a := a
		if !a.up || !a.gateway || a.ipv4 == nil || core.IsTunnelAdapter(a.name, a.desc, a.typ) {
			continue
		}
		if best == nil || a.metric < best.metric {
			best = &a
		}
	}
	if best == nil {
		return nil, ""
	}
	return best.ipv4, best.name
}
