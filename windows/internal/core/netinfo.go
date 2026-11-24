package core

import "strings"

// AnthropicProbeIP is api.anthropic.com / claude.ai. Only its ROUTE is looked up;
// nothing is ever sent to it.
const AnthropicProbeIP = "160.79.104.10"

// CheckProbeHost is the IP-check site whose route is compared with Anthropic's.
const CheckProbeHost = "api4.ipify.org"

// NetInfo describes which network interfaces traffic takes, to detect TUN-mode VPNs
// (v2rayN/sing-box/Clash TUN, WireGuard, OpenVPN...) and Anthropic traffic that
// bypasses the tunnel.
type NetInfo struct {
	CheckIface        string `json:"checkIface,omitempty"` // interface the IP-check sites are reached through
	CheckIsTunnel     bool   `json:"checkIsTunnel,omitempty"`
	AnthropicIface    string `json:"anthropicIface,omitempty"` // interface Anthropic's IPs are routed through
	AnthropicIsTunnel bool   `json:"anthropicIsTunnel,omitempty"`
	TunnelName        string `json:"tunnelName,omitempty"` // friendly name/description of the active tunnel
	// Bound: the direct check was pinned to AnthropicIface because Anthropic bypasses the tunnel.
	Bound bool `json:"bound,omitempty"`
}

// TunnelActive reports whether a TUN/VPN interface carries the default or Anthropic traffic.
func (n NetInfo) TunnelActive() bool { return n.CheckIsTunnel || n.AnthropicIsTunnel }

// AnthropicBypassesCheck reports whether Anthropic traffic leaves through a different
// interface than the IP-check sites (so a plain check would see the wrong exit IP).
func (n NetInfo) AnthropicBypassesCheck() bool {
	return n.CheckIface != "" && n.AnthropicIface != "" && n.CheckIface != n.AnthropicIface
}

// Summary is a one-line description for the UI.
func (n NetInfo) Summary() string {
	name := n.TunnelName
	switch {
	case n.AnthropicBypassesCheck() && n.CheckIsTunnel && !n.AnthropicIsTunnel:
		return "TUN VPN " + name + " is on, but Anthropic traffic BYPASSES it (goes via " + n.AnthropicIface + ")"
	case n.AnthropicBypassesCheck():
		return "Anthropic traffic goes via " + n.AnthropicIface + ", other traffic via " + n.CheckIface
	case n.TunnelActive():
		return "TUN VPN on: " + name
	case n.CheckIface != "":
		return "No TUN VPN (traffic goes via " + n.CheckIface + ")"
	}
	return "unknown"
}

// IsTunnelAdapter classifies a Windows adapter. ifType: IF_TYPE_PPP=23,
// IF_TYPE_PROP_VIRTUAL=53 (Wintun, TAP), IF_TYPE_TUNNEL=131.
func IsTunnelAdapter(name, desc string, ifType uint32) bool {
	if ifType == 23 || ifType == 53 || ifType == 131 {
		return true
	}
	s := strings.ToLower(name + " " + desc)
	for _, kw := range []string{"wintun", "tap-windows", "tap adapter", "wireguard", "sing-tun", "sing-box", "singbox",
		"meta tunnel", "clash", "v2ray", "xray", "nekoray", "hiddify", "openvpn", "outline", "tun2socks", "vpn"} {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// IsTunnelIfaceName classifies a macOS/BSD interface name (utun3, ipsec0, ppp0...).
func IsTunnelIfaceName(name string) bool {
	for _, p := range []string{"utun", "tun", "tap", "ipsec", "ppp", "wg"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
