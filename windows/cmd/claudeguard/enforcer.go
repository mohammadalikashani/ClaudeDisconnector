//go:build windows

package main

import (
	"log"
	"net"
	"os"
	"strings"

	"claudeguard/internal/core"
	"claudeguard/internal/win"
)

// Enforcer controls two independent block layers:
//
//  1. Windows Firewall - rule "ClaudeGuard-Block" rejects all DIRECT traffic to
//     Anthropic's IP ranges; open IPv4 connections to them are reset. Traffic that
//     goes through a local proxy (v2ray) is unaffected, because v2ray connects to its
//     own server - unless v2ray routes Anthropic "direct", which this also catches.
//  2. hosts file - Claude domains resolve to 0.0.0.0. Dropped while a safe proxy
//     route exists, so v2ray's own domain resolution can't be poisoned by it.
//
// Both persist across reboots, so the machine stays blocked until the service
// has verified the location again.
type Enforcer struct {
	firewall bool
	hosts    bool
	// Warning is non-empty when part of the block can't work (e.g. firewall turned off).
	Warning string
}

func (e *Enforcer) Blocked() bool { return e.firewall }

// Block turns both layers on (force re-applies even if already on).
func (e *Enforcer) Block(force bool) { e.Set(true, true, force) }

// Unblock turns both layers off.
func (e *Enforcer) Unblock(force bool) { e.Set(false, false, force) }

func (e *Enforcer) Set(firewall, hosts bool, force bool) {
	if hosts != e.hosts || force {
		applyHosts(hosts)
		win.FlushDNS()
		e.hosts = hosts
		log.Printf("hosts block: %v", hosts)
	}
	if firewall != e.firewall || force {
		if firewall {
			e.blockFirewall()
		} else {
			win.RemoveFirewallBlock()
			e.Warning = ""
			log.Printf("firewall block: off")
		}
		e.firewall = firewall
	}
}

func (e *Enforcer) blockFirewall() {
	extra := resolve(core.CoreDomains)
	targets := append(append([]string{}, core.AnthropicRanges...), extra...)
	if err := win.AddFirewallBlock(targets); err != nil {
		log.Printf("ERROR firewall: %v", err)
	}
	e.Warning = ""
	if off := win.FirewallDisabledProfiles(); len(off) > 0 {
		e.Warning = "Windows Firewall is OFF for the " + strings.Join(off, "/") +
			" profile, so only the hosts-file block is active there."
		log.Printf("WARN %s", e.Warning)
	}
	killed := win.KillTCP(toNets(targets))
	log.Printf("firewall block: on (extra IPs %v, reset %d connection(s))", extra, killed)
}

func applyHosts(block bool) {
	path := win.HostsPath()
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("ERROR reading hosts: %v", err)
		return
	}
	orig := string(data)
	updated := core.RenderHosts(orig, block)
	if updated == orig {
		return
	}
	_ = os.Chmod(path, 0o666) // clear a read-only attribute if some tool set it
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		log.Printf("ERROR writing hosts: %v", err)
	}
}

// resolve looks up the real addresses of hosts, skipping our own 0.0.0.0 / ::1 entries.
func resolve(hosts []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hosts {
		ips, err := net.LookupIP(h)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip.IsUnspecified() || ip.IsLoopback() {
				continue
			}
			s := ip.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

func toNets(targets []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, t := range targets {
		if !strings.Contains(t, "/") {
			if strings.Contains(t, ":") {
				t += "/128"
			} else {
				t += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(t); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}
