package core

import "strings"

// Anthropic-owned IP ranges (api.anthropic.com, claude.ai, claude.com all live here).
var AnthropicRanges = []string{"160.79.104.0/23", "2607:6bc0::/48"}

// Resolved at block time and added to the firewall rule too (future-proofing).
var CoreDomains = []string{"api.anthropic.com", "claude.ai", "claude.com", "anthropic.com"}

var HostsDomains = []string{
	"anthropic.com", "www.anthropic.com", "api.anthropic.com", "console.anthropic.com",
	"statsig.anthropic.com", "mcp-proxy.anthropic.com", "a-api.anthropic.com",
	"a-cdn.anthropic.com", "s-cdn.anthropic.com", "docs.anthropic.com", "support.anthropic.com",
	"claude.ai", "www.claude.ai", "api.claude.ai", "a.claude.ai", "assets.claude.ai",
	"downloads.claude.ai", "storage.claude.ai",
	"claude.com", "www.claude.com", "code.claude.com", "platform.claude.com",
	"api.claude.com", "docs.claude.com", "support.claude.com",
}

const (
	HostsBegin = "# >>> ClaudeGuard (managed automatically - do not edit) >>>"
	HostsEnd   = "# <<< ClaudeGuard <<<"
)

// RenderHosts removes any existing ClaudeGuard section and, if block is true,
// appends a fresh one. Output uses CRLF line endings (Windows).
func RenderHosts(original string, block bool) string {
	var lines []string
	inside := false
	for _, raw := range strings.Split(original, "\n") {
		line := strings.TrimRight(raw, "\r")
		switch {
		case line == HostsBegin:
			inside = true
		case line == HostsEnd:
			inside = false
		case !inside:
			lines = append(lines, line)
		}
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	if block {
		lines = append(lines, "", HostsBegin)
		for _, d := range HostsDomains {
			lines = append(lines, "0.0.0.0 "+d, "::1 "+d)
		}
		lines = append(lines, HostsEnd)
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}
