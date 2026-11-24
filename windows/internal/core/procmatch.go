package core

import "strings"

// IsClaudeDesktop tells Claude Desktop apart from the Claude Code CLI (both are claude.exe).
func IsClaudeDesktop(name, path string) bool {
	if !strings.EqualFold(name, "claude.exe") {
		return false
	}
	p := strings.ToLower(path)
	if strings.Contains(p, `\.local\bin\`) || strings.Contains(p, `\npm\`) || strings.Contains(p, `node_modules`) {
		return false // Claude Code CLI
	}
	return strings.Contains(p, `\anthropicclaude\`) ||
		(strings.Contains(p, `\windowsapps\`) && strings.Contains(p, "claude")) ||
		strings.Contains(p, `\programs\claude\`)
}
