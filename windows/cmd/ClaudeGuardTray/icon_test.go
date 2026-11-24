package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ICON_OUT=dir go test ./cmd/ClaudeGuardTray  -> writes the PNG payloads for a visual check
func TestIcons(t *testing.T) {
	for name, ico := range map[string][]byte{"allowed": iconAllowed, "proxy": iconProxy, "iran": iconIran, "unknown": iconUnknown, "checking": iconChecking, "down": iconDown} {
		if len(ico) < 100 || string(ico[22:26]) != "\x89PNG" {
			t.Fatalf("%s: bad ico", name)
		}
		if d := os.Getenv("ICON_OUT"); d != "" {
			os.WriteFile(filepath.Join(d, name+".png"), ico[22:], 0o644)
		}
	}
}
