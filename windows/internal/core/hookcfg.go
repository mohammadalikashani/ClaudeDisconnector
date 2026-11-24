package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// HookCommand is what Claude Code runs on every prompt. Forward slashes + quotes
// work both in Git Bash (which Claude Code uses on Windows) and in cmd.
const HookCommand = `"C:/Program Files/ClaudeGuard/claudeguard.exe" hook`

func ClaudeSettingsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "settings.json")
}

// orderedObject is a JSON object that keeps its key order on round-trip,
// so we don't reshuffle the user's settings.json.
type orderedObject struct {
	keys []string
	vals map[string]json.RawMessage
}

func parseObject(data []byte) (*orderedObject, error) {
	o := &orderedObject{vals: map[string]json.RawMessage{}}
	if len(bytes.TrimSpace(data)) == 0 {
		return o, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("expected a JSON object")
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k := kt.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		if _, exists := o.vals[k]; !exists {
			o.keys = append(o.keys, k)
		}
		o.vals[k] = v
	}
	return o, nil
}

func (o *orderedObject) set(k string, v json.RawMessage) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *orderedObject) del(k string) {
	if _, ok := o.vals[k]; !ok {
		return
	}
	delete(o.vals, k)
	for i, kk := range o.keys {
		if kk == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o *orderedObject) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		b.Write(o.vals[k])
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func pretty(o *orderedObject) ([]byte, error) {
	raw, err := o.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var compact, out bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, err
	}
	if err := json.Indent(&out, compact.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

type hookGroup struct {
	Hooks []struct {
		Command string `json:"command"`
	} `json:"hooks"`
}

func groupHasCommand(raw json.RawMessage, cmd string) bool {
	var g hookGroup
	if json.Unmarshal(raw, &g) != nil {
		return false
	}
	for _, h := range g.Hooks {
		if h.Command == cmd {
			return true
		}
	}
	return false
}

// AddHook returns settings JSON with the ClaudeGuard UserPromptSubmit hook added
// (unchanged=true if it was already there).
func AddHook(settings []byte, cmd string) (out []byte, unchanged bool, err error) {
	root, err := parseObject(settings)
	if err != nil {
		return nil, false, err
	}
	hooks, err := parseObject(root.vals["hooks"])
	if err != nil {
		return nil, false, fmt.Errorf("hooks: %w", err)
	}
	var groups []json.RawMessage
	if raw, ok := hooks.vals["UserPromptSubmit"]; ok {
		if err := json.Unmarshal(raw, &groups); err != nil {
			return nil, false, fmt.Errorf("UserPromptSubmit: %w", err)
		}
	}
	for _, g := range groups {
		if groupHasCommand(g, cmd) {
			return settings, true, nil
		}
	}
	entry, _ := json.Marshal(map[string]any{
		"hooks": []map[string]any{{"type": "command", "command": cmd, "timeout": 15}},
	})
	groups = append(groups, entry)
	gb, _ := json.Marshal(groups)
	hooks.set("UserPromptSubmit", gb)
	hb, _ := hooks.MarshalJSON()
	root.set("hooks", hb)
	out, err = pretty(root)
	return out, false, err
}

// RemoveHook returns settings JSON with the ClaudeGuard hook removed.
func RemoveHook(settings []byte, cmd string) (out []byte, unchanged bool, err error) {
	root, err := parseObject(settings)
	if err != nil {
		return nil, false, err
	}
	rawHooks, ok := root.vals["hooks"]
	if !ok {
		return settings, true, nil
	}
	hooks, err := parseObject(rawHooks)
	if err != nil {
		return nil, false, err
	}
	var groups []json.RawMessage
	if raw, ok := hooks.vals["UserPromptSubmit"]; ok {
		if err := json.Unmarshal(raw, &groups); err != nil {
			return nil, false, err
		}
	}
	var kept []json.RawMessage
	for _, g := range groups {
		if !groupHasCommand(g, cmd) {
			kept = append(kept, g)
		}
	}
	if len(kept) == len(groups) {
		return settings, true, nil
	}
	if len(kept) == 0 {
		hooks.del("UserPromptSubmit")
	} else {
		gb, _ := json.Marshal(kept)
		hooks.set("UserPromptSubmit", gb)
	}
	hb, _ := hooks.MarshalJSON()
	root.set("hooks", hb)
	out, err = pretty(root)
	return out, false, err
}

// InstallHook / UninstallHook edit the current user's ~/.claude/settings.json.
func InstallHook() (string, error) {
	p := ClaudeSettingsPath()
	data, err := os.ReadFile(p)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	out, unchanged, err := AddHook(data, HookCommand)
	if err != nil {
		return "", fmt.Errorf("%s: %w", p, err)
	}
	if unchanged {
		return "Claude Code hook already present", nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	if len(data) > 0 {
		_ = os.WriteFile(p+".claudeguard-backup", data, 0o644)
	}
	if err := os.WriteFile(p, out, 0o644); err != nil {
		return "", err
	}
	return "Claude Code hook added to " + p, nil
}

func UninstallHook() (string, error) {
	p := ClaudeSettingsPath()
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return "no Claude Code settings file", nil
	}
	if err != nil {
		return "", err
	}
	out, unchanged, err := RemoveHook(data, HookCommand)
	if err != nil {
		return "", err
	}
	if unchanged {
		return "Claude Code hook not present", nil
	}
	return "Claude Code hook removed", os.WriteFile(p, out, 0o644)
}

// ------------------------------------------------------------------ Claude Code proxy env

// SetEnv / UnsetEnv edit the "env" object of settings.json, keeping key order.
func SetEnv(settings []byte, key, value string) ([]byte, error) {
	root, err := parseObject(settings)
	if err != nil {
		return nil, err
	}
	env, err := parseObject(root.vals["env"])
	if err != nil {
		return nil, fmt.Errorf("env: %w", err)
	}
	vb, _ := json.Marshal(value)
	env.set(key, vb)
	eb, _ := env.MarshalJSON()
	root.set("env", eb)
	return pretty(root)
}

func UnsetEnv(settings []byte, keys ...string) (out []byte, unchanged bool, err error) {
	root, err := parseObject(settings)
	if err != nil {
		return nil, false, err
	}
	raw, ok := root.vals["env"]
	if !ok {
		return settings, true, nil
	}
	env, err := parseObject(raw)
	if err != nil {
		return nil, false, err
	}
	changed := false
	for _, k := range keys {
		if _, ok := env.vals[k]; ok {
			env.del(k)
			changed = true
		}
	}
	if !changed {
		return settings, true, nil
	}
	if len(env.keys) == 0 {
		root.del("env")
	} else {
		eb, _ := env.MarshalJSON()
		root.set("env", eb)
	}
	out, err = pretty(root)
	return out, false, err
}

// ClaudeSettingsProxy returns env.HTTPS_PROXY (or HTTP_PROXY) from ~/.claude/settings.json.
func ClaudeSettingsProxy() string {
	data, err := os.ReadFile(ClaudeSettingsPath())
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

// SetClaudeProxy makes Claude Code route its traffic through proxyURL (an HTTP proxy;
// Claude Code doesn't support SOCKS). "" removes the setting.
func SetClaudeProxy(proxyURL string) (string, error) {
	p := ClaudeSettingsPath()
	data, err := os.ReadFile(p)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	var out []byte
	if proxyURL == "" {
		var unchanged bool
		out, unchanged, err = UnsetEnv(data, "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy")
		if err != nil {
			return "", err
		}
		if unchanged {
			return "Claude Code had no proxy configured in " + p, nil
		}
	} else {
		if strings.HasPrefix(strings.ToLower(proxyURL), "socks") {
			return "", fmt.Errorf("Claude Code doesn't support SOCKS proxies; use v2ray's HTTP port")
		}
		out, err = SetEnv(data, "HTTPS_PROXY", NormalizeProxyURL(proxyURL))
		if err != nil {
			return "", err
		}
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	if len(data) > 0 {
		_ = os.WriteFile(p+".claudeguard-backup", data, 0o644)
	}
	if err := os.WriteFile(p, out, 0o644); err != nil {
		return "", err
	}
	if proxyURL == "" {
		return "Claude Code proxy removed from " + p + ". Restart Claude Code sessions.", nil
	}
	return "Claude Code will use " + NormalizeProxyURL(proxyURL) + " (set in " + p + "). Restart Claude Code sessions.", nil
}
