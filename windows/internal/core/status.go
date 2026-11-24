// Package core holds the platform-independent parts of ClaudeGuard:
// the status model, the IP/country checker, hosts-file rendering and
// the Claude Code settings.json hook editor.
package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const (
	ServiceName = "ClaudeGuard"
	// Named event the tray / hook signal to make the service re-check now.
	RefreshEvent = `Global\ClaudeGuardRefresh`
	// If the service hasn't rewritten status.json for this long, it's considered dead.
	StaleAfter = 90 * time.Second
)

type State string

const (
	StateAllowed   State = "allowed"   // direct route verified, not Iran
	StateProxyOnly State = "proxyOnly" // direct route is Iran/unknown (blocked), system proxy exits abroad
	StateBlocked   State = "blocked"   // Iran, or location could not be verified, and no safe proxy
	StateChecking  State = "checking"  // check in progress
)

type Status struct {
	State State `json:"state"`
	// Enforcing: direct connections to Anthropic are blocked (firewall).
	// Traffic through a local proxy (v2ray) is not affected by this block.
	Enforcing bool   `json:"enforcing"`
	InIran    bool   `json:"inIran"` // the DIRECT route exits in Iran
	Message   string `json:"message"`
	// Direct route (what Claude Code uses without proxy env vars).
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
	Country string `json:"country,omitempty"`
	// System-proxy route (what Claude Desktop uses), if a system proxy is set.
	Proxy *ProxyRoute `json:"proxy,omitempty"`
	// Which interfaces traffic takes (TUN VPN detection).
	Network *NetInfo `json:"network,omitempty"`
	// Detected Clash / sing-box instances and how they route Claude.
	Apps []ProxyApp `json:"apps,omitempty"`
	// Claude Desktop is being closed because its route exits in Iran.
	DesktopBlocked bool       `json:"desktopBlocked,omitempty"`
	CheckedAt      *time.Time `json:"checkedAt,omitempty"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}

func (s Status) IsStale() bool { return time.Since(s.UpdatedAt) > StaleAfter }

// SameContent compares two statuses ignoring the heartbeat timestamp.
func (s Status) SameContent(o *Status) bool {
	if o == nil {
		return false
	}
	a, b := s, *o
	a.UpdatedAt, b.UpdatedAt = time.Time{}, time.Time{}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// DataDir is C:\ProgramData\ClaudeGuard (CLAUDEGUARD_DATA_DIR overrides it, for testing).
func DataDir() string {
	if d := os.Getenv("CLAUDEGUARD_DATA_DIR"); d != "" {
		return d
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "ClaudeGuard")
}

func StatusFile() string { return filepath.Join(DataDir(), "status.json") }
func LogFile() string    { return filepath.Join(DataDir(), "claudeguard.log") }

// LoadStatus reads status.json, retrying briefly in case the service is mid-replace.
func LoadStatus() *Status {
	for i := 0; i < 4; i++ {
		data, err := os.ReadFile(StatusFile())
		if err == nil {
			var s Status
			if json.Unmarshal(data, &s) == nil {
				return &s
			}
		} else if os.IsNotExist(err) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func (s Status) Save() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := StatusFile() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	// On Windows the rename can fail for a moment while a reader has the file open.
	for i := 0; ; i++ {
		err = os.Rename(tmp, StatusFile())
		if err == nil || i >= 20 {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func Now() time.Time { return time.Now().UTC().Truncate(time.Second) }

// CountryName returns an English name for common codes, else the code itself.
func CountryName(code string) string {
	if code == "" {
		return "Unknown"
	}
	if n, ok := countryNames[code]; ok {
		return n
	}
	return code
}

var countryNames = map[string]string{
	"IR": "Iran", "US": "United States", "GB": "United Kingdom", "DE": "Germany", "NL": "Netherlands",
	"FR": "France", "CA": "Canada", "TR": "Turkey", "AE": "United Arab Emirates", "SE": "Sweden",
	"FI": "Finland", "CH": "Switzerland", "AT": "Austria", "IT": "Italy", "ES": "Spain", "PL": "Poland",
	"JP": "Japan", "SG": "Singapore", "AU": "Australia", "IN": "India", "RU": "Russia", "AM": "Armenia",
	"GE": "Georgia", "IQ": "Iraq", "QA": "Qatar", "OM": "Oman", "BH": "Bahrain", "KW": "Kuwait",
	"SA": "Saudi Arabia", "HK": "Hong Kong", "LU": "Luxembourg", "NO": "Norway", "DK": "Denmark",
	"BE": "Belgium", "IE": "Ireland", "PT": "Portugal", "RO": "Romania", "CZ": "Czechia", "UA": "Ukraine",
	"BG": "Bulgaria", "HU": "Hungary", "CY": "Cyprus", "MY": "Malaysia", "KR": "South Korea", "BR": "Brazil",
}
