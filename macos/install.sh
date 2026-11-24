#!/bin/bash
# Installs ClaudeGuard. Run as your normal user (NOT with sudo); it asks for your password when needed.
set -euo pipefail
cd "$(dirname "$0")"

if [[ $EUID -eq 0 ]]; then
  echo "Run ./install.sh as your normal user (it will call sudo itself)." >&2
  exit 1
fi

echo "==> Building"
./build.sh

echo
echo "==> Current location check"
./build/claudeguardd check || true
echo
echo "NOTE: Protection starts in BLOCKED mode and unblocks after the check (~2s)."
echo "      If you are on an Iranian IP right now, Claude (including any open Claude Code session) will be cut off."
read -r -p "Continue? [y/N] " ok
[[ "$ok" =~ ^[Yy]$ ]] || exit 1

echo "==> Installing protection service (needs admin password)"
sudo /bin/launchctl bootout system/com.claudeguard.daemon 2>/dev/null || true
sudo /bin/mkdir -p /Library/PrivilegedHelperTools
sudo /usr/bin/install -o root -g wheel -m 755 build/claudeguardd /Library/PrivilegedHelperTools/claudeguardd
sudo /usr/bin/install -o root -g wheel -m 644 Resources/com.claudeguard.daemon.plist /Library/LaunchDaemons/com.claudeguard.daemon.plist
sudo /bin/mkdir -p /usr/local/bin
sudo /bin/ln -sf /Library/PrivilegedHelperTools/claudeguardd /usr/local/bin/claudeguard
sudo /bin/launchctl bootstrap system /Library/LaunchDaemons/com.claudeguard.daemon.plist

echo "==> Installing menu bar app"
AGENT="$HOME/Library/LaunchAgents/com.claudeguard.app.plist"
/bin/launchctl bootout "gui/$UID/com.claudeguard.app" 2>/dev/null || true
pkill -x ClaudeGuard 2>/dev/null || true
rm -rf /Applications/ClaudeGuard.app
cp -R build/ClaudeGuard.app /Applications/ClaudeGuard.app
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$AGENT" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.claudeguard.app</string>
    <key>ProgramArguments</key>
    <array><string>/Applications/ClaudeGuard.app/Contents/MacOS/ClaudeGuard</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><false/>
    <key>LimitLoadToSessionType</key><string>Aqua</string>
</dict>
</plist>
PLIST
/bin/launchctl bootstrap "gui/$UID" "$AGENT"

echo "==> Adding Claude Code hook (~/.claude/settings.json)"
/usr/bin/python3 - <<'PY'
import json, os, shutil
p = os.path.expanduser("~/.claude/settings.json")
cmd = "/Library/PrivilegedHelperTools/claudeguardd hook"
os.makedirs(os.path.dirname(p), exist_ok=True)
data = {}
if os.path.exists(p):
    shutil.copy2(p, p + ".claudeguard-backup")
    with open(p) as f:
        data = json.load(f)
groups = data.setdefault("hooks", {}).setdefault("UserPromptSubmit", [])
if not any(h.get("command") == cmd for g in groups for h in g.get("hooks", [])):
    groups.append({"hooks": [{"type": "command", "command": cmd, "timeout": 15}]})
    with open(p, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("   hook added (backup: settings.json.claudeguard-backup)")
else:
    print("   hook already present")
PY

sleep 3
echo
echo "==> Status"
/Library/PrivilegedHelperTools/claudeguardd status || true
echo
echo "Done. Look for the shield icon in your menu bar. Logs: /var/log/claudeguard.log"
