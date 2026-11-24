#!/bin/bash
# Removes ClaudeGuard completely and lifts all blocks. Run as your normal user.
set -uo pipefail

echo "==> Stopping protection service and removing blocks (needs admin password)"
sudo /bin/launchctl bootout system/com.claudeguard.daemon 2>/dev/null
if [[ -x /Library/PrivilegedHelperTools/claudeguardd ]]; then
  sudo /Library/PrivilegedHelperTools/claudeguardd cleanup
fi
sudo rm -f /Library/LaunchDaemons/com.claudeguard.daemon.plist \
           /Library/PrivilegedHelperTools/claudeguardd \
           /usr/local/bin/claudeguard

echo "==> Removing menu bar app"
/bin/launchctl bootout "gui/$UID/com.claudeguard.app" 2>/dev/null
pkill -x ClaudeGuard 2>/dev/null
rm -f "$HOME/Library/LaunchAgents/com.claudeguard.app.plist"
rm -rf /Applications/ClaudeGuard.app

echo "==> Removing Claude Code hook"
/usr/bin/python3 - <<'PY'
import json, os
p = os.path.expanduser("~/.claude/settings.json")
cmd = "/Library/PrivilegedHelperTools/claudeguardd hook"
if os.path.exists(p):
    with open(p) as f:
        data = json.load(f)
    hooks = data.get("hooks", {})
    groups = hooks.get("UserPromptSubmit", [])
    kept = [g for g in groups if not any(h.get("command") == cmd for h in g.get("hooks", []))]
    if len(kept) != len(groups):
        if kept: hooks["UserPromptSubmit"] = kept
        else: hooks.pop("UserPromptSubmit", None)
        with open(p, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        print("   hook removed")
PY
echo "ClaudeGuard uninstalled."
