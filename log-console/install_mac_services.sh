#!/bin/bash
# Installs two launchd jobs for the current user (no sudo):
#   com.lab.receiver  - keeps receiver.py running (restarts it if it stops / if the VM network is not up yet)
#   com.lab.pipeline  - runs pipeline.py --once every 120 seconds (mask -> Claude -> e-mail)
# Usage:  ./install_mac_services.sh            install / reinstall
#         ./install_mac_services.sh uninstall
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
BIND="${BIND:-}"      # the Mac's address on the UTM shared network
PORT="${PORT:-8443}"
EVERY="${EVERY:-120}"
PY="$(command -v python3)"
AGENTS="$HOME/Library/LaunchAgents"
UIDN="$(id -u)"

if [ "${1:-}" = "uninstall" ]; then
  for j in receiver pipeline; do
    launchctl bootout "gui/$UIDN/com.lab.$j" 2>/dev/null || true
    rm -f "$AGENTS/com.lab.$j.plist"
  done
  echo "Removed."; exit 0
fi

[ -f "$DIR/config.env" ] || { echo "Create $DIR/config.env first (copy config.env.example)"; exit 1; }
[ -f "$DIR/cert.pem" ] && [ -f "$DIR/key.pem" ] || { echo "cert.pem / key.pem not found in $DIR"; exit 1; }
chmod 600 "$DIR/config.env" "$DIR/key.pem"
mkdir -p "$AGENTS"

cat > "$AGENTS/com.lab.receiver.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.lab.receiver</string>
  <key>ProgramArguments</key><array>
    <string>$PY</string><string>-u</string><string>$DIR/receiver.py</string>
    <string>--bind</string><string>$BIND</string><string>--port</string><string>$PORT</string>
    <string>--cert</string><string>$DIR/cert.pem</string><string>--key</string><string>$DIR/key.pem</string>
  </array>
  <key>WorkingDirectory</key><string>$DIR</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardOutPath</key><string>$DIR/receiver.log</string>
  <key>StandardErrorPath</key><string>$DIR/receiver.log</string>
</dict></plist>
PLIST

cat > "$AGENTS/com.lab.pipeline.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.lab.pipeline</string>
  <key>ProgramArguments</key><array>
    <string>$PY</string><string>$DIR/pipeline.py</string><string>--once</string>
  </array>
  <key>WorkingDirectory</key><string>$DIR</string>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>$EVERY</integer>
  <key>StandardOutPath</key><string>$DIR/pipeline.log</string>
  <key>StandardErrorPath</key><string>$DIR/pipeline.log</string>
</dict></plist>
PLIST

for j in receiver pipeline; do
  launchctl bootout "gui/$UIDN/com.lab.$j" 2>/dev/null || true
  launchctl bootstrap "gui/$UIDN" "$AGENTS/com.lab.$j.plist"
done
echo "Installed. receiver on https://$BIND:$PORT, pipeline every ${EVERY}s."
echo "Logs: tail -f $DIR/receiver.log $DIR/pipeline.log"
echo "Note: the receiver cannot bind $BIND until the VM is running (bridge100 appears then);"
echo "      launchd retries every 30 s, so it comes up by itself."
