#!/usr/bin/env bash
set -euo pipefail

OC_DIR="${OPENCODE_CONFIG_DIR:-$HOME/.config/opencode}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)/src"

echo "Installing pocketpilot into $OC_DIR"

mkdir -p "$OC_DIR/plugin" "$OC_DIR/tui-plugins"
cp "$SRC_DIR/plugin.ts" "$OC_DIR/plugin/remote-control.ts"
cp "$SRC_DIR/tui.ts" "$OC_DIR/tui-plugins/remote-control-tui.ts"

if [ ! -f "$OC_DIR/package.json" ]; then
  printf '{\n  "dependencies": {}\n}\n' > "$OC_DIR/package.json"
fi
npm install --prefix "$OC_DIR" --save qrcode-generator@^2.0.4 web-push@^3.6.7 >/dev/null

node - "$OC_DIR" <<'EOF'
const fs = require("fs")
const path = require("path")
const file = path.join(process.argv[2], "tui.json")
let cfg = {}
try { cfg = JSON.parse(fs.readFileSync(file, "utf8")) } catch {}
cfg.$schema = cfg.$schema || "https://opencode.ai/tui.json"
cfg.plugin = Array.isArray(cfg.plugin) ? cfg.plugin : []
const entry = "./tui-plugins/remote-control-tui.ts"
if (!cfg.plugin.includes(entry)) cfg.plugin.push(entry)
fs.writeFileSync(file, JSON.stringify(cfg, null, 2) + "\n")
console.log("tui.json updated")
EOF

echo ""
echo "Done. Restart opencode, then:"
echo "  - type /remote in the TUI to see the QR, or"
echo "  - run: $OC_DIR/remote-control/qr.sh"
