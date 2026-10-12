#!/bin/bash
# Install Based: the based program into ~/.local/bin and the bar widget into
# the Omarchy shell. Builds the program from this repo's source with Go.
# Run with --uninstall to remove both again.
set -euo pipefail

cd "$(dirname "$0")"
PLUGIN_ID="io.github.bufuuu.based"
BIN_DIR="$HOME/.local/bin"
PLUGIN_DIR="$HOME/.config/omarchy/plugins/$PLUGIN_ID"

# early builds used the ID based.shield; replace that copy
if [[ -d $HOME/.config/omarchy/plugins/based.shield ]]; then
  omarchy plugin disable based.shield >/dev/null 2>&1 || true
  rm -rf "$HOME/.config/omarchy/plugins/based.shield"
fi

if [[ ${1:-} == "--uninstall" ]]; then
  omarchy plugin disable "$PLUGIN_ID" 2>/dev/null || true
  rm -rf "$PLUGIN_DIR"
  rm -f "$BIN_DIR/based"
  omarchy-shell shell rescanPlugins 2>/dev/null || true
  echo "Removed Based. Scan history is kept in ${XDG_STATE_HOME:-$HOME/.local/state}/based"
  exit 0
fi

if command -v go >/dev/null; then
  GO=(go)
elif command -v mise >/dev/null && mise which go >/dev/null 2>&1; then
  GO=(mise exec -- go)
else
  echo "Based is built from this repo's Go source, and Go is missing: omarchy pkg add go" >&2
  exit 1
fi
echo "Building based…"
mkdir -p "$BIN_DIR"
"${GO[@]}" build -trimpath -ldflags "-s -w" -o "$BIN_DIR/based" ./cmd/based

echo "Installing bar widget…"
changed=0
# `omarchy plugin add` clones this repo into the plugin folder itself
if [[ $(realpath .) != $(realpath -m "$PLUGIN_DIR") ]]; then
  mkdir -p "$PLUGIN_DIR"
  if [[ -f $PLUGIN_DIR/Widget.qml ]] && ! cmp -s Widget.qml "$PLUGIN_DIR/Widget.qml"; then
    changed=1
  fi
  cp manifest.json Widget.qml "$PLUGIN_DIR/"
fi
if ((changed)); then
  # the shell keeps a loaded widget's compiled code; only a restart picks up the new one
  omarchy-restart-shell >/dev/null 2>&1 || true
else
  omarchy-shell shell rescanPlugins >/dev/null 2>&1 || true
fi
if ! omarchy plugin list 2>/dev/null | grep -q "$PLUGIN_ID.*enabled"; then
  omarchy plugin enable "$PLUGIN_ID" --section right >/dev/null
fi

echo
echo "Done. Try:"
echo "  based scan          # user scan"
echo "  based scan --sudo   # full coverage incl. root-only files"
echo "  based               # timeline"
