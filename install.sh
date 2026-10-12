#!/bin/bash
# Install Based: the based program into ~/.local/bin and the bar widget into
# the Omarchy shell. Builds from source when Go is available, otherwise
# downloads the release binary. Run with --uninstall to remove both again.
set -euo pipefail

cd "$(dirname "$0")"
REPO="BuFuuu/based"
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

mkdir -p "$BIN_DIR"
if command -v go >/dev/null; then
  GO=(go)
elif command -v mise >/dev/null && mise which go >/dev/null 2>&1; then
  GO=(mise exec -- go)
else
  GO=()
fi
if ((${#GO[@]})); then
  echo "Building based…"
  "${GO[@]}" build -trimpath -ldflags "-s -w" -o "$BIN_DIR/based" ./cmd/based
else
  case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *)
    echo "No Go and no release binary for $(uname -m): omarchy pkg add go" >&2
    exit 1
    ;;
  esac
  echo "Downloading based (no Go found)…"
  curl -fsSL -o "$BIN_DIR/based.new" "https://github.com/$REPO/releases/latest/download/based-linux-$arch"
  chmod +x "$BIN_DIR/based.new"
  mv "$BIN_DIR/based.new" "$BIN_DIR/based"
fi

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
