#!/usr/bin/env bash
# Installe les outils recon ProjectDiscovery (subfinder, httpx, nuclei) dans ~/.local/bin.
# Via `go install` si Go est présent, sinon via les binaires des releases GitHub.
# Idempotent : relançable sans risque. Cible: Linux amd64.
set -uo pipefail

BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"

declare -A GOPKG=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
  [httpx]="github.com/projectdiscovery/httpx/cmd/httpx"
  [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
)
declare -A REPO=(
  [subfinder]="projectdiscovery/subfinder"
  [httpx]="projectdiscovery/httpx"
  [nuclei]="projectdiscovery/nuclei"
)

install_via_release() {
  local name="$1" repo="$2" tmp url
  url=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" \
        | grep -oE "https://[^\"]*${name}_[0-9.]+_linux_amd64\.zip" | head -1)
  [ -n "$url" ] || { echo "  $name: URL release introuvable"; return 1; }
  tmp=$(mktemp -d)
  curl -fsSL "$url" -o "$tmp/$name.zip" && unzip -oq "$tmp/$name.zip" -d "$tmp" \
    && install -m755 "$tmp/$name" "$BIN_DIR/$name" && echo "  $name: installé (release)"
  rm -rf "$tmp"
}

for tool in subfinder httpx nuclei; do
  echo "== $tool =="
  if command -v go >/dev/null 2>&1; then
    GOBIN="$BIN_DIR" go install "${GOPKG[$tool]}@latest" 2>&1 | tail -1 \
      && echo "  $tool: installé (go)" || install_via_release "$tool" "${REPO[$tool]}"
  else
    install_via_release "$tool" "${REPO[$tool]}"
  fi
done

echo ""
echo "== Vérification (doit dire projectdiscovery) =="
for t in subfinder httpx nuclei; do
  v=$("$BIN_DIR/$t" -version 2>&1 | head -1)
  echo "  $t -> ${v:-ABSENT}"
done
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "⚠️  Ajoute $BIN_DIR au PATH (export PATH=\"$BIN_DIR:\$PATH\")";; esac
