#!/usr/bin/env bash
# Installe le SETUP RECON COMPLET dans ~/.local/bin.
# Core (ProjectDiscovery): subfinder, httpx, nuclei, dnsx, katana, naabu.
# Extra: gau (lc/gau), ffuf. Via `go install` si Go OK, sinon binaires des releases.
# Idempotent. Cible: Linux amd64.
set -uo pipefail

BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"

# name : github_repo : go_package
TOOLS=(
  "subfinder:projectdiscovery/subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
  "httpx:projectdiscovery/httpx:github.com/projectdiscovery/httpx/cmd/httpx"
  "nuclei:projectdiscovery/nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
  "dnsx:projectdiscovery/dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx"
  "katana:projectdiscovery/katana:github.com/projectdiscovery/katana/cmd/katana"
  "naabu:projectdiscovery/naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu"
  "gau:lc/gau:github.com/lc/gau/v2/cmd/gau"
  "ffuf:ffuf/ffuf:github.com/ffuf/ffuf/v2"
  "asnmap:projectdiscovery/asnmap:github.com/projectdiscovery/asnmap/cmd/asnmap"
  "tlsx:projectdiscovery/tlsx:github.com/projectdiscovery/tlsx/cmd/tlsx"
  "cdncheck:projectdiscovery/cdncheck:github.com/projectdiscovery/cdncheck/cmd/cdncheck"
  "interactsh-client:projectdiscovery/interactsh:github.com/projectdiscovery/interactsh/cmd/interactsh-client"
  "notify:projectdiscovery/notify:github.com/projectdiscovery/notify/cmd/notify"
  "dalfox:hahwul/dalfox:github.com/hahwul/dalfox/v2"
  "trufflehog:trufflesecurity/trufflehog:github.com/trufflesecurity/trufflehog/v3"
  "anew:tomnomnom/anew:github.com/tomnomnom/anew"
  "gf:tomnomnom/gf:github.com/tomnomnom/gf"
  "qsreplace:tomnomnom/qsreplace:github.com/tomnomnom/qsreplace"
)

install_via_release() {
  local name="$1" repo="$2" tmp url bin
  # amd64 OU x86_64 (goreleaser varie selon les projets), jamais arm/aarch64
  url=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" \
        | grep -oiE "https://[^\"]*[lL]inux[_-]?(amd64|x86_64)[^\"]*\.(zip|tar\.gz)" \
        | grep -viE "arm|aarch" | head -1)
  [ -n "$url" ] || { echo "  $name: URL release introuvable"; return 1; }
  tmp=$(mktemp -d)
  curl -fsSL "$url" -o "$tmp/arc" || { rm -rf "$tmp"; return 1; }
  case "$url" in
    *.zip)    unzip -oq "$tmp/arc" -d "$tmp" 2>/dev/null ;;
    *.tar.gz) tar xzf "$tmp/arc" -C "$tmp" 2>/dev/null ;;
  esac
  bin=$(find "$tmp" -type f -name "$name" 2>/dev/null | head -1)
  if [ -n "$bin" ]; then install -m755 "$bin" "$BIN_DIR/$name"; echo "  $name: installé (release)";
  else echo "  $name: binaire introuvable dans l'archive"; fi
  rm -rf "$tmp"
}

for entry in "${TOOLS[@]}"; do
  IFS=: read -r name repo gopkg <<<"$entry"
  echo "== $name =="
  if [ -x "$BIN_DIR/$name" ]; then echo "  déjà présent"; continue; fi
  if command -v go >/dev/null 2>&1 && [ -n "$gopkg" ]; then
    GOBIN="$BIN_DIR" GOTOOLCHAIN=auto go install "${gopkg}@latest" 2>/dev/null \
      && echo "  $name: installé (go)" || install_via_release "$name" "$repo"
  else
    install_via_release "$name" "$repo"
  fi
done

echo ""
echo "== Vérification =="
for entry in "${TOOLS[@]}"; do
  IFS=: read -r name _ _ <<<"$entry"
  if [ -x "$BIN_DIR/$name" ]; then
    v=$("$BIN_DIR/$name" -version 2>&1 | grep -oiE "v?[0-9]+\.[0-9]+\.[0-9]+" | head -1)
    echo "  $name -> ${v:-présent}"
  else echo "  $name -> ABSENT"; fi
done
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "⚠️  Ajoute $BIN_DIR au PATH";; esac
