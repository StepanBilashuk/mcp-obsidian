#!/usr/bin/env bash
# Installs vaultmcp as a systemd service. Run from the unpacked folder: sudo ./install.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "Run with sudo: sudo ./install.sh" >&2; exit 1; fi
cd "$(dirname "$0")"

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
BIN=""
for c in "${VAULTMCP_BIN:-}" ./vaultmcp "./vaultmcp-linux-$ARCH" "./dist/vaultmcp-linux-$ARCH"; do
  if [[ -n "$c" && -f "$c" ]]; then BIN="$c"; break; fi
done
[[ -n "$BIN" ]] || { echo "No binary found. Build one with 'make dist' or set VAULTMCP_BIN=/path/to/vaultmcp" >&2; exit 1; }

install -m 0755 "$BIN" /usr/local/bin/vaultmcp

id vaultmcp &>/dev/null || useradd --system --home-dir /srv/vault --shell /usr/sbin/nologin vaultmcp
install -d -o vaultmcp -g vaultmcp -m 0750 /srv/vault
install -d -o root -g vaultmcp -m 0750 /etc/vaultmcp

if [[ ! -f /etc/vaultmcp/env ]]; then
  TOKEN="$(openssl rand -hex 32)"
  umask 077
  cat > /etc/vaultmcp/env <<ENV
VAULT_DIR=/srv/vault
VAULT_ADDR=127.0.0.1:8787
VAULT_MCP_TOKEN=${TOKEN}
ENV
  chown root:vaultmcp /etc/vaultmcp/env
  chmod 0640 /etc/vaultmcp/env
  echo "Generated a new token."
fi

install -m 0644 vaultmcp.service /etc/systemd/system/vaultmcp.service
systemctl daemon-reload
systemctl enable --now vaultmcp
sleep 1
systemctl --no-pager --lines=5 status vaultmcp || true

echo
echo "Health check: $(curl -fsS http://127.0.0.1:8787/healthz || echo FAILED)"
echo "Token (keep it secret): $(grep '^VAULT_MCP_TOKEN=' /etc/vaultmcp/env | cut -d= -f2)"
echo "The server listens on 127.0.0.1 only. See README.md for how to connect."
