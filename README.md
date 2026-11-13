# vaultmcp

Small MCP server (Go, one static binary, ~30 MB RAM) that gives Claude access to a folder of
markdown notes, for example an Obsidian vault. Obsidian builds its graph from `[[wikilinks]]`,
so notes written through this server show up in the graph automatically.

## Tools

| Tool | What it does |
|---|---|
| `list_notes` | list notes, optionally inside one folder |
| `read_note` | read a note |
| `write_note` | create a note (or replace with `overwrite=true`) |
| `append_note` | append text to a note, creating it if needed |
| `search_notes` | full-text search (all words must appear, case-insensitive) |
| `list_backlinks` | notes that link to a given note |
| `find_broken_links` | `[[links]]` that point to missing notes |
| `create_moc` | create a "map of content" hub note linking to a list of notes |

There is deliberately no delete tool.

## Safety

* Every path is vault-relative. `..`, absolute paths, hidden folders (`.obsidian`, `.git`)
  and symlinks that leave the vault are refused. Only `.md` notes, max 1 MiB each.
* HTTP mode requires a bearer token (`VAULT_MCP_TOKEN`, at least 24 characters) and listens on
  `127.0.0.1` by default, so nothing is exposed to the internet.
* The systemd unit runs as an unprivileged user that can only write to `/srv/vault`.

## Install on the server

Build the binaries on any machine with Go 1.24+ (or use the ones from a release archive), copy the
folder to the server, then install:

```bash
make dist                         # builds dist/vaultmcp-linux-amd64 and dist/vaultmcp-linux-arm64
scp -r . ubuntu@YOUR_SERVER:~/vaultmcp
ssh ubuntu@YOUR_SERVER 'cd ~/vaultmcp && sudo ./install.sh'
```

`install.sh` picks the binary for the server architecture from `dist/` (or `./vaultmcp`, or `VAULTMCP_BIN`).

The script installs the binary, creates the `vaultmcp` user and `/srv/vault`, generates a token in
`/etc/vaultmcp/env`, and starts the `vaultmcp` service. Useful commands:

```bash
systemctl status vaultmcp
journalctl -u vaultmcp -f
sudo cat /etc/vaultmcp/env        # token
curl http://127.0.0.1:8787/healthz
```

If the service does not start on your system, read `journalctl -u vaultmcp` first; a strict
hardening option in `vaultmcp.service` is the usual suspect on unusual kernels.

## Connect Claude Code (through an SSH tunnel, nothing is exposed)

On your computer:

```bash
ssh -N -L 8787:127.0.0.1:8787 ubuntu@YOUR_SERVER      # keep it running
claude mcp add --transport http vault http://127.0.0.1:8787/mcp \
  --header "Authorization: Bearer YOUR_TOKEN"
```

Check the exact flags with `claude mcp add --help`, they can change between versions.
Inside Claude Code run `/mcp` to see that `vault` is connected.

You can also run it locally over stdio without any token:

```bash
./vaultmcp-linux-amd64 -mode stdio -vault ~/vault
```

## Getting the notes into Obsidian

Obsidian reads a normal folder, so sync `/srv/vault` with the computer where Obsidian runs
(Syncthing or git). The sync tool must be able to write to the folder: either run it as the
`vaultmcp` user, or add your user to the `vaultmcp` group and make the folder group-writable
(`sudo chmod -R g+rwX /srv/vault`). Obsidian itself is not needed on the server.

## Connect a claude.ai custom connector (OAuth)

claude.ai needs a public HTTPS URL and signs in with OAuth. vaultmcp has a small built-in
authorization server for a single owner: dynamic client registration, authorization code with
PKCE (S256), refresh token rotation. You prove who you are on the consent page with a password.

1. Pick a public HTTPS entry. With Tailscale Funnel (HTTPS and Funnel must be enabled for the
   tailnet in the admin console):

   ```bash
   sudo sed -i "s/^VAULT_ADDR=.*/VAULT_ADDR=127.0.0.1:8787/" /etc/vaultmcp/env   # Funnel proxies to localhost
   sudo tailscale funnel --bg 8787        # check `tailscale funnel --help` for your version
   tailscale funnel status                # shows https://<machine>.<tailnet>.ts.net
   ```

   Any reverse proxy with a certificate (Caddy, nginx) works the same way.
2. Add to `/etc/vaultmcp/env` (no quotes):

   ```
   VAULT_PUBLIC_URL=https://<machine>.<tailnet>.ts.net
   VAULT_OWNER_PASSWORD=<at least 12 characters, generate with: openssl rand -base64 18>
   ```

   Then `sudo systemctl restart vaultmcp`. State (registered clients, refresh tokens as hashes)
   lives in `/var/lib/vaultmcp/oauth-state.json`, mode 0600.
3. In claude.ai: Settings, Connectors, Add custom connector, URL `https://<host>/mcp`, leave
   the client ID and secret empty (Claude registers itself). Sign in with the owner password.

Notes: after 5 wrong passwords the login is locked for 10 minutes. Access tokens live 1 hour,
refresh tokens 30 days. The static `VAULT_MCP_TOKEN` keeps working for Claude Code and curl.
The notes are reachable by anyone who knows the password, so make it long and unique.

## Build from source

```bash
make test
make build        # ./vaultmcp for this machine
make dist         # static Linux binaries for amd64 and arm64
```

`go.mod` replaces `golang.org/x/oauth2` and `golang.org/x/tools` with their GitHub mirrors, so it
builds in places where golang.org is blocked. Needs Go 1.24+. SDK: github.com/modelcontextprotocol/go-sdk v1.2.0.
