---
name: bibavpn-setup
description: Set up, connect to, or troubleshoot BibaVPN clients and servers, including the local Docker lab, SOCKS5 connectivity, invitations, and per-user access. Use when a user asks to run or diagnose BibaVPN; consult the repository's own documentation for implementation changes.
---

# BibaVPN setup

Help the user reach the requested BibaVPN outcome. First identify whether they have an existing server or invitation, want a local Docker lab, or want to self-host; use existing configuration rather than recreating it. If essential host, credential, or certificate details are missing, ask only for what is needed; do not ask the user to paste secrets into chat.

## Workflow

1. Find the BibaVPN repository and read its `AGENTS.md` and the relevant sections of `README.md`. The README is the source of truth for current commands and options. If the repository is unavailable, obtain it only when that is part of the task.
2. Choose the matching path:
   - **Existing invitation:** import it in the client and use its separate passphrase. For the CLI, see the README's invitation instructions. Do not print or log the URI or passphrase.
   - **Local lab:** follow README Quick start with `docker-compose.hub.yml` and fresh local credentials. Check that Docker, Compose, OpenSSL, curl, and the required ports are available. The lab uses self-signed TLS and is not a remote-server security template.
   - **Self-hosted server:** follow README Self-host on a VPS and Build from source. Use a reachable host, verified TLS or a trusted certificate pin, and matching client/server PSK and token. For separate users, follow Manage multiple users in the README, including the registry file's permissions and per-process session limits.
3. Verify the requested outcome. The CLI supplies a SOCKS5 or HTTP proxy, not a system-wide VPN. For SOCKS5, run the bundled script with an explicitly chosen HTTP(S) target and the correct local port:

   ```bash
   bash scripts/check-connection.sh --socks 127.0.0.1:11080 --url https://example.com/
   ```

   The command is relative to this skill directory; use `127.0.0.1:1080` for the README's source client example and `11080` for its Docker lab. The target receives a request; choose one appropriate to the user's task. A successful request proves proxy reachability, not anonymity, DNS-leak resistance, UDP support, or that all applications use the tunnel.
4. If setup or verification fails, read [troubleshooting.md](references/troubleshooting.md), identify the failing layer, and report the result without credentials, invitation contents, private keys, or unredacted environment dumps.

## Operational details

- A `biba://` invitation, its passphrase, PSK, token, user registry, and private key are secrets. Use existing private channels; do not include them in reports or commit them.
- `start.sh` replaces `.biba-start.env` secrets when rerun. Preserve existing deployments and use the user's chosen environment. The source Compose lab publishes proxy ports on host interfaces; the hub lab binds them to localhost.
- Keep certificate verification enabled for remote servers. Do not suggest `--insecure` outside an explicitly local test. Do not weaken authentication to fix a connection.
- For device apps, platform builds, protocol details, and full CLI options, follow the relevant repository docs and `--help` rather than guessing. Do not claim a setup works until the intended connection has been tested.
