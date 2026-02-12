# SSH Git Server (External sshd Bridge)

Plue ships a production-ready Git-over-SSH path by delegating the SSH protocol (banner, KEX, ciphers, channels) to OpenSSH (`sshd -i`) while Plue enforces repository authorization and executes git commands. The native Zig SSH server remains experimental and is disabled by default.

## Key Files

| File | Purpose |
|------|---------|
| `server.zig` | SSH server and external-sshd bridge |
| `session.zig` | SSH session management and lifecycle |
| `types.zig` | SSH protocol types and structures |
| `auth.zig` | Public key authentication and user lookup |
| `health.zig` | Server health checks and monitoring |
| `rate_limit.zig` | Connection rate limiting |
| `connection_limit.zig` | Concurrent connection limits |
| `security_log.zig` | Security event logging |
| `proxy_protocol.zig` | PROXY protocol v1 support for load balancers |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SSH Git Server                           │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │    Server    │───▶│   Session    │───▶│     Auth     │  │
│  │              │    │              │    │              │  │
│  │ • TCP :22    │    │ • Lifecycle  │    │ • PublicKey  │  │
│  │ • TLS (opt)  │    │ • Command    │    │ • DB lookup  │  │
│  │ • Health     │    │   execution  │    │ • User map   │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ Rate Limit   │    │ Conn Limit   │    │Security Log  │  │
│  │              │    │              │    │              │  │
│  │ • Per-IP     │    │ • Max conns  │    │ • Auth fails │  │
│  │ • Token      │    │ • Per-user   │    │ • Anomalies  │  │
│  │   bucket     │    │   limits     │    │ • Audit log  │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐ │
│  │              PROXY Protocol v1                        │ │
│  │                                                       │ │
│  │  • Original client IP preservation                   │ │
│  │  • Load balancer support                             │ │
│  └───────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
                   jj-lib (Rust FFI)
                   Git Operations

Active mode: External sshd bridge
- PROXY v1 header is fully read (capped) before handoff to avoid banner corruption.
- Real client IP is passed to the child process via `PLUE_REAL_CLIENT_IP`.
- OpenSSH is launched in inetd mode with a tightly scoped config and a dynamic `AuthorizedKeysCommand` that calls `plue ssh authorized-keys`. The `AuthorizedKeysCommand` binary path is absolute and must be root-owned and not group/world-writable.
```

## Connection Flow (Bridge Mode)

```
Git Client
    │
    │ SSH handshake
    ▼
┌──────────────────┐
│  PROXY Protocol  │  Extract real client IP (if behind LB)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Rate Limit     │  Check connection rate
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Connection Limit│  Check concurrent connections
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Authentication  │  Performed by OpenSSH using dynamic authorized_keys lines
│                  │  `AuthorizedKeysCommand` -> `plue ssh authorized-keys`
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Session Create  │  Initialize SSH session
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Git Command     │  Execute git-receive-pack or git-upload-pack
│                  │  - Validate repository access
│                  │  - Stream Git protocol
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Security Log    │  Log operation and close session
└──────────────────┘
```

## Security Features

| Feature | Implementation |
|---------|----------------|
| Public key auth | Database-backed key lookup |
| Rate limiting | Token bucket per IP |
| Connection limits | Max concurrent per user/global |
| Security logging | All auth attempts logged |
| PROXY protocol | Preserve client IP through LB |
| Health checks | Liveness and readiness endpoints |

## Git Operations

| Command | Description |
|---------|-------------|
| `git-upload-pack` | Clone, fetch, pull operations |
| `git-receive-pack` | Push operations |

Both commands:
- Validate repository access permissions
- Stream Git pack protocol
- Update refs on successful push
- Trigger webhooks/workflows on push

Additionally supported:
- `git-lfs-authenticate <repo> (download|upload)` prints JSON with `href` and optional `Authorization` header (Bearer) based on `PLUE_LFS_URL`/`PLUE_LFS_TOKEN`. This mirrors Gitea parity for LFS over SSH (auth step).

## Notes

- Privilege model (inetd bridge): The embedded inetd-mode (`sshd -i`) requires the Plue process to run as root or as the configured login user (default `git`). If neither is true, the bridge will refuse to start. Production deployments should prefer the system sshd with `AuthorizedKeysCommand` as shown in `server/scripts/sshd_config.plue`.
- Users: Configure `SSH_LOGIN_USER` and `SSH_AUTHORIZED_KEYS_USER` env vars (or their equivalents in `server/config.zig`). Preflight validates that these users exist. The `authorized_keys_command.sh` and `plue ssh authorized-keys` both honor the precedence `SSH_AUTHORIZED_KEYS_USER` > `SSH_LOGIN_USER` > `git`.
  - Note: `AuthorizedKeysCommandUser` switching requires running system `sshd` as root. In inetd bridge mode (`sshd -i`), run Plue as root or as the configured `SSH_LOGIN_USER`.
- Host keys: Missing host keys are auto-generated on server start. Preflight only warns if absent.
- Hardening: The bridge sets `AllowTcpForwarding=no`, `X11Forwarding=no`, `PermitTTY=no`, `LoginGraceTime=20`, and `MaxAuthTries=3`. If you run a system sshd instead, mirror these settings in your sshd_config.
- Hardening: The bridge sets `AllowTcpForwarding=no`, `AllowAgentForwarding=no`, `X11Forwarding=no`, `PermitTTY=no`, `LoginGraceTime=20`, and `MaxAuthTries=3`. It also enforces `AuthenticationMethods=publickey` and disables `AuthorizedKeysFile` fallback. If you run a system sshd instead, mirror these settings in your sshd_config.
- Auth accounting: Plue runs sshd with `-e` and parses stderr lines like "Failed publickey" and "Accepted publickey" to update its rate limiter (ban on repeated failures). When using an external system sshd, redirect logs to stderr (`-e`) or a configured file and feed them to Plue if you want identical semantics.
- Authorized keys emission adds `restrict,no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,no-user-rc` and uses a ForcedCommand `plue ssh serv key-<id>`.
  - The `AuthorizedKeysCommand` path must be absolute, root-owned, and not group/world-writable; Plue validates this at startup.
- `PLUE_BIN` is escaped for inclusion inside a double-quoted authorized_keys command, but avoid embedding quotes when possible.
- Security logging: Authz decisions and command executions from `plue ssh serv` are forwarded to `server/ssh/security_log.zig` for centralized visibility.
- PROXY Protocol: Only v1 is implemented. If you deploy behind Cloudflare Spectrum, enable the PROXY v1 option. Partial headers are read to completion (capped at 512 bytes) before forwarding any SSH bytes to avoid corrupting the handshake.
