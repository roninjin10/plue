# SSH Protocol Implementation

**Priority:** Critical
**Area:** server/ssh

## Description

The SSH server has a full security framework (auth, rate limiting, connection limits, PROXY protocol, health monitoring) but the actual SSH protocol handling is not implemented. The server accepts connections but cannot perform key exchange or handle Git-over-SSH operations.

## Current State

- `server/ssh/server.zig:452` — Auth handling is stubbed
- `server/ssh/server.zig:595` — Full SSH protocol TODO noting complexity:
  1. Key Exchange (KEX)
  2. User authentication
  3. Channel management
  4. Git command parsing/execution
  5. Git data transfer

## What's Working

- Public key authentication validation (`ssh/auth.zig`)
- Connection limiting — global + per-IP (`ssh/connection_limit.zig`)
- Rate limiting with automatic IP banning (`ssh/rate_limit.zig`)
- PROXY protocol support for Cloudflare Spectrum (`ssh/proxy_protocol.zig`)
- Health monitoring (`ssh/health.zig`)
- Security event logging (`ssh/security_log.zig`)

## What's Needed

Either integrate `libssh2` bindings or implement a pure Zig SSH protocol handler covering:
- Key exchange negotiation
- SSH channel management
- Git pack protocol (git-upload-pack, git-receive-pack)
- Data transfer streaming

## Files

- `server/ssh/server.zig`
- `server/ssh/auth.zig`
- `server/ssh/session.zig`
