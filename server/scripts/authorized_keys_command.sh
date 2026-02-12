#!/usr/bin/env bash
# Plue SSH Authorized Keys Command
# Queries the database for authorized SSH public keys
#
# Usage: authorized_keys_command.sh <username>
#
# Configure in sshd_config:
#   AuthorizedKeysCommand /opt/plue/scripts/authorized_keys_command.sh
#   AuthorizedKeysCommandUser git
#
# Security considerations:
# - This script runs as the AuthorizedKeysCommandUser (typically 'git')
# - Only active users' keys are returned
# - Each key is prefixed with security restrictions:
#   - no-port-forwarding: Prevents SSH port forwarding
#   - no-X11-forwarding: Prevents X11 forwarding
#   - no-agent-forwarding: Prevents SSH agent forwarding
#   - no-pty: Prevents pseudo-terminal allocation
#   - These restrictions ensure the SSH session can only run git commands

set -euo pipefail

USERNAME="$1"

# Only allow 'git' user (like GitHub)
if [ "$USERNAME" != "git" ]; then
    exit 1
fi

# Delegate to Zig CLI which queries the database and emits authorized_keys lines.
# It also excludes users with prohibit_login = true and prefixes a per-key forced
# command that calls `plue ssh serv key-<id>`.
exec "${PLUE_BIN:-plue}" ssh authorized-keys "$USERNAME"
