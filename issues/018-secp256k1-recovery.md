# Secp256k1 Public Key Recovery at Origin

**Priority:** Medium
**Area:** server/crypto

## Description

Secp256k1 public key recovery is intentionally disabled at the origin server — it returns `RecoveryNotImplemented`. SIWE signature verification happens at the edge worker instead.

## Current State

`server/crypto/secp256k1.zig:80-104`:
```zig
/// secp256k1 public key recovery is not implemented in this build.
RecoveryNotImplemented,

/// IMPORTANT: This function is intentionally not implemented at the origin server.
pub fn recoverPublicKey(...) ![]const u8 {
    return error.RecoveryNotImplemented;
}
```

## Consideration

This may be intentional by design (edge handles auth). If origin-level SIWE verification is ever needed (e.g., for mTLS-only deployments without the edge), this would need a real implementation — likely linking against `libsecp256k1`.

## Files

- `server/crypto/secp256k1.zig`
