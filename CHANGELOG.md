# Changelog

All notable changes to `@lam/keyring` are documented in this file.

## [1.0.1] - 2026-10-21

### Changed

- Requires `lamc` 3.0 (`>=3.0, <4`); tests no longer work around lamc 2.1 limitations.

## [1.0.0] - 2026-10-19

First release, extracted from the `SecretBox` of the managed-file-transfer
application and extended.

### Added

- `KeyRing`: AES-256-GCM key rings with key ids and a primary key.
  `parse` (`id=hex;id=hex`, `ring:` prefix, `id:hex,id:hex`, one optional
  unlabelled key), `fromEnv`, `single`, `generateKey`, `add`, `merge`,
  `withPrimary`, `without`, `toSpec`, `primaryId`, `ids`, `has`, `size`;
  rings are immutable.
- `seal(plaintext, aad="")` / `open(sealed, aad="")` with the legacy
  (unprefixed), `v2:<keyId>:` and new `v3:<keyId>:` (associated data) forms;
  `inspect` describes a value without opening it.
- Error kinds `InvalidKey`, `KeyNotFound`, `Corrupted`,
  `WrongAssociatedData`, `CryptoError`.
- Rotation: `needsReseal`, `reseal`, `rebind`, and `Resealer` (`values`,
  `items`, paged `run(fetch, store, batchSize)` with compare-and-swap
  conflicts, dry runs, `stopOnError`) with `SealedItem` and `ResealReport`
  counts.
- Purpose-scoped HKDF subkeys: `forPurpose`.
- Envelope encryption: `wrapKey`, `unwrapKey`, `newWrappedKey`
  (`WrappedKey`), `unwrapRing`.
- Key derivation: `KeyRing.derive` (HKDF-SHA256), `KeyRing.fromPassword`
  (PBKDF2-HMAC-SHA256), `KeyRing.deriveLegacy` and `KeyRing.withFallback`
  (the HMAC-SHA256 derivation of SecretBox, label as a parameter), and
  `KeyDerivation` (`hkdf`, `hkdfHex`, `pbkdf2`, `legacyHmac`, `randomHex`).
- `KeyRing.constantTimeEquals`.

### Compatibility

- Reads and writes SecretBox values byte for byte (legacy and `v2`
  forms, `JWT_SECRET`-derived fallback key with the `mft:secret-box:v1`
  label).
- Requires `lamc` `>=2.1, <4` and Go 1.24 or newer (`crypto/hkdf`,
  `crypto/pbkdf2`); no Go module dependencies.

### Testing

- `tests/run_lamkeyring_tests.py` compiles every `tests/test_*.lam` through
  the installed-package boundary: parsing, sealing and tampering,
  associated data, derivation (RFC 5869 HKDF and PBKDF2-HMAC-SHA256
  vectors), managed-file-transfer fixtures, purpose and envelope keys, the
  resealer, and a composed lifecycle test. `--mft <dir>` adds the
  two-way interop test in `tests/interop/` against a managed-file-transfer
  checkout.
