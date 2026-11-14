# Changelog

All notable changes to `@lam/keyring` are documented in this file.

## [1.0.3] - 2026-11-14

### Fixed

- `KeyDerivation.randomHex(size)` with a negative size returns `""`; it
  panicked (`makeslice: len out of range`).

### Tests

- `tests/test_keyring_bytes_concurrency.lam`: every byte value and a 1 MiB
  value round-trip byte-exact; associated data compared as bytes (precomposed
  and decomposed `é`), long and separator-laden associated data, an empty aad
  is no aad; non-ASCII and invalid key ids; `randomHex`, HKDF and PBKDF2
  bounds; `constantTimeEquals` on non-ASCII and empty strings; 64 async tasks
  sealing and opening rows with a ring and its purpose subring, four
  concurrent `Resealer`s after a rotation, and a `?`/`do/catch` pipeline over
  the result.
- `tests/test_keyring_composed.lam` counts legacy values by the absence of a
  `v2:`/`v3:` prefix. It counted values not starting with `v`, but a legacy
  value is bare base64 of a random nonce and starts with `v` 1 time in 64, so
  the test failed about 1 run in 20 (`legacy=2`).

## [1.0.2] - 2026-11-03

### Changed

- Compatible with `lamc` 4.x: `compatibility.lamc = ">=3.0, <5"` (test runner too).

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
