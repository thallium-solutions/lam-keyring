# @lam/keyring

`@lam/keyring` seals secrets at rest for the
[Lammergeier programming language](https://github.com/thallium-solutions/lammergeier-lang)
([lammergeier-lang.dev](https://lammergeier-lang.dev)): TOTP seeds, OAuth/SSO
client secrets, API tokens, import credentials and per-tenant data keys that
an application must store in its database and read back later.

Values are encrypted with AES-256-GCM under a **key ring**: every value
records the id of the key that sealed it, so keys can rotate without a flag
day, and a `Resealer` re-encrypts stored values in batches afterwards.
Values can be bound to their row (associated data), rings can be scoped to
a purpose, and data keys can be wrapped for envelope encryption. Only the
Go standard library is used.

## Why not `lamcrypto`?

`Crypto.encrypt` in the standard library is a good one-shot primitive, but
secrets at rest need more around it: key ids in the value, several keys open
while one seals, a way to find and re-encrypt values sealed with old keys,
protection against copying a ciphertext from one row to another, and clear
errors when something is off. That is this package. Its format is not the
`lamcrypto:v1:` envelope; it is the `v2:<keyId>:...` format described below,
which existing applications already store.

## Features

- `KeyRing.parse("k2=<hex>;k1=<hex>")`, `KeyRing.fromEnv(...)`: 32-byte keys
  with ids; the primary key seals, every key opens.
- `seal(plaintext, aad="")` / `open(sealed, aad="")` with AES-256-GCM, random
  96-bit nonces and optional associated data binding a value to its
  table, column and row.
- Error kinds you can act on: `KeyNotFound`, `Corrupted`,
  `WrongAssociatedData` (plus `InvalidKey` for configuration problems).
- Rotation: `needsReseal`, `reseal`, `rebind`, and a `Resealer` that pages
  through a table with compare-and-swap writes and reports counts.
- Purpose-scoped subkeys (`forPurpose("totp")`) derived with HKDF.
- Envelope encryption: `wrapKey`/`unwrapKey`/`newWrappedKey`/`unwrapRing`
  for per-tenant or per-file data keys.
- Key derivation: HKDF-SHA256 (`KeyRing.derive`), PBKDF2-HMAC-SHA256 for
  password keys (`KeyRing.fromPassword`), and the legacy HMAC-SHA256
  derivation of older applications (`KeyRing.deriveLegacy`,
  `KeyRing.withFallback`).
- `KeyRing.generateKey()`, `KeyRing.inspect(sealed)`,
  `KeyRing.constantTimeEquals(a, b)`.
- Immutable rings: safe to share between goroutines.

## Requirements

- `lamc` 2.1 or newer (`>=2.1, <4`).
- A Go toolchain with `crypto/hkdf` and `crypto/pbkdf2` (Go 1.24 or newer).
- No Go module dependencies.

## Installation

Add the release to `lamlib.toml`:

```toml
[dependencies]
"@lam/keyring" = { git = "https://github.com/thallium-solutions/lam-keyring.git", ref = "1.0.0" }
```

or install it directly:

```bash
lamc install https://github.com/thallium-solutions/lam-keyring.git@1.0.0
lamc install ../lam-keyring          # a local checkout
```

Every form installs to `extlibs/@lam/keyring`:

```lammergeier
from @lam/keyring import KeyRing, Resealer, ResealReport, SealedItem
```

## Quick start

Generate a key (`openssl rand -hex 32`, or `KeyRing.generateKey()`) and keep
it in your secret store, for example `APP_KEYS=k1:<64 hex characters>`.

```lammergeier
from @lam/keyring import KeyRing
from lamerrors import Result

func storeAndRead(ring: KeyRing) -> Result[str] {
    sealed: str = ring.seal("JBSWY3DPEHPK3PXP", "accounts.mfa_secret:42")?
    # ... store ``sealed`` in accounts.mfa_secret for row 42 ...
    return ring.open(sealed, "accounts.mfa_secret:42")
}

func main() {
    do {
        ring: KeyRing = KeyRing.fromEnv("APP_KEYS")?
        print(storeAndRead(ring)?)
    } catch err {
        print(f"keyring: {err}")
    }
}
```

## Format

A **key** is 32 random bytes, written as 64 hexadecimal characters. A
**key id** is a non-empty string without whitespace, control characters or
any of `: ; , =`.

A **ring spec** lists keys, primary first unless `primary` says otherwise:

```text
spec    = [ "ring:" ] entry *( ( ";" / "," ) entry )
entry   = [ id ( "=" / ":" ) ] hexkey        ; whitespace around parts is ignored
hexkey  = 64 HEXDIG                          ; either case
```

`k2=<hex>;k1=<hex>`, `ring:k2=<hex>;k1=<hex>` and `k2:<hex>,k1:<hex>` are the
same ring. At most one entry may omit the id: that is the **unlabelled**
(legacy) key.

A **sealed value** is ASCII text in one of three forms (`base64` is standard
base64 with padding, RFC 4648 section 4; `||` is concatenation):

| Form | Written when | Layout |
|---|---|---|
| legacy | the primary key is unlabelled | `base64(nonce \|\| ciphertext \|\| tag)` |
| `v2` | no associated data | `v2:<keyId>:base64(nonce \|\| ciphertext \|\| tag)` |
| `v3` | with associated data | `v3:<keyId>:base64(check \|\| nonce \|\| ciphertext \|\| tag)` |

- Cipher: AES-256-GCM, `nonce` = 12 random bytes (crypto/rand), `tag` = 16
  bytes. The GCM additional data is empty for legacy and `v2` values and the
  associated data bytes for `v3`. A sealed value is
  `ceil((len(plaintext) + 28 [+ 8]) / 3) * 4` characters plus its prefix.
- `check` (`v3` only, 8 bytes) =
  `HMAC-SHA256(HKDF-SHA256(ikm = root key, salt = "", info = "lam-keyring/v1/aad-check", L = 32), aad)[0:8]`,
  where the root key is the ring key before any purpose derivation. It lets
  `open` tell `WrongAssociatedData` apart from `Corrupted`; integrity comes
  from the GCM tag.
- A legacy value has no key id: `open` tries every key of the ring in order.
- **Purpose subkeys**: `forPurpose(p)` replaces every key `K` with
  `HKDF-SHA256(ikm = K, salt = "", info = "lam-keyring/v1/purpose/" + p, L = 32)`
  under the same id; nested purposes apply this repeatedly. Purpose values
  use the same three forms.
- **Wrapped data keys** are ordinary sealed values whose plaintext is the
  data key as 64 lowercase hexadecimal characters.
- **Derivations** (outputs are keys): `KeyRing.derive(secret, label, id, salt)` =
  `HKDF-SHA256(ikm = secret, salt, info = label, L = 32)`;
  `KeyRing.deriveLegacy(secret, label)` = `HMAC-SHA256(key = secret, message = label)`;
  `KeyRing.fromPassword(password, saltHex, id, iterations = 600000)` =
  `PBKDF2-HMAC-SHA256(password, salt, iterations, L = 32)`.

### Compatibility with SecretBox values

The legacy and `v2` forms are byte-compatible with the `SecretBox` of the
managed-file-transfer application, from which this package was extracted:
its values open here and values sealed here open there (see
`tests/test_keyring_mft.lam` and `tests/interop/`). Its configuration maps to:

```lammergeier
from @lam/keyring import KeyRing
from lamerrors import Result
from lamenv import Env

#- DATA_ENCRYPTION_KEYS ("id:hex,id:hex", first seals) plus the key derived
   from JWT_SECRET under the id ``legacy``; without DATA_ENCRYPTION_KEYS only
   the derived (unlabelled) key, which keeps writing legacy values. -#
func secretsRing() -> Result[KeyRing] {
    return KeyRing.withFallback(Env.getOr("DATA_ENCRYPTION_KEYS", ""), Env.getOr("JWT_SECRET", ""), "mft:secret-box:v1")
}

func main() {
    print(secretsRing().ok())
}
```

Differences: invalid `DATA_ENCRYPTION_KEYS` entries are an `InvalidKey`
error instead of being skipped, and values with associated data use the new
`v3` form, which `SecretBox` cannot open.

## API reference

All fallible operations return `Result[T]`; the error `kind` is one of the
kinds below.

| Error kind | Meaning |
|---|---|
| `InvalidKey` | bad ring spec, key, id, derivation input, or an operation the ring cannot do (e.g. associated data with an unlabelled primary key, exporting a purpose ring) |
| `KeyNotFound` | the value names a key id that is not in the ring (or `primary`/`withPrimary`/`without` names a missing key) |
| `Corrupted` | malformed value, tampered value, wrong key material or wrong purpose |
| `WrongAssociatedData` | the value was sealed with different associated data, with associated data while none was given, or without it while some was given |
| `CryptoError` | the platform failed (crypto/rand) |

### `KeyRing`

Construction (static):

| Method | Result |
|---|---|
| `KeyRing.parse(spec, primary="")` | `Result[KeyRing]`: parse a ring spec; `primary` selects the sealing key (default: the first entry) |
| `KeyRing.fromEnv(name, primary="")` | `Result[KeyRing]`: parse environment variable `name` (`InvalidKey` when unset) |
| `KeyRing.single(id, hexKey)` | `Result[KeyRing]`: a one-key ring (`id` empty = unlabelled) |
| `KeyRing.derive(secret, label, id="derived", salt="")` | `Result[KeyRing]`: one HKDF-SHA256 key from a high-entropy secret |
| `KeyRing.deriveLegacy(secret, label, id="")` | `Result[KeyRing]`: one HMAC-SHA256(secret, label) key, unlabelled by default |
| `KeyRing.fromPassword(password, saltHex, id="password", iterations=600000)` | `Result[KeyRing]`: one PBKDF2-HMAC-SHA256 key; the salt is at least 16 bytes, store it next to the data |
| `KeyRing.withFallback(spec, fallbackSecret, label, fallbackId="legacy")` | `Result[KeyRing]`: `spec` plus a legacy-derived key; with an empty `spec`, only the unlabelled derived key |
| `KeyRing.generateKey()` | `str`: a new random key (64 hex characters) |
| `KeyRing.inspect(sealed)` | `Result[SealedInfo]`: `version` (`legacy`, `v2`, `v3`), `keyId`, `boundToAad`, without opening |
| `KeyRing.constantTimeEquals(a, b)` | `bool`: compare tokens/MACs/codes in constant time |

Sealing and rotation:

| Method | Result |
|---|---|
| `seal(plaintext, aad="")` | `Result[str]`: seal with the primary key (`v2`, `v3` with `aad`, legacy for an unlabelled primary) |
| `open(sealed, aad="")` | `Result[str]`: open a value sealed by any key of the ring |
| `needsReseal(sealed)` | `bool`: not sealed with the primary key (`false` for empty values and for rings whose primary is unlabelled) |
| `reseal(sealed, aad="")` | `Result[str]`: re-encrypted with the primary key when needed, else unchanged |
| `rebind(sealed, fromAad, toAad)` | `Result[str]`: open with `fromAad`, seal with `toAad` (bind old values to their row, follow a changed id) |

Envelope keys:

| Method | Result |
|---|---|
| `wrapKey(dataKeyHex, aad="")` | `Result[str]`: seal a 32-byte data key |
| `unwrapKey(wrapped, aad="")` | `Result[str]`: the data key (64 lowercase hex characters) |
| `newWrappedKey(aad="")` | `Result[WrappedKey]`: a fresh data key (`key`) and its sealed form (`wrapped`) |
| `unwrapRing(wrapped, id, aad="")` | `Result[KeyRing]`: the unwrapped data key as a one-key ring |

Ring changes (each returns a new ring; the receiver is unchanged):

| Method | Result |
|---|---|
| `add(id, hexKey)` | `Result[KeyRing]`: a non-primary key appended |
| `merge(other)` | `Result[KeyRing]`: the keys of `other` appended |
| `withPrimary(id)` | `Result[KeyRing]`: `id` seals |
| `without(id)` | `Result[KeyRing]`: retire a non-primary key |
| `forPurpose(purpose)` | `KeyRing`: purpose subkeys (throws `ValueError` for an empty purpose) |

Inspection: `primaryId()`, `ids()`, `has(id)`, `size()`, `purpose()`,
`toSpec() -> Result[str]` (the keys, primary first; a secret; refused for
purpose rings) and `str(ring)`, which never shows key material.

### `KeyDerivation`

Static helpers returning lowercase hex: `hkdf(secret, salt, info, length=32)`,
`hkdfHex(secretHex, saltHex, infoHex, length=32)`, `pbkdf2(password, saltHex,
iterations, length=32)` (all `Result[str]`), `legacyHmac(secret, label)` and
`randomHex(size=16)` (`str`).

### `Resealer`, `SealedItem`, `ResealReport`

`Resealer(ring, dryRun=False, stopOnError=False)` re-encrypts values that are
not sealed with the primary key of `ring`:

| Method | Result |
|---|---|
| `values(values, aad="")` | `Result[ResealReport]`: reseal a list sharing one `aad`; `report.values` holds the output in input order |
| `items(items)` | `Result[ResealReport]`: reseal `SealedItem`s in place |
| `run(fetch, store, batchSize=500)` | `Result[ResealReport]`: page through stored values (below) |
| `process(item)` | `Result[bool]`: one item; `true` when it changed |
| `needsWork(item)` | `bool` |

`SealedItem(id, sealed, aad="")` is one stored value; `rebindTo(aad)` asks for
a different associated data on the new value. After processing,
`item.resealed`, `item.changed` and `item.problem` describe the outcome.

`run` calls `fetch(afterId, limit) -> Result[list[SealedItem]]` with `""`
first and then the id of the last item of the previous page; return up to
`limit` items with a greater id, ordered by id. It calls
`store(item) -> Result[bool]` for each changed item: write `item.resealed`
only where the column still holds `item.sealed` and return whether a row
changed. A `false` counts as a conflict (someone else wrote the row; run
again). Errors returned by `fetch` or `store` stop the run.

`ResealReport` has `scanned`, `resealed`, `unchanged`, `failed`,
`conflicts`, `batches`, `errors` (`"<id>: <kind>: <message>"`), `values`,
`ok()` (no failures) and `add(other)`. Values that do not open are counted
as `failed` and left as they are, unless `stopOnError` makes the first one
fail the run. A dry run counts what would be resealed without sealing or
calling `store`.

## Examples

### A database column bound to its row

Bind each value to its table, column and row id. A value copied into
another row (by an attacker with write access to the database, or by a
bug) then fails with `WrongAssociatedData` instead of yielding another
user's secret.

```lammergeier
from @lam/keyring import KeyRing
from lamdb import Db
from lamerrors import Result, Error

func mfaAad(accountId: str) -> str {
    return f"accounts.mfa_secret_sealed:{accountId}"
}

func saveMfaSecret(db: Db, ring: KeyRing, accountId: str, secret: str) -> Result[bool] {
    sealed: str = ring.seal(secret, mfaAad(accountId))?
    _ = db.exec("UPDATE accounts SET mfa_secret_sealed = ? WHERE id = ?", [sealed, accountId])?
    return Result.Ok(True)
}

func loadMfaSecret(db: Db, ring: KeyRing, accountId: str) -> Result[str] {
    rows: list[dict[str, any]] = db.query("SELECT mfa_secret_sealed AS sealed FROM accounts WHERE id = ?", [accountId])?
    if len(rows) == 0 {
        return Result.Err(Error("NotFound", f"account {accountId}"))
    }
    sealed: str = str(rows[0]["sealed"])
    opened: Result[str] = ring.open(sealed, mfaAad(accountId))
    if not opened.ok() and opened.error.kind == "WrongAssociatedData" {
        return Result.Err(Error("Tampered", f"the MFA secret of account {accountId} belongs to another row"))
    }
    return opened
}

func main() {
    pass
}
```

### Rotating a key and resealing in batches

1. Generate a key and put it **in front** of the ring:
   `APP_KEYS=k2:<new>,k1:<old>`. With several instances, roll out in two
   steps so no instance meets a key it does not know: first deploy the new
   key as a non-primary key everywhere (`KeyRing.fromEnv("APP_KEYS", "k1")`
   or `k1:<old>,k2:<new>`), then make it primary.
2. Run the resealer for every sealed column (below) until a run reports
   `resealed=0 failed=0 conflicts=0`. A `Resealer(ring, dryRun = True)` run
   answers "is anything left?" without writing.
3. Remove the old key from the ring. Keep it archived for as long as you
   keep database backups taken before step 2: they still need it.

A compromised key follows the same steps, as fast as possible; the old key
stays readable to anyone who has it, so also rotate any secret it protected.

```lammergeier
from @lam/keyring import KeyRing, Resealer, ResealReport, SealedItem
from lamdb import Db
from lamerrors import Result

#- Reseals one ``table.column`` whose values are bound to
   ``"<table>.<column>:<id>"``. Ids are compared as text: use a key that
   sorts as text (UUIDs) or adapt the queries. -#
func resealColumn(db: Db, ring: KeyRing, table: str, column: str, batchSize: int = 500) -> Result[ResealReport] {
    fetch: func(str, int) -> Result[list[SealedItem]] = lambda(afterId: str, limit: int) -> Result[list[SealedItem]]: fetchPage(db, table, column, afterId, limit)
    store: func(SealedItem) -> Result[bool] = lambda(item: SealedItem) -> Result[bool]: storeItem(db, table, column, item)
    return Resealer(ring).run(fetch, store, batchSize)
}

func fetchPage(db: Db, table: str, column: str, afterId: str, limit: int) -> Result[list[SealedItem]] {
    rows: list[dict[str, any]] = db.query(f"SELECT id::text AS id, {column} AS sealed FROM {table} WHERE {column} <> '' AND id::text > ? ORDER BY id::text LIMIT ?", [afterId, limit])?
    page: list[SealedItem] = []
    for row in rows {
        id: str = str(row["id"])
        page.append(SealedItem(id, str(row["sealed"]), f"{table}.{column}:{id}"))
    }
    return Result.Ok(page)
}

func storeItem(db: Db, table: str, column: str, item: SealedItem) -> Result[bool] {
    # Compare-and-swap: only replace the value we read.
    changed: int = db.exec(f"UPDATE {table} SET {column} = ? WHERE id::text = ? AND {column} = ?", [item.resealed, item.id, item.sealed])?
    return Result.Ok(changed == 1)
}

func main() {
    do {
        db: Db = Db.connect("postgres", "postgres://app@localhost/app")?
        ring: KeyRing = KeyRing.fromEnv("APP_KEYS")?
        total: ResealReport = ResealReport()
        for column in [["accounts", "mfa_secret_sealed"], ["tenant_sso", "client_secret_sealed"]] {
            report: ResealReport = resealColumn(db, ring, column[0], column[1])?
            print(f"{column[0]}.{column[1]}: {report}")
            total.add(report)
        }
        print(f"done: {total.ok() and total.conflicts == 0}")
    } catch err {
        print(f"reseal failed: {err}")
    }
}
```

To bind values that were sealed without associated data while rotating,
build the items with `SealedItem(id, sealed).rebindTo(aad)`.

### Envelope keys for tenants or files

The ring wraps one data key per tenant (or per file); the data key encrypts
the tenant's data. Rotating the ring only re-wraps the small data keys, and
deleting a wrapped key makes everything sealed with it unreadable
(crypto-shredding).

```lammergeier
from @lam/keyring import KeyRing, WrappedKey
from lamerrors import Result

func tenantAad(tenantId: str) -> str {
    return f"tenants.data_key_sealed:{tenantId}"
}

#- Creates the tenant's data key; store ``wrapped`` with the tenant. -#
func createTenantKey(ring: KeyRing, tenantId: str) -> Result[str] {
    fresh: WrappedKey = ring.forPurpose("tenant-keys").newWrappedKey(tenantAad(tenantId))?
    return Result.Ok(fresh.wrapped)
}

func tenantRing(ring: KeyRing, tenantId: str, wrapped: str) -> Result[KeyRing] {
    return ring.forPurpose("tenant-keys").unwrapRing(wrapped, tenantId, tenantAad(tenantId))
}

func main() {
    do {
        ring: KeyRing = KeyRing.single("k1", KeyRing.generateKey())?
        wrapped: str = createTenantKey(ring, "acme")?
        data: KeyRing = tenantRing(ring, "acme", wrapped)?
        sealed: str = data.seal("quarterly report", "files:acme/report.csv")?
        print(data.open(sealed, "files:acme/report.csv")?)
    } catch err {
        print(f"error: {err}")
    }
}
```

`unwrapKey` returns the raw data key (64 hex characters) when another system
needs it, such as S3 SSE-C customer keys.

### Purpose-scoped subkeys

One configured ring can serve several independent uses. A value sealed for
one purpose cannot be opened as another, even under the same key id, so a
bug that passes a TOTP seed where an SSO secret is expected fails loudly.

```lammergeier
from @lam/keyring import KeyRing
from lamerrors import Result

func main() {
    do {
        ring: KeyRing = KeyRing.parse(f"k1={KeyRing.generateKey()}")?
        totp: KeyRing = ring.forPurpose("totp")
        sso: KeyRing = ring.forPurpose("sso")
        sealed: str = totp.seal("JBSWY3DPEHPK3PXP")?
        print(totp.open(sealed)?)
        wrong: Result[str] = sso.open(sealed)
        print(wrong.error.kind)
    } catch err {
        print(f"error: {err}")
    }
}
```

Rotation works the same for purpose rings: derive them from the rotated ring
(`Resealer(rotated.forPurpose("totp"))`).

## Security notes

**What it protects.** Confidentiality and integrity of stored values against
someone who can read (and possibly write) the database, its backups or
replicas but not the keys: SQL injection that reads tables, a leaked dump, a
lost backup, an over-privileged analyst. Keep the keys out of the database
and out of database backups (a secret store, environment, KMS-delivered
file).

**What it does not protect.** Anyone who can read the process memory, its
environment or the key store can open every value. Go strings are not
zeroed after use. The length of a plaintext is visible (ciphertext = 28
bytes more, 36 for `v3`); pad values first if the length matters.

**Associated data.** Without associated data a valid sealed value can be
moved between rows and still opens: an attacker who can write the database
could copy their own TOTP seed into another account. Bind values to
`table.column:id` (`v3`). Legacy and `v2` values carry no binding; rebind
them while resealing.

**Key ids and versions** are not secret. Changing them makes a value fail
(`KeyNotFound` or `Corrupted`); it never selects a key that opens it.

**The `v3` check** is a keyed 8-byte fingerprint of the associated data. It
reveals whether two values sealed under the same root key share associated
data (normally unique per row anyway), and a forged check only changes the
error kind to `WrongAssociatedData`: authentication is GCM's.

**Nonces** are 96 random bits. Keep a key below 2^32 seals (NIST SP 800-38D);
rotation every few months, or when people with key access leave, keeps you
far below that.

**Derived keys.** `derive` and `deriveLegacy` are only as strong as the
secret: use high-entropy secrets (32 random bytes). For human passwords use
`fromPassword` (PBKDF2, 600000 iterations by default, random 16+ byte salt).
A key derived from another secret (such as a JWT signing secret) couples the
two: move to dedicated keys and reseal before rotating that secret.

**Legacy values** carry no key id, so `open` tries each key, and they can
never be bound to associated data. Reseal them to `v2`/`v3`.

**Comparisons.** GCM verifies tags in constant time, the `v3` check is
compared in constant time, and `KeyRing.constantTimeEquals` is available for
your own tokens and codes.

**Errors and logs** never contain key material or plaintext. `str(ring)`
shows only key ids; `toSpec()` returns the keys and must be treated as a
secret.

## Testing

```bash
python3 tests/run_lamkeyring_tests.py --verbose
python3 tests/run_lamkeyring_tests.py --verbose --mft ../managed-file-transfer   # interop with SecretBox
lamc fmt --check .
```

The runner uses `lamc` from `PATH` (2.1 or newer), stages this checkout as
`extlibs/@lam/keyring` in a temporary directory, compiles each
`tests/test_*.lam` program without caches and compares its output with the
`# expect:` lines. The suites cover RFC 5869 HKDF and PBKDF2-HMAC-SHA256
vectors, fixtures sealed by managed-file-transfer and by an independent
Python implementation (`v3` and purpose values), tampering, wrong associated
data, rotation and resealing, envelope keys and a composed lifecycle test.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE). Release history is recorded in [CHANGELOG.md](CHANGELOG.md).
