# py-libtab

**A lightweight, database-like store — without the database engine.
SQLite gave you a relational DB in a file; py-libtab gives you a
document store in files, and the files stay human-readable.**

py-libtab writes and reads `.tab` files: ordinary, human-readable text files
that behave like a small document/NoSQL collection. Each file carries a
**declared, typed schema** (the columns live *in the file itself* — nothing
external to keep in sync), rows in a **deterministic order** (so the same data
serializes byte-for-byte the same, and files diff cleanly in `git`), and, when
you want it, **per-field cryptography** — a field can be **hashed**, **signed**,
or **sealed** (encrypted), with the algorithm and parameters riding inline in
the cell. It's just a file: `cat` it, `grep` it, `git diff` it, back it up
with `cp`.

## Why this exists

If you want structured data on disk from Python, your options are usually:

- a **database** — SQLite or a server: real queries, but an opaque binary
  and an engine to run; you can't `grep` it or `git diff` it;
- a **document store** (Mongo & friends) — the document shape you want, but
  your documents are locked inside the engine, not files you can open;
- **JSON/CSV** — real files, but no declared schema, no stable ordering, and
  if you need crypto you bolt it on by hand (and probably get it subtly wrong).

There's no lightweight middle: *a document store whose documents are real,
readable files — schema and ordering built in, crypto available per field.*
That's the gap py-libtab fills. It's a **store and a format, not a query
engine**: you get attribute lookup and search over a table, not joins,
indexes, or cross-collection transactions — that's the point of having no
engine.

### Three ways to protect a field

| Type | Guarantees | Readable? | Use for |
|---|---|---|---|
| `HASHED` | integrity — irreversible digest | the digest is | checksums, content addresses, "did this change?" |
| `SIGNED` | authenticity — tamper-evident | **yes**, plaintext + signature | audit logs, signed config/release metadata |
| `sealed` | **confidentiality** — encrypted | **no**, only the key holder | API keys, tokens, anything secret at rest |

Good fits: tamper-evident audit logs whose entries you can still read · signed
release metadata · content-addressable manifests · **API-key / token vaults
where the values are sealed** but the surrounding table (ids, labels, which
key is which) stays greppable.

One caveat worth stating: `HASHED` and `SIGNED` cells are *readable by design*
— a signed value's plaintext is right there in the file. Use `sealed` for
anything that must stay secret. (And note a bare password-*hash* table, even
committed as `HASHED`, is still an offline-cracking target if it leaks — for
credentials you'd typically seal the table or keep it out of version control.)

## How it works

```
                              py-libtab
   ══════════════════════════════ WRITE ══════════════════════════════

     your Python code  —  writing a tamper-evident audit log
     ┌──────────────────────────────────────────────────────────────┐
     │ t = NativeTable.create("audit.tab", ...)                      │
     │ t.set(row, "event", "user.delete")   → plain text             │
     │ t.set_hashed(row, "payload", blob)   → BLAKE2b content hash    │
     │ t.set_signed(row, "sig", entry, sk)  → Ed25519 signature      │
     │ t.commit()                                                    │
     └───────────────┬──────────────────────────────────────────────┘
                     │ calls
                     ▼
     ┌──────────────────────────────────────────────────────────────┐
     │  native library   (audited C crypto — text parser ·          │
     │  BLAKE2b · argon2id · Ed25519 · XChaCha20-Poly1305)          │
     └───────────────┬──────────────────────────────────────────────┘
                     │ writes
                     ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  audit.tab   —  plain text: cat it · grep it · diff it in git    │
   │                                                                   │
   │   schema=audit                                                    │
   │       col=id                                                      │
   │       col=event                                                   │
   │       col=payload type=HASHED                                     │
   │       col=sig     type=SIGNED signer=ci                           │
   │                                                                   │
   │   id=2024-06-01T12:00Z-0001                                       │
   │       event=user.delete                                           │
   │       payload=hashed:AQ8Kf3...      ← self-describing: the algo,  │
   │       sig=signed:aGVsbG8=:3q2+7w...    params & salt ride inline  │
   └─────────────────────────────────────────────────────────────────┘
                     │
   ══════════════════╪═══════════ READ + VERIFY ══════════════════════
                     │ reads
                     ▼
     ┌──────────────────────────────────────────────────────────────┐
     │ t = NativeTable.open("audit.tab")                             │
     │ row = t.search("event", "user.delete")[0]                     │
     │                                                               │
     │ t.verify_hash(row, "payload", blob)  → True / False  (did the │
     │                                        payload change?)        │
     │ t.verify_signed(row, "sig", pubkey)  → entry bytes, or raises │
     │                                        if the entry was forged │
     └──────────────────────────────────────────────────────────────┘

   one representation everywhere:  on disk == on the wire == in a backup
   the file IS the data · the crypto rides inside it · you can still read it
```

## Usage

Write a tamper-evident audit log. Each entry records an event, a **content
hash** of its payload (integrity), and an **Ed25519 signature** over the entry
(provenance):

```python
from libtab import NativeTable, NativeColumn

t = NativeTable.create("audit.tab", "audit", [
    NativeColumn("id"),
    NativeColumn("event"),
    NativeColumn("payload", type="HASHED"),
    NativeColumn("sig", type="SIGNED", signer="ci"),
])
row = t.add_row("id", "2024-06-01T12:00Z-0001")
t.set(row, "event", "user.delete")
t.set_hashed(row, "payload", payload_blob)     # BLAKE2b digest of the payload
t.set_signed(row, "sig", entry_bytes, sk)      # sk = your 32-byte signing key
t.commit()
t.close()
```

The file on disk is just text — greppable, diffable in git, and every entry
carries its own verification data:

```text
schema=audit
	col=id
	col=event
	col=payload type=HASHED
	col=sig type=SIGNED signer=ci

id=2024-06-01T12:00Z-0001
	event=user.delete
	payload=hashed:AQ8Kf3...
	sig=signed:aGVsbG8=:3q2+7w...
```

Read it back and verify — the hash proves the payload wasn't altered, the
signature proves the entry is authentic (and returns the signed bytes, or
raises if it was forged):

```python
from libtab import NativeTable

t = NativeTable.open("audit.tab")
row = t.search("event", "user.delete")[0]

t.verify_hash(row, "payload", payload_blob)    # True if the payload matches
entry = t.verify_signed(row, "sig", pubkey)    # signed bytes, or raises
t.close()
```

### Sealing a secret

For values that must stay confidential, `set_sealed` encrypts the field under
a 32-byte key; only the key holder can read it back with `get_sealed`. The
surrounding table stays plain text, so you can still `grep` for a row — but
the sealed value is ciphertext on disk:

```python
import os
from libtab import NativeTable, NativeColumn

key = os.urandom(32)   # keep this out of the file

t = NativeTable.create("vault.tab", "vault", [
    NativeColumn("id"),
    NativeColumn("secret"),        # an ordinary column; sealing is per-value
])
row = t.add_row("id", "stripe-api-key")
t.set_sealed(row, "secret", b"sk-live-abc123", key)
t.commit()
t.close()
# on disk:  secret=sealed:LZ5tJO8m...   (plaintext never present)

t = NativeTable.open("vault.tab")
row = t.search("id", "stripe-api-key")[0]
t.get_sealed(row, "secret", key)              # b"sk-live-abc123"
t.get_sealed(row, "secret", os.urandom(32))   # raises — wrong key or tampered
t.close()
```

Sealing uses XChaCha20-Poly1305 with a fresh random nonce per value, so it's
also tamper-evident: a modified ciphertext fails to decrypt. The raw
`seal(key, data)` / `unseal(key, blob)` functions are exposed too if you want
to encrypt something without a table.

## The `.tab` format

A simple attribute/value text file. The first tuple declares the schema;
every later tuple is a row keyed by the first column:

```text
schema=orders
	col=id
	col=item
	col=qty

id=a
	item=widget
	qty=5

id=b
	item=gadget
	qty=3
```

Columns may be typed `HASHED` (BLAKE2b or argon2id) or `SIGNED` (Ed25519);
typed cells carry a self-describing `<type>:<base64url>` tag that includes the
algorithm, parameters, and salt, so a cell is verifiable on its own. `sealed`
cells (XChaCha20-Poly1305) use the same tag convention on an ordinary column.
Untyped columns are plain text.

The crypto is the real thing — BLAKE2b, argon2id, Ed25519, and
XChaCha20-Poly1305 from an audited C implementation, not hand-rolled `hashlib`
calls with guessed-at parameters.

## Build & install

Requires a C toolchain (`gcc`, `ar`).

```bash
cd vendor && ./build.sh          # builds the native library
cd .. && pip install .
```

The engine is compiled from vendored C sources; `pip install` links it in.
There are **no Python runtime dependencies**.

## Testing

These files carry secrets, integrity data, and provenance people rely on, so
py-libtab is tested like the security primitive it is: unit + integration
tests, **fuzzing** of the parser and the decrypt path under
**AddressSanitizer**, **crypto known-answer vectors**
(BLAKE2b/argon2id/Ed25519/XChaCha20-Poly1305 checked against independent
references), and **mutation testing** (0 surviving mutants). One command runs
everything:

```bash
./run-all-tests.sh          # fast gate
./run-all-tests.sh all      # everything, incl. fuzz + mutation
```

See [TESTING.md](TESTING.md) for the full breakdown of each layer.
