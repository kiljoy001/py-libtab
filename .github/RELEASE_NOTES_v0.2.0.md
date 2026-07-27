## libtab 0.2.0

A lightweight document store in plain, greppable `.tab` files — declared
schema, deterministic ordering, and optional per-field encryption.

```
pip install libtab
```

Prebuilt wheels for Linux x86_64, CPython 3.10–3.13. No compiler needed.

### Highlights

- **One-line signing keys.** `keypair()` generates an Ed25519 signing keypair
  seeded from the OS CSPRNG — no more hand-rolling `ctypes` buffers to sign a
  field.

  ```python
  from libtab import keypair
  secret_key, public_key = keypair()
  ```

- **The public API now speaks the Tabula vocabulary.** A `.tab` file is a
  Tabula:

  | old | new |
  |-----|-----|
  | `NativeTable` | `Tabula` |
  | `NativeColumn` | `Column` |
  | `NativeRow` | `Row` |
  | `LibtabNativeError` | `TabulaError` |
  | `NativeUnavailable` | `TabulaUnavailable` |

  The old `Native*` names still work as **deprecated aliases**, so existing
  code keeps running — but migrate when you can; they'll be removed later.

- **Clearer failure when a value has an unquoted space.** `.tab` values follow
  the ndb grammar, so a value with a space must be double-quoted
  (`payee="Widget LLC"`). Opening a file that violates this now explains the
  real cause instead of reporting a baffling "undeclared column".

- **Honest packaging + description.** PyPI now states Linux x86_64 support
  explicitly, and the project describes what it is — a greppable document
  store with per-field crypto — rather than implementation details.

- **A runnable demo.** `examples/demo_tamper_evident.py` writes a signed
  payment record, forges the amount on disk, and shows the signature check
  catch it.

### Upgrading

No code changes are required — the `Native*` names still resolve. To move to
the new names, rename `NativeTable` → `Tabula`, `NativeColumn` → `Column`,
`NativeRow` → `Row`, and the two exception types as above.

---

Full details in [CHANGELOG.md](https://github.com/kiljoy001/py-libtab/blob/main/CHANGELOG.md).
