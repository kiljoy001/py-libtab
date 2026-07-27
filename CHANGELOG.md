# Changelog

All notable changes to py-libtab are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-27

### Added
- `keypair()` — generate an Ed25519 signing keypair in one call, seeded from
  the OS CSPRNG (`secrets.token_bytes`). Signing no longer requires
  hand-rolling `ctypes` buffers.
- A clearer error when opening a `.tab` file fails because a value contains an
  unquoted space: the message now names the real cause (ndb values with spaces
  must be double-quoted, e.g. `payee="Widget LLC"`) instead of a bare
  "undeclared column".
- `examples/demo_tamper_evident.py` — a short, runnable walkthrough: a signed
  payment amount is forged on disk and the signature check catches it.

### Changed
- **Public API renamed to the Tabula vocabulary.** A `.tab` file is a Tabula:
  - `NativeTable` → `Tabula`
  - `NativeColumn` → `Column`
  - `NativeRow` → `Row`
  - `LibtabNativeError` → `TabulaError`
  - `NativeUnavailable` → `TabulaUnavailable`

  The old names still work but are deprecated (see below). The internal
  `libtab.native` module keeps its name.
- Package description and README lead with what libtab is — a lightweight,
  greppable document store with a declared schema and optional per-field
  encryption — rather than implementation details.
- PyPI metadata now states Linux x86_64 support explicitly (trove
  classifiers); a source build on other platforms fails with a clear message
  instead of a cryptic compiler error.

### Deprecated
- The `Native*` names (`NativeTable`, `NativeColumn`, `NativeRow`,
  `NativeError`, `NativeUnavailable`) remain importable as aliases for the new
  Tabula names, so existing code keeps working. They will be removed in a
  future release; migrate to the new names.

## [0.1.0] - 2026-07-26

### Added
- Initial release: a ctypes binding to objective-9c's `libtab` C
  implementation for reading and writing `.tab` files.
- Typed columns: plain, `HASHED` (BLAKE2b / argon2id), and `SIGNED` (Ed25519),
  with `verify_hash` / `verify_signed`.
- `seal()` / `unseal()` and `set_sealed()` / `get_sealed()` for per-field
  confidentiality (XChaCha20-Poly1305).
- Prebuilt manylinux x86_64 wheels (CPython 3.10–3.13) — `pip install libtab`
  needs no compiler.

[0.2.0]: https://github.com/kiljoy001/py-libtab/releases/tag/v0.2.0
[0.1.0]: https://github.com/kiljoy001/py-libtab/releases/tag/v0.1.0
