# Testing py-libtab

py-libtab is a `ctypes` binding over a real C library (`libtab.c` +
monocypher) that parses untrusted `.tab` files and does cryptography. That
shape drives the testing strategy: the interesting failure modes are
**memory-unsafety in the C parser reachable from a crafted file**,
**crypto that is wrong but doesn't crash**, and **a thin Python marshaling
layer whose bugs degrade to a segfault rather than a clean exception**.
The suite is built in layers, each targeting one of those.

## TL;DR

```bash
./run-all-tests.sh              # standard gate: unit lint dup sast audit  (fast, ~10s)
./run-all-tests.sh all          # every layer, including fuzz + mutation (~5 min)
./run-all-tests.sh fuzz mutation   # just the named layers
./run-all-tests.sh --list       # list layer names
```

A missing **optional** tool (pmd, atheris, gcc/libasan, mutmut) skips that
layer with a warning; it does not fail the run. A layer that *can* run and
fails makes the whole script exit non-zero.

## One-time setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[test,security]"
(cd vendor && ./build.sh)              # builds vendor/libtab.so
(cd vendor && SANITIZE=1 ./build.sh)   # builds vendor/libtab-asan.so (for fuzzing)
```

`vendor/build.sh` compiles the vendored `libtab.c` against a
position-independent rebuild of the plan9port libraries it needs, into
`vendor/libtab.so`. Requires a C toolchain (`gcc`, `ar`). The `SANITIZE=1`
variant adds AddressSanitizer + UndefinedBehaviorSanitizer and produces
`vendor/libtab-asan.so`, which the fuzzer loads.

Every test module skips itself cleanly if `vendor/libtab.so` isn't built.

## The layers

| Layer | Tool | What it catches | Speed |
|---|---|---|---|
| `unit` | pytest | correctness of the ctypes binding, error paths, crypto vectors, SAST gate | fast |
| `coverage` | pytest-cov | untested lines | fast |
| `lint` | ruff | style / obvious defects | instant |
| `dup` | PMD/CPD | copy-paste duplication | instant |
| `sast` | bandit | dangerous Python patterns (eval/shell/pickle) | instant |
| `audit` | pip-audit | vulnerable dependencies | fast (network) |
| `fuzz` | atheris + ASan | memory-unsafety in the C parser on crafted input | short by default |
| `mutation` | mutmut | tests that pass but don't actually assert anything | slow (~4 min) |

### unit + integration — `pytest`

The bulk of the suite (~180 tests across `tests/test_*.py`). Beyond happy
paths, these deliberately exercise:

- **Every error path** (`test_native_errors.py`, `test_native_error_context.py`)
  — a wrong argtype or unchecked nil return in a ctypes binding degrades to
  a segfault or silent data corruption, not an exception, so each failure
  path is driven and its raised message asserted.
- **Use-after-free / use-after-close guards** (`test_native_closed_table.py`,
  `test_native_defensive.py`) — `tab_close`/`tab_remove_row` free the
  underlying C struct; the Python wrapper must reject a stale handle rather
  than let it reach C.
- **The null-rejection FFI guards** (`test_native_nonnull_handle.py`,
  `test_native_bytes_validation.py`) — `_NonNullHandle`/`_NonNullCharP`/
  `_NonNullIntP` reject `None` at the ctypes dispatch boundary before it
  can segfault libtab.
- **Exact ctypes signatures** (`test_native_ffi_signatures.py`) — asserts
  the `restype`/`argtypes` of every bound function, so a change that
  silently drops a guard or corrupts marshaling fails.
- **`test_aaa_subprocess_smoke.py`** — the `aaa` prefix makes it collect
  first. It runs the crash-prone flows in a **child process** so that a
  segfault (from a disabled guard) becomes a clean parent-side returncode
  assertion instead of killing the whole test run. This is what makes the
  memory-safety guards mutation-testable.

Run directly:
```bash
.venv/bin/pytest -q
.venv/bin/pytest tests/test_native_errors.py -v    # one module, verbose
```

### crypto known-answer vectors — `tests/test_crypto_vectors.py`

Distinct from "set then verify round-trips" (which would pass even if the
crypto were self-consistently wrong). These check the C primitives produce
the *correct, specific* output against an independent reference:

- **BLAKE2b** vs Python's stdlib `hashlib.blake2b` (the reference impl) —
  exact match.
- **argon2id** vs `argon2-cffi`'s `hash_secret_raw` with the same params +
  salt recovered from the cell — exact match.
- **Ed25519** — monocypher uses a **BLAKE2b-based EdDSA variant, not RFC
  8032 SHA-512**, so there is no external reference; the test asserts
  sign→check consistency and pins a known seed's public key + signature as
  a regression vector, so any future change to monocypher's output fails
  loudly.

(These live inside the `unit` layer — they're ordinary pytest tests.)

### fuzz + sanitizer — `tests/fuzz/`

The highest-value security layer, because a `.tab` file is untrusted input
that flows straight into the C parser. Coverage-guided fuzzing with
[atheris](https://github.com/google/atheris) against `NativeTable.open()`
and `b64_decode()`.

Run in **two phases** (why: atheris's bundled libFuzzer and ASan fight over
signal/coverage handling when preloaded together, producing spurious
non-reproducible crashes — so fuzzing and sanitizing are separated):

```bash
tests/fuzz/run.sh fuzz open              # coverage-guided fuzz vs the normal build
tests/fuzz/run.sh fuzz open -max_total_time=600   # a real campaign
tests/fuzz/run.sh replay open            # replay the whole corpus under ASan
tests/fuzz/run.sh fuzz b64               # same for the base64 decoder
tests/fuzz/run.sh replay b64
```

Phase 1 (`fuzz`) grows `tests/fuzz/corpus_<target>/` with any input reaching
new code and reports Python-level crashes/hangs. Phase 2 (`replay`) re-runs
every corpus input through `libtab-asan.so`, turning a one-byte over-read
into a located AddressSanitizer report. `tests/test_fuzz_smoke.py` runs a
tiny budget of both as part of the normal suite, so the tooling itself is
regression-tested.

Current status: 100k+ fuzzed inputs per target plus ASan replay find **no
memory-safety issues** in libtab's parser.

### mutation testing — `mutmut`

The layer that tests *the tests*. mutmut mutates `libtab/native.py` one
change at a time and checks the suite still fails; a surviving mutant means
a change that no test noticed — a real assertion gap (or a provably
equivalent mutant, handled below).

```bash
./run-all-tests.sh mutation      # automated (handles the mutants/vendor dance)
# or manually:
rm -rf mutants .mutmut-cache
.venv/bin/mutmut run --max-children 1   # generates mutants/ (stats step fails — ignore)
ln -sf ../vendor mutants/vendor         # tests resolve vendor/libtab.so relative to themselves
.venv/bin/mutmut run                    # the real run
.venv/bin/mutmut results --all true | grep -oE ': [a-z]+$' | sort | uniq -c
```

**Current status: 468 killed, 0 survived, 0 segfault.**

Notes learned the hard way, encoded in the tests and `native.py`:

- **Coverage association**: mutmut only runs a mutant against tests whose
  *own execution* touched the mutated code. Import-time code (`_load`,
  `_get_lib`) is nearly untested unless a test forces it to re-run inside
  itself — see the function-scoped `lib()` fixture in
  `test_native_ffi_signatures.py`.
- **The `mutants/vendor` symlink** must exist inside the generated tree or
  every test skips (they can't find `libtab.so`).
- **Equivalent mutants** (e.g. `rc != 0` → `rc != 1` where `_check_error`
  is a no-op on success either way; message-string text; `c_int(0)` an out-
  param the C code overwrites) can't be killed by any test. Those are either
  rewritten to remove the class by construction (`rc != 0` → `if rc:`) or
  marked `# pragma: no mutate` with a justifying comment. Every pragma is
  audited to be diagnostic-text / proven-equivalent only — never a path,
  sentinel, context string, or validation name.

### lint / duplication / SAST / audit

- **ruff** (`lint`) — style and common defects. `PYI034` is ignored on
  purpose (see `pyproject.toml`): the explicit `NativeTable` `__enter__`
  return keeps the module valid on Python 3.10 without a runtime
  `typing_extensions` dependency.
- **PMD/CPD** (`dup`) — copy-paste detection. Reports source-level
  duplication; it does not fail the gate on cosmetic test-fixture
  duplication. Needs `pmd` + Java on PATH.
- **bandit** (`sast`) — Python static analysis. Expected to find nothing
  (no `eval`/shell/`pickle`/`yaml.load` on untrusted data); kept as a cheap
  regression gate. Also runs inside the suite as `test_security_gates.py`.
- **pip-audit** (`audit`) — dependency advisories. Near-no-op today (zero
  runtime dependencies — pure ctypes), but the gate belongs in CI for when
  packaging deps land. `tests/security/check.sh` runs bandit + pip-audit
  together.

## Known gaps / not-yet-covered

- **Property-based tests** (hypothesis is installed) are not currently
  wired — they existed for the deleted pure-Python engine and haven't been
  re-added for the ctypes binding. A generative `.tab`-grammar strategy
  would complement the fuzzer.
- **SMT / formal** (z3, Coq) — out of scope for a format binding; the C
  parser's memory safety is covered dynamically by fuzz + ASan instead.

## CI shape

The intended gate: `./run-all-tests.sh all` on a runner with `gcc`, Java,
and the `.[test,security]` extra installed. `mutation` and a longer `fuzz`
budget are the slow parts; a fast PR gate can run `./run-all-tests.sh
standard` and defer `all` to a nightly job.
