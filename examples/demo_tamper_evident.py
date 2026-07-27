#!/usr/bin/env python3
"""
libtab demo — a plain-text record you can read, but can't forge.

Run it:   python examples/demo_tamper_evident.py

The story, in one screen:
  1. Write a payment record to a .tab file. The amount is SIGNED and a
     secret token is SEALED (encrypted).
  2. cat the file: it's ordinary text — labels and structure are readable,
     the secret is ciphertext.
  3. Read it back: the signature verifies, the secret decrypts with the key.
  4. A forger edits the amount on disk (1000 -> 9000) with a text editor.
  5. Read it back again: the signature check FAILS. The file caught the edit.

No database, no server. Just a file. pip install libtab.
"""
import os
import tempfile
import time

from libtab import Column, Tabula, keypair, native

# ── colours for a recordable terminal ─────────────────────────────────
G, R, Y, C, DIM, B, X = (
    "\033[32m", "\033[31m", "\033[33m", "\033[36m", "\033[2m", "\033[1m", "\033[0m"
)


def pause(seconds: float = 1.4) -> None:
    """A beat between steps so a screen recording is readable."""
    time.sleep(seconds)


def step(n: int, title: str) -> None:
    print(f"\n{B}{C}[{n}] {title}{X}")
    pause(0.6)


def main() -> None:
    path = os.path.join(tempfile.mkdtemp(), "payment.tab")
    # The CFO holds the secret key and signs the amount; anyone with the
    # public key can verify it, but nobody can forge a new signature.
    cfo_sk, cfo_pk = keypair()
    vault_key = os.urandom(32)  # symmetric key for the sealed secret

    print(f"{B}libtab — a text file that catches forgery{X}")
    print(f"{DIM}a signed payment record you can read but cannot edit{X}")

    # ── 1. write ──────────────────────────────────────────────────────
    step(1, "Write a payment record")
    t = Tabula.create(path, "payments", [
        Column("payee"),
        Column("amount", type="SIGNED", signer="cfo"),   # signed by the CFO
        Column("account_token"),                          # will be sealed
    ])
    row = t.add_row("payee", "Widget-LLC")
    t.set_signed(row, "amount", b"1000", cfo_sk)               # CFO signs "1000"
    t.set_sealed(row, "account_token", b"acct_9f3a-SECRET", vault_key)
    t.commit()
    t.close()
    print(f"  wrote {C}{path}{X}")

    # ── 2. cat it ─────────────────────────────────────────────────────
    step(2, "It's just text — cat it")
    with open(path) as fh:
        print(DIM + "".join("    " + line for line in fh) + X)
    print(f"  {G}✔{X} the schema and payee are readable")
    print(f"  {G}✔{X} amount is plaintext {B}+{X} a signature")
    print(f"  {G}✔{X} the token is {B}sealed{X} — ciphertext, unreadable without the key")
    pause()

    # ── 3. read it back honestly ──────────────────────────────────────
    step(3, "Read it back — everything checks out")
    t = Tabula.open(path)
    r = t.search("payee", "Widget-LLC")[0]
    amount = t.verify_signed(r, "amount", cfo_pk)              # raises if forged
    token = t.get_sealed(r, "account_token", vault_key)
    t.close()
    print(f"  {G}✔ signature valid{X} — CFO-signed amount = {B}{amount.decode()}{X}")
    print(f"  {G}✔ secret decrypted{X} with the key = {B}{token.decode()}{X}")
    pause()

    # ── 4. a forger edits the file ────────────────────────────────────
    step(4, "A forger opens the file and changes 1000 → 9000")
    import base64
    with open(path) as fh:
        text = fh.read()
    old = base64.urlsafe_b64encode(b"1000").decode().rstrip("=")   # MTAwMA
    new = base64.urlsafe_b64encode(b"9000").decode().rstrip("=")   # OTAwMA
    with open(path, "w") as fh:
        fh.write(text.replace(old, new))
    print(f"  {Y}edited the amount cell on disk (no key needed to type){X}")
    pause()

    # ── 5. the file catches it ────────────────────────────────────────
    step(5, "Read it back again")
    t = Tabula.open(path)
    r = t.search("payee", "Widget-LLC")[0]
    try:
        t.verify_signed(r, "amount", cfo_pk)
        print(f"  {R}(should not reach here){X}")
    except native.TabulaError as e:
        print(f"  {R}{B}>>> SIGNATURE CHECK FAILED <<<{X}")
        print(f"  {R}✘ the file rejected the forged amount{X}")
        print(f"    {DIM}{e}{X}")
    finally:
        t.close()

    print(f"\n{B}{G}The record proved its own tampering — from a plain text file.{X}")
    print(f"{DIM}No database. No server. pip install libtab.{X}\n")
    os.remove(path)


if __name__ == "__main__":
    main()
