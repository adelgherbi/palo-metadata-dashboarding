#!/usr/bin/env python3
"""
secure_blob.py - dependency-free symmetric encryption for storing notes/code
in a PUBLIC place (e.g. a public GitHub repo) without leaking the contents.

Standard library only (Python 3.6+). No pip install needed.
  - pbkdf2 (hashlib)  : derive keys from your passphrase (stdlib, portable)
  - HMAC-SHA256 (CTR) : stream cipher to encrypt the bytes
  - HMAC-SHA256 (EtM) : authentication, so a wrong passphrase or any
                        tampering is detected instead of giving garbage

Output is base64 text -> safe to commit to a public repo.
The passphrase is NEVER written to the file. Without it the content
cannot be recovered. Keep it out of the repo.

Usage:
  python3 secure_blob.py encrypt notes.md                 -> notes.md.enc
  python3 secure_blob.py decrypt notes.md.enc            -> notes.md
  python3 secure_blob.py encrypt notes.md -o blob.txt
  python3 secure_blob.py decrypt blob.txt   -o notes.md
  python3 secure_blob.py decrypt notes.md.enc -o -       (print to screen)
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import os
import sys

MAGIC = b"PKBLOB2"
SALT_LEN = 16
NONCE_LEN = 16
MAC_LEN = 32
# PBKDF2-HMAC-SHA256 key derivation. Pure stdlib hashlib -> works on macOS,
# Linux, anywhere. (scrypt is unavailable on Python builds linked against
# LibreSSL, e.g. macOS system Python.)
PBKDF2_ITERS = 600_000


def _derive_keys(passphrase, salt):
    dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt,
                             PBKDF2_ITERS, dklen=64)
    return dk[:32], dk[32:]          # (enc_key, mac_key)


def _keystream(enc_key, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(enc_key, nonce + counter.to_bytes(8, "big"),
                            hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def encrypt(plaintext, passphrase):
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    enc_key, mac_key = _derive_keys(passphrase, salt)
    ks = _keystream(enc_key, nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, ks))
    body = MAGIC + salt + nonce + ciphertext
    mac = hmac.new(mac_key, body, hashlib.sha256).digest()
    return base64.b64encode(body + mac)


def decrypt(blob_b64, passphrase):
    raw = base64.b64decode(blob_b64)
    if not raw.startswith(MAGIC):
        raise ValueError("Not a recognized encrypted blob (bad magic).")
    body, mac = raw[:-MAC_LEN], raw[-MAC_LEN:]
    off = len(MAGIC)
    salt = body[off:off + SALT_LEN]
    nonce = body[off + SALT_LEN:off + SALT_LEN + NONCE_LEN]
    ciphertext = body[off + SALT_LEN + NONCE_LEN:]
    enc_key, mac_key = _derive_keys(passphrase, salt)
    if not hmac.compare_digest(hmac.new(mac_key, body, hashlib.sha256).digest(), mac):
        raise ValueError("Wrong passphrase or corrupted/tampered file.")
    ks = _keystream(enc_key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, ks))


def main():
    ap = argparse.ArgumentParser(description="Encrypt/decrypt text for safe public storage.")
    ap.add_argument("mode", choices=["encrypt", "decrypt"])
    ap.add_argument("infile", help="input file ('-' for stdin)")
    ap.add_argument("-o", "--outfile", default=None,
                    help="output file ('-' for stdout). Default: add/remove .enc")
    args = ap.parse_args()

    data = sys.stdin.buffer.read() if args.infile == "-" else open(args.infile, "rb").read()

    pw = getpass.getpass("Passphrase: ")
    if args.mode == "encrypt":
        if pw != getpass.getpass("Confirm passphrase: "):
            print("Passphrases do not match.", file=sys.stderr)
            return 1
        out = encrypt(data, pw)
        default_out = args.infile + ".enc"
    else:
        out = decrypt(data, pw)
        default_out = args.infile[:-4] if args.infile.endswith(".enc") else args.infile + ".dec"

    target = args.outfile or default_out
    if target == "-":
        sys.stdout.buffer.write(out)
        if args.mode == "encrypt":
            sys.stdout.write("\n")
    else:
        with open(target, "wb") as f:
            f.write(out)
        print("Wrote " + target, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
