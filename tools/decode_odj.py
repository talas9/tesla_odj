#!/usr/bin/env python3
"""Decode Tesla Odin ODJ (Odin Diagnostic Job) files to JSON.

Firmware ships diagnostic jobs as ``opt/odin/data/<Model>/odj/*.odj.bin``.
They are encrypted with a key that Odin itself embeds in its own code; no
other secret is involved.

Method
------
* Cipher: Fernet (AES-128-CBC + HMAC-SHA256).
* Key: PBKDF2-HMAC-SHA256, 32 bytes, 123456 iterations, over the embedded
  Odin password ``cmftubxi7wlvmh1wmbzz00vf1ziqezf6``; the result is
  urlsafe-base64-encoded to form the Fernet key.
* Two on-disk generations differ in the salt and the payload encoding:

  ===========  =============================  ==========================
  format       layout                         payload after decryption
  ===========  =============================  ==========================
  new          16-byte random salt (file[:16])  Python pickle
               + Fernet token (file[16:])
  old          Fernet token (whole file),     JSON (UTF-8)
               fixed salt ``salt_123``
  ===========  =============================  ==========================

  The new format is tried first; if decryption or decoding fails, the old
  format is tried.

Safe unpickling
---------------
The new payload is a pickle. Unpickling untrusted data can execute arbitrary
code, so a restricted ``Unpickler`` whose ``find_class`` refuses EVERY global
is used. The ODJ data is plain containers and scalars (dict, list, str, int,
float, bool, None), which pickle encodes without importing anything, so
refusing all globals loses nothing and makes decoding unable to run code.

Usage
-----
    decode_odj.py FILE.odj.bin                 # writes FILE.json next to it
    decode_odj.py DIR [--recursive]            # all *.odj.bin / *.odj in DIR
    decode_odj.py DIR --recursive --output OUT # mirror tree under OUT

Output is pretty JSON (indent=4, sorted keys) named ``<stem>.json``, where the
``.odj.bin`` / ``.odj`` suffix is stripped. Requires ``cryptography``.
"""

import argparse
import base64
import io
import json
import pickle
import sys
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ODIN_PASSWORD = b"cmftubxi7wlvmh1wmbzz00vf1ziqezf6"  # embedded in Odin's own code
ITERATIONS = 123456
SALT_LEN = 16
OLD_SALT = b"salt_123"
SUFFIXES = (".odj.bin", ".odj")


class _NoGlobalsUnpickler(pickle.Unpickler):
    """Unpickler that refuses every global, so loading cannot execute code."""

    def find_class(self, module, name):
        raise pickle.UnpicklingError(f"global {module}.{name} refused")


def _fernet(salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=ITERATIONS)
    return Fernet(base64.urlsafe_b64encode(kdf.derive(ODIN_PASSWORD)))


def _decode_new(data: bytes):
    plain = _fernet(data[:SALT_LEN]).decrypt(data[SALT_LEN:])
    return _NoGlobalsUnpickler(io.BytesIO(plain)).load()


def _decode_old(data: bytes):
    plain = _fernet(OLD_SALT).decrypt(data)
    return json.loads(plain.decode("utf-8"))


def decode(data: bytes):
    """Return the decoded object; new format first, then old."""
    try:
        return _decode_new(data)
    except Exception as new_err:
        try:
            return _decode_old(data)
        except Exception as old_err:
            raise ValueError(
                f"not a recognised ODJ file (new format: {new_err!r}; "
                f"old format: {old_err!r})") from None


def _stem(path: Path) -> str:
    for suffix in SUFFIXES:
        if path.name.endswith(suffix):
            return path.name[: -len(suffix)]
    return path.stem


def _inputs(src: Path, recursive: bool):
    if src.is_file():
        return [(src, src.parent)]
    pattern = "**/*" if recursive else "*"
    files = sorted(p for p in src.glob(pattern)
                   if p.is_file() and p.name.endswith(SUFFIXES))
    return [(p, src) for p in files]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Decode Tesla Odin ODJ files to JSON.")
    ap.add_argument("input", type=Path, help="an .odj/.odj.bin file or a directory")
    ap.add_argument("-r", "--recursive", action="store_true",
                    help="descend into subdirectories")
    ap.add_argument("-o", "--output", type=Path,
                    help="output directory (default: next to each input)")
    args = ap.parse_args(argv)

    if not args.input.exists():
        ap.error(f"not found: {args.input}")
    items = _inputs(args.input, args.recursive)
    if not items:
        print("no .odj / .odj.bin files found", file=sys.stderr)
        return 1

    ok = failed = 0
    for path, base in items:
        try:
            obj = decode(path.read_bytes())
            text = json.dumps(obj, indent=4, sort_keys=True)
        except Exception as err:
            print(f"FAIL {path}: {err}", file=sys.stderr)
            failed += 1
            continue
        out_dir = (args.output / path.parent.relative_to(base)
                   if args.output else path.parent)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{_stem(path)}.json").write_text(text)
        ok += 1
    print(f"decoded {ok}, failed {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
