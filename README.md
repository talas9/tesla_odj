# tesla_odj

Decoded ODJ (Odin Diagnostic Job) data from Tesla firmware, as JSON.

## Layout

- `firmware/<version>/<Model>/` - ODJ data decoded from that Tesla firmware image. Currently `firmware/2026.26.6.5/` with `Model3/` and `ModelY/` (no Model S/X in that image).
- `Model 3/`, `Model S/`, `Model X/`, `Model Y/` - the earlier (legacy) set, kept unchanged.

The firmware ships these files encrypted (`.odj.bin`). They were decoded with the key Odin itself embeds in its own code; no other secret is involved.

## Decoding

Tesla firmware ships ODJ files as `opt/odin/data/<Model>/odj/*.odj.bin`, encrypted with Fernet. The key is derived with PBKDF2-HMAC-SHA256 (32 bytes, 123456 iterations) from a password that Odin embeds in its own code (`cmftubxi7wlvmh1wmbzz00vf1ziqezf6`); no other secret is involved. Two on-disk formats exist:

| Format | Layout | Payload |
|---|---|---|
| Newer firmware | 16-byte per-file salt, then the Fernet token | Python pickle |
| Older firmware | whole file is the Fernet token, fixed salt `salt_123` | JSON |

The pickle is loaded with a restricted unpickler that refuses every global, so decoding cannot execute code.

`tools/decode_odj.py` reproduces the `firmware/<version>/` JSON from a firmware's ODJ files. It tries the new format first, then the old one:

```
pip install cryptography
python3 tools/decode_odj.py path/to/Model3/odj/DI.odj.bin
python3 tools/decode_odj.py path/to/Model3/odj/ --output out/Model3
python3 tools/decode_odj.py path/to/odin/data/ --recursive --output out
```

Output is pretty JSON (`indent=4`, sorted keys), named `<stem>.json`. Requires Python 3 and the `cryptography` package.
