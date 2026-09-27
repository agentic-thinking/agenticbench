#!/usr/bin/env python3
# Payload decoding shared by analyse_unit.py (needle scan, opaque check) and score_bench.py (L2 identifier comparison), so both
# read a body the same way. expand() can record which optional decoders it needed; the analyser stores that per record, and the
# scorer counts a record as uninspected when this host lacks one of them (brotli, zstandard), instead of comparing less text.
import base64, gzip, re, zlib

DECODERS = [("gzip", gzip.decompress), ("zlib", zlib.decompress), ("deflate", lambda x: zlib.decompress(x, -15))]
OPTIONAL = ("zstd", "brotli")          # the tools image installs both (python3-zstandard, python3-brotli)
try:
    import zstandard; DECODERS.append(("zstd", lambda x: zstandard.ZstdDecompressor().decompress(x, max_output_size=1 << 30)))
except ImportError: pass
try:
    import brotli; DECODERS.append(("brotli", brotli.decompress))
except ImportError: pass
AVAILABLE = {n for n, _ in DECODERS}
MISSING = sorted(set(OPTIONAL) - AVAILABLE)
B64 = re.compile(rb"[A-Za-z0-9+/_-]{40,}={0,2}")


def expand(b, depth=0, used=None):
    """body plus decoded variants: gzip/zlib/deflate/zstd/brotli members, base64 runs (recursively, up to 3 levels: depth 0, 1 and 2).
    used (a set), if given, collects the names of the decoders that succeeded."""
    out = [b]
    if depth > 2 or not b: return out
    for name, f in DECODERS:   # the same decoders opaque() accepts, so a body judged readable is also scanned decoded
        try: d = f(b)
        except Exception: continue
        if used is not None: used.add(name)
        out += expand(d, depth + 1, used); break
    for m in B64.finditer(b):   # the whole body: an encoded value past any cut would go unseen
        s = m.group(0)
        # standard alphabet only when every character belongs to it (b64decode would otherwise drop "-" and "_" silently and
        # succeed on the wrong bytes); a run with "-" or "_" is decoded with the URL-safe alphabet
        for dec in (lambda x: base64.b64decode(x, validate=True), base64.urlsafe_b64decode):
            try:
                d = dec(s + b"=" * (-len(s) % 4))
                if d: out += expand(d, depth + 1, used)
                break
            except Exception: pass
    return out


def opaque(b):
    """bytes the needle scan cannot read: not UTF-8 text, and no known decoding (gzip, zlib, deflate, zstd, brotli) turns them
    into UTF-8 text. Binary encodings (protobuf, msgpack, compressed or encrypted data) are counted as uninspected, never as
    'nothing found' (METHOD.md, evidence invariant)."""
    if not b: return False
    cand = [b]
    for _, f in DECODERS:
        try: cand.append(f(b))
        except Exception: pass
    for x in cand:
        try: x.decode("utf-8"); return False
        except UnicodeDecodeError: pass
    return True
