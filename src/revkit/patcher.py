from __future__ import annotations

def patch_bytes(path: str, offset: int, raw_hex: str, out_path: str):
    # raw_hex: "90 90" -> bytes
    bs = bytes(int(b, 16) for b in raw_hex.strip().split())
    with open(path, "rb") as f:
        data = bytearray(f.read())
    end = offset + len(bs)
    if end > len(data):
        raise ValueError("Patch exceeds file size")
    data[offset:end] = bs
    with open(out_path, "wb") as f:
        f.write(data)
