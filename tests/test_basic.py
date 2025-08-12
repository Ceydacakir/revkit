import os
from revkit.utils import calc_entropy, magic

def test_entropy_zero():
    assert calc_entropy(b"") == 0.0

def test_magic_unknown(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"ABCD")
    assert magic(str(p)) == "Unknown"
