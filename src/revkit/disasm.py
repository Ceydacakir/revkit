from __future__ import annotations
from typing import Optional
from rich.console import Console
from .analyzers import Analyzer

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
except Exception:
    Cs = None

console = Console()

def disassemble(path: str, start: int, size: int, arch: Optional[str] = None, mode_bits: Optional[int] = None):
    if Cs is None:
        raise RuntimeError("capstone not installed; pip install capstone")
    ana = Analyzer(path)
    if arch is None or mode_bits is None:
        hint = ana.arch_hint()
        if hint:
            arch, mode_bits = hint
    if arch != "x86":
        raise ValueError("Only x86/x86-64 supported in this demo; pass --arch x86 --mode 32|64")
    mode = CS_MODE_64 if mode_bits == 64 else CS_MODE_32
    md = Cs(CS_ARCH_X86, mode)
    with open(path, "rb") as f:
        f.seek(start)
        code = f.read(size)
    addr = start
    for insn in md.disasm(code, addr):
        console.print(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
