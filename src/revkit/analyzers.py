from __future__ import annotations
import os
from typing import Optional
from rich.table import Table
from rich.console import Console
from .utils import magic, iter_strings, calc_entropy

try:
    import lief  # type: ignore
except Exception:
    lief = None

console = Console()

class Analyzer:
    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self.kind = magic(path)
        self._binary = None
        if lief is not None:
            try:
                self._binary = lief.parse(path)
            except Exception:
                self._binary = None

    def summary(self, show_sections=False, show_imports=False, show_entropy=False, show_strings=False, max_strings=40):
        console.print(f"[bold]File:[/] {self.path}  [dim]({len(self.data)} bytes)[/]")
        console.print(f"[bold]Type:[/] {self.kind}")
        if show_entropy:
            ent = calc_entropy(self.data)
            console.print(f"[bold]Entropy:[/] {ent:.3f} (0-8)")
        if show_sections and self._binary is not None:
            table = Table(title="Sections")
            table.add_column("Name"); table.add_column("VA"); table.add_column("Size"); table.add_column("Entropy")
            for s in getattr(self._binary, "sections", []):
                ent = calc_entropy(bytes(s.content)) if s.size > 0 else 0.0
                table.add_row(s.name, hex(s.virtual_address), hex(s.size), f"{ent:.2f}")
            console.print(table)
        if show_imports and self._binary is not None:
            table = Table(title="Imports")
            table.add_column("Library"); table.add_column("Symbols")
            for imp in getattr(self._binary, "imported_libraries", []):
                syms = []
                for e in self._binary.get_import(imp).entries:
                    syms.append(e.name or "?")
                table.add_row(imp, ", ".join(syms[:10]) + (" ..." if len(syms) > 10 else ""))
            console.print(table)
        if show_strings:
            table = Table(title=f"Strings (max {max_strings})")
            table.add_column("Offset"); table.add_column("String")
            for i, (off, s) in enumerate(iter_strings(self.data)):
                if i >= max_strings: break
                table.add_row(hex(off), s)
            console.print(table)

    def arch_hint(self) -> Optional[tuple[str,int]]:
        if self._binary is None:
            return None
        try:
            if self._binary.format == lief.EXE_FORMATS.PE:
                if self._binary.header.machine == lief.PE.MACHINE_TYPES.AMD64:
                    return ("x86", 64)
                if self._binary.header.machine in (lief.PE.MACHINE_TYPES.I386,):
                    return ("x86", 32)
            if self._binary.format == lief.EXE_FORMATS.ELF:
                if self._binary.header.identity_class == lief.ELF.ELF_CLASS.CLASS64:
                    return ("x86", 64) if self._binary.header.machine_type == lief.ELF.ARCH.x86_64 else None
                if self._binary.header.identity_class == lief.ELF.ELF_CLASS.CLASS32:
                    return ("x86", 32) if self._binary.header.machine_type == lief.ELF.ARCH.i386 else None
        except Exception:
            return None
        return None
