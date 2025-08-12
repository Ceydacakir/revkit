from __future__ import annotations
import argparse
from rich.console import Console
from .analyzers import Analyzer
from .disasm import disassemble
from .patcher import patch_bytes
from .patterns import find_pattern

console = Console()

def _int_auto(x: str) -> int:
    return int(x, 0)

def main():
    p = argparse.ArgumentParser(prog="revkit", description="Educational RE toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="summarize binary")
    a.add_argument("path")
    a.add_argument("--sections", action="store_true")
    a.add_argument("--imports", action="store_true")
    a.add_argument("--entropy", action="store_true")
    a.add_argument("--strings", action="store_true")
    a.add_argument("--max-strings", type=int, default=40)

    d = sub.add_parser("disasm", help="disassemble a range")
    d.add_argument("path")
    d.add_argument("--start", type=_int_auto, required=True)
    d.add_argument("--size", type=_int_auto, required=True)
    d.add_argument("--arch", choices=["x86"], default=None)
    d.add_argument("--mode", type=int, choices=[32, 64], default=None)

    pa = sub.add_parser("patch", help="patch bytes at offset")
    pa.add_argument("path")
    pa.add_argument("--offset", type=_int_auto, required=True)
    pa.add_argument("--bytes", required=True, help="hex bytes like '90 90'")
    pa.add_argument("--out", required=True)

    f = sub.add_parser("find", help="find wildcard byte pattern")
    f.add_argument("path")
    f.add_argument("--pattern", required=True)

    args = p.parse_args()

    if args.cmd == "analyze":
        ana = Analyzer(args.path)
        ana.summary(show_sections=args.sections, show_imports=args.imports, show_entropy=args.entropy, show_strings=args.strings, max_strings=args.max_strings)
    elif args.cmd == "disasm":
        disassemble(args.path, args.start, args.size, args.arch, args.mode)
    elif args.cmd == "patch":
        patch_bytes(args.path, args.offset, args.bytes, args.out)
        console.print(f"[green]Wrote:[/] {args.out}")
    elif args.cmd == "find":
        with open(args.path, "rb") as f:
            data = f.read()
        hits = find_pattern(data, args.pattern)
        for off in hits:
            console.print(f"hit @ 0x{off:x}")
        if not hits:
            console.print("no hits")

if __name__ == "__main__":
    main()
