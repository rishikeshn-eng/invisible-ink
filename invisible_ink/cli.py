"""CLI for invisible-ink.

    invisible-ink "text…"             scan text for Unicode smuggling
    echo "text" | invisible-ink -      scan stdin
    invisible-ink --clean "text…"      print the sanitised text
    invisible-ink --json "text…"       machine-readable scan result
    invisible-ink --reveal "text…"     print any hidden payload that was decoded

Exit status: 0 clean, 1 suspicious, 2 dangerous, 3 usage error.
"""
from __future__ import annotations

import argparse
import json
import sys

from .scan import scan
from .sanitize import sanitize, Policy

_EXIT = {"clean": 0, "suspicious": 1, "dangerous": 2}
_COL = {"clean": "\033[32m", "suspicious": "\033[33m", "dangerous": "\033[31m"}
_SEVCOL = {"critical": "\033[31m", "warning": "\033[33m", "info": "\033[36m"}
_ICON = {"clean": "✓", "suspicious": "⚠", "dangerous": "✗"}
_R, _D, _B = "\033[0m", "\033[2m", "\033[1m"


def _color():
    import os
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _pretty(r, color):
    def c(x):
        return x if color else ""
    out = [f"{c(_COL[r.verdict])}{c(_B)}{_ICON[r.verdict]} {r.verdict.upper()}{c(_R)}"
           f"  {c(_D)}{r.stats['length']} chars, {r.stats['invisible']} invisible"
           f"{(', scripts: ' + ', '.join(r.stats['scripts'])) if r.stats['scripts'] else ''}{c(_R)}"]
    if not r.findings:
        out.append(f"  {c(_D)}no Unicode smuggling detected{c(_R)}")
    for f in r.findings:
        out.append(f"  {c(_SEVCOL[f.severity])}●{c(_R)} [{f.severity}] {f.message}")
        if f.decoded:
            out.append(f"      {c(_B)}hidden payload:{c(_R)} {f.decoded!r}")
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(prog="invisible-ink",
                                description="Detect and remove Unicode smuggling in untrusted text.")
    p.add_argument("text", nargs="?", help="text to scan ('-' reads stdin)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--clean", action="store_true", help="print the sanitised text and exit")
    p.add_argument("--reveal", action="store_true", help="print only the decoded hidden payload")
    p.add_argument("--aggressive", action="store_true", help="also strip script-legit zero-width chars")
    p.add_argument("--map-confusables", action="store_true", help="fold Latin look-alikes to ASCII")
    p.add_argument("--quiet", "-q", action="store_true")
    a = p.parse_args(argv)

    if a.text == "-" or (a.text is None and not sys.stdin.isatty()):
        text = sys.stdin.read()
    elif a.text is None:
        p.print_help()
        return 3
    else:
        text = a.text

    if a.clean:
        pol = Policy(keep_script_zero_width=not a.aggressive, map_confusables=a.map_confusables)
        sys.stdout.write(sanitize(text, pol).cleaned)
        return 0

    r = scan(text)
    if a.reveal:
        sys.stdout.write(r.hidden_text)
        return _EXIT.get(r.verdict, 3)
    if a.json:
        print(json.dumps(r.to_json(), indent=2, ensure_ascii=False))
    elif not a.quiet:
        print(_pretty(r, _color()))
    return _EXIT.get(r.verdict, 3)


if __name__ == "__main__":
    sys.exit(main())
