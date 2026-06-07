#!/usr/bin/env python3
"""Rejoue les cas adversariaux de l'audit du scope guard contre le code courant.

    python tests/audit/replay.py tests/audit/cases.json

Note : ces cas sont passés à `Scope` BRUT (sans la couche de construction
`aggregate._in_patterns/_out_patterns`). Les fuites résiduelles affichées sont
neutralisées à la construction — voir docs/AUDIT_SCOPE_GUARD.md.
"""
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from bb.scope import Scope  # noqa: E402


def main(path: str) -> int:
    cases = json.load(open(path))
    leaks, false_neg, crashes, ok = [], [], [], 0
    for c in cases:
        try:
            s = Scope(in_scope=c.get("in_scope") or [], out_of_scope=c.get("out_of_scope") or [])
            actual = s.allows(c.get("target", ""))
        except Exception as e:  # noqa: BLE001
            crashes.append({**c, "error": repr(e)})
            continue
        exp = c.get("expected_allows")
        if actual == exp:
            ok += 1
        elif exp is False and actual is True:
            leaks.append({**c, "actual": actual})
        else:
            false_neg.append({**c, "actual": actual})

    def show(title, items):
        print(f"\n{'='*78}\n{title}: {len(items)}\n{'='*78}")
        for c in items:
            print(f"[{c.get('severity','?'):8}] target={c.get('target')!r}  "
                  f"attendu={c.get('expected_allows')} obtenu={c.get('actual','CRASH')}")
            print(f"   in={c.get('in_scope')}  out={c.get('out_of_scope')}")

    print(f"TOTAL {len(cases)} | OK {ok} | FUITES {len(leaks)} | "
          f"faux-négatifs {len(false_neg)} | crashes {len(crashes)}")
    if leaks:
        show("FUITES (Scope brut — voir doc, neutralisées à la construction)", leaks)
    if crashes:
        show("CRASHES", crashes)
    return 1 if crashes else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "tests/audit/cases.json"))
