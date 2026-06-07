"""CLI de l'agrégateur : `python -m bb update | list | scope`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import aggregate, report as report_mod, sources


def _print_table(programs, limit: int, show_score: bool = False) -> None:
    rows = programs[:limit]
    head = f"{'PLATFORM':10} {'BOUNTY':>11}  {'WILD':>4} {'CC':2} {'REPORTS':>7}"
    if show_score:
        head += f" {'SCORE':>5}"
    print(head + "  NAME")
    print("-" * (98 if show_score else 92))
    for p in rows:
        rc = "--" if p.reports_count is None else str(p.reports_count)
        line = (f"{p.platform:10} {p.bounty_str:>11}  {p.wildcard_count:>4} "
                f"{(p.country or '--'):2} {rc:>7}")
        if show_score:
            line += f" {p.starter_score:>5.0f}"
        print(line + f"  {p.name[:40]}")
    print(f"\n{len(rows)} affichés / {len(programs)} au total")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="bb", description="Agrégateur de programmes bug bounty")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("update", help="télécharger les feeds (réseau requis)")

    lp = sub.add_parser("list", help="lister les programmes")
    lp.add_argument("--beginner", action="store_true", help="filtre débutant (cash+ouvert+web+scope)")
    lp.add_argument("--starter", action="store_true",
                    help="filtre débutant + tri par score anti-saturation (reports bas, FR, prime modérée)")
    lp.add_argument("--no-cash", action="store_true", help="inclure les programmes sans prime (VDP)")
    lp.add_argument("--platform", help="filtrer par plateforme")
    lp.add_argument("--fr", action="store_true", help="programmes FR uniquement")
    lp.add_argument("--min-bounty", type=float, default=0)
    lp.add_argument("--sort", choices=["bounty", "surface"], default="bounty")
    lp.add_argument("--limit", type=int, default=25)

    sc = sub.add_parser("scope", help="afficher le scope d'un programme")
    sc.add_argument("query", help="sous-chaîne du nom ou du handle")

    rp = sub.add_parser("report", help="générer un rapport depuis un finding JSON")
    rp.add_argument("finding", help="fichier JSON {finding:{...}, validation:{...}}")
    rp.add_argument("--program", help="nom du programme (pour vérifier le scope)")
    rp.add_argument("--draft", action="store_true", help="brouillon même si validation incomplète")
    rp.add_argument("--out", help="fichier de sortie (défaut: stdout)")

    args = ap.parse_args(argv)

    if args.cmd == "update":
        print("Téléchargement des feeds (bounty-targets-data + API YesWeHack)…")
        sources.update()
        print("OK. Cache: data/programs/")
        return 0

    if args.cmd == "report":
        data = json.loads(Path(args.finding).read_text())
        finding = report_mod.finding_from_dict(data.get("finding", data))
        validation = report_mod.validation_from_dict(data.get("validation", {}))
        scope = None
        if args.program:
            feeds, ywh_api = sources.load()
            progs = aggregate.aggregate(feeds)
            aggregate.enrich_ywh(progs, ywh_api)
            q = args.program.lower()
            matches = [p for p in progs if q in p.name.lower() or q in p.handle.lower()]
            scope = matches[0].scope if matches else None
        try:
            md = report_mod.render(finding, validation, scope, enforce=not args.draft)
        except report_mod.ReportNotValidated as e:
            print(f"⛔ {e}", file=sys.stderr)
            return 2
        if args.out:
            Path(args.out).write_text(md)
            print(f"Rapport écrit: {args.out}")
        else:
            print(md)
        return 0

    feeds, ywh_api = sources.load()
    if not feeds:
        print("Aucun feed en cache. Lance d'abord: python -m bb update", file=sys.stderr)
        return 1
    progs = aggregate.aggregate(feeds)
    aggregate.enrich_ywh(progs, ywh_api)

    if args.cmd == "list":
        if args.starter or args.beginner:
            progs = aggregate.beginner(progs, require_cash=not args.no_cash)
        elif not args.no_cash:
            progs = [p for p in progs if p.pays_cash]
        if args.platform:
            progs = [p for p in progs if p.platform == args.platform]
        if args.fr:
            progs = [p for p in progs if p.country == "FR"]
        if args.min_bounty:
            progs = [p for p in progs if (p.max_bounty or 0) >= args.min_bounty]
        if args.starter:
            progs = sorted(progs, key=lambda p: (p.starter_score, p.max_bounty or 0), reverse=True)
        else:
            progs = aggregate.sort_programs(progs, args.sort)
        _print_table(progs, args.limit, show_score=args.starter)
        return 0

    if args.cmd == "scope":
        q = args.query.lower()
        matches = [p for p in progs if q in p.name.lower() or q in p.handle.lower()]
        if not matches:
            print("Aucun programme trouvé.")
            return 1
        for p in matches[:5]:
            print(f"\n## {p.name} [{p.platform}]  {p.url}")
            print(f"   bounty: {p.bounty_str} | pays={p.country or '?'} | cats: {sorted(p.categories)}")
            print(f"   IN-SCOPE ({len(p.scope.in_scope)}):")
            for s in p.scope.in_scope[:40]:
                print(f"     + {s}")
            if p.scope.out_of_scope:
                print(f"   OUT-OF-SCOPE ({len(p.scope.out_of_scope)}):")
                for s in p.scope.out_of_scope[:20]:
                    print(f"     - {s}")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
