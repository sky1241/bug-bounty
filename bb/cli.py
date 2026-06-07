"""CLI de l'agrégateur : `python -m bb update | list | scope`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import aggregate, recon as recon_mod, report as report_mod, sources
from .scope import Scope, normalize_host


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

    re_ = sub.add_parser("recon", help="recon in-scope d'un domaine (sous-domaines + probe)")
    re_.add_argument("domain")
    re_.add_argument("--program", help="programme pour charger le scope (recommandé)")
    re_.add_argument("--authorized", action="store_true",
                     help="affirmer l'autorisation si pas de --program (scope = domain + *.domain)")
    re_.add_argument("--passive-only", action="store_true", help="aucun paquet actif")
    re_.add_argument("--no-checks", action="store_true", help="probe sans les checks basiques")
    re_.add_argument("--scan", action="store_true", help="lancer nuclei si présent (plus intrusif)")
    re_.add_argument("--out", help="écrire le rapport JSON")

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

    if args.cmd == "recon":
        domain = normalize_host(args.domain) or args.domain.strip().lower()
        if args.program:
            feeds, ywh_api = sources.load()
            progs = aggregate.aggregate(feeds)
            aggregate.enrich_ywh(progs, ywh_api)
            q = args.program.lower()
            m = [p for p in progs if q in p.name.lower() or q in p.handle.lower()]
            if not m:
                print(f"Programme '{args.program}' introuvable (lance `bb update`).", file=sys.stderr)
                return 1
            scope = m[0].scope
        elif args.authorized:
            scope = Scope(in_scope=[domain, f"*.{domain}"])
            print(f"⚠️  --authorized : tu affirmes être autorisé à tester {domain}.", file=sys.stderr)
        else:
            print("Refus: fournis --program <nom> (scope du programme), "
                  "ou --authorized si tu es certain d'être in-scope.", file=sys.stderr)
            return 2
        rep = recon_mod.run(domain, scope, passive_only=args.passive_only,
                            do_checks=not args.no_checks, do_scan=args.scan)
        print(f"[{domain}] découverts={rep['discovered']} in-scope={rep['in_scope']} "
              f"rejetés={rep['rejected']} vivants={rep.get('alive', '-')}  outils={rep['tools']}")
        if rep.get("passive_errors"):
            print(f"  ⚠️  sources passives en échec: {', '.join(rep['passive_errors'])}", file=sys.stderr)
        for h in rep["hosts"][:40]:
            line = f"  {h['host']}"
            if h.get("status"):
                line += f"  [{h['status']}] {h.get('title', '')[:48]}"
            if h.get("findings"):
                line += f"  ⚑ {len(h['findings'])} finding(s)"
            print(line)
        if args.out:
            Path(args.out).write_text(json.dumps(rep, indent=2, ensure_ascii=False))
            print(f"JSON: {args.out}")
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
