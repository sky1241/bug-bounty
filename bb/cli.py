"""CLI de l'agrégateur : `python -m bb update | list | scope`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import (aggregate, doctor, engagement, fleet, journal, recon as recon_mod,
               report as report_mod, sources)
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
    re_.add_argument("domains", nargs="+", help="un ou plusieurs domaines (shard de la fleet)")
    re_.add_argument("--program", help="programme pour charger le scope (recommandé)")
    re_.add_argument("--scope-file", help="scope JSON {in_scope,out_of_scope} ('-' = stdin, mode worker)")
    re_.add_argument("--authorized", action="store_true",
                     help="affirmer l'autorisation si pas de --program (scope = domain + *.domain)")
    re_.add_argument("--passive-only", action="store_true", help="aucun paquet actif")
    re_.add_argument("--no-checks", action="store_true", help="probe sans les checks basiques")
    re_.add_argument("--scan", action="store_true", help="lancer nuclei si présent (plus intrusif)")
    re_.add_argument("--json", action="store_true", help="sortir le JSON sur stdout (mode worker)")
    re_.add_argument("--out", help="écrire le rapport JSON dans un fichier")

    cp = sub.add_parser("scan", help="évalue un programme et prépare l'engagement (clé en main)")
    cp.add_argument("program")
    cp.add_argument("--go", action="store_true", help="créer le dossier d'engagement + vérifier les outils")

    sub.add_parser("doctor", help="vérifie que tous les outils nécessaires sont installés")

    fp = sub.add_parser("fleet", help="recon distribué sur la fleet (sky-master + cousins)")
    fp.add_argument("program", help="nom du programme (scope + domaines in-scope)")
    fp.add_argument("--nodes", default="local", help="alias SSH séparés par virgule (ex: pc1,pc3,local)")
    fp.add_argument("--scan", action="store_true", help="passer --scan aux workers")
    fp.add_argument("--out", help="écrire les résultats agrégés (JSON)")

    jp = sub.add_parser("journal", help="historique des tests (le « dictionnaire » du projet)")
    jp.add_argument("action", nargs="?", default="summary", choices=["summary", "list", "add"])
    jp.add_argument("--type", dest="jtype", choices=list(journal.TYPES))
    jp.add_argument("--target", default="")
    jp.add_argument("--note", default="")
    jp.add_argument("--grep", default="")
    jp.add_argument("--limit", type=int, default=30)

    args = ap.parse_args(argv)

    if args.cmd == "update":
        print("Téléchargement des feeds (bounty-targets-data + API YesWeHack)…")
        sources.update()
        print("OK. Cache: data/programs/")
        return 0

    if args.cmd == "doctor":
        rep = doctor.check()
        print("Python :", {k: ("OK" if v else "MANQUANT") for k, v in rep["python_deps"].items()})
        print("Outils PD :", {k: (f"{rep['versions'].get(k) or '?'}" if v else "absent")
                               for k, v in rep["pd_tools"].items()})
        for w in rep["warnings"]:
            print(f"  ⚠️  {w}")
        print("\n" + ("✅ PRÊT à scanner" if rep["ready"] else "❌ PAS PRÊT (installe les deps requises)"))
        return 0 if rep["ready"] else 1

    if args.cmd == "scan":
        feeds, ywh_api = sources.load()
        if not feeds:
            print("Aucun feed en cache. Lance `bb update`.", file=sys.stderr)
            return 1
        progs = aggregate.aggregate(feeds)
        aggregate.enrich_ywh(progs, ywh_api)
        q = args.program.lower()
        m = [p for p in progs if q in p.name.lower() or q in p.handle.lower()]
        if not m:
            print(f"Programme '{args.program}' introuvable (lance `bb update`).", file=sys.stderr)
            return 1
        p = m[0]
        interesting = p.pays_cash and p.web_surface and p.is_open and p.starter_score >= 5
        verdict = "INTÉRESSANT ✅" if interesting else "moyen / à évaluer"
        print(f"{p.name} [{p.platform}] prime={p.bounty_str} score={p.starter_score:.0f} "
              f"pays={p.country or '?'}  →  {verdict}")
        print(f"  scope: {p.in_scope_count} règles ({p.wildcard_count} wildcards), "
              f"web={p.web_surface}, cash={p.pays_cash}")
        seen = engagement.exists(p.name)
        prev = journal.search(p.name, "recon")
        if seen or prev:
            print(f"  ⚠️  déjà vu (engagement={'oui' if seen else 'non'}, "
                  f"{len(prev)} recon(s) au journal) — on évite le re-scan inutile.")
        if not args.go:
            print("  → ajoute --go pour créer le dossier d'engagement et vérifier les outils.")
            return 0
        drep = doctor.check()
        if not drep["ready"]:
            print("  ❌ doctor: dépendances manquantes — `bb doctor` pour le détail.", file=sys.stderr)
            return 1
        d = engagement.create(p.name, p.scope)
        journal.record("note", p.name, note=f"engagement créé ({d.name})", engagement=str(d))
        tools = ", ".join(t for t, v in drep["pd_tools"].items() if v) or "fallback Python"
        print(f"  ✅ Engagement prêt: {d}")
        print(f"     Outils dispo: {tools}")
        print(f"     → conteneur isolé du projet : bash scripts/project_run.sh {d.name} doctor")
        print(f"     → recon distribué (fleet)   : bb fleet \"{p.name}\" --nodes pc1,pc3,local")
        return 0

    if args.cmd == "fleet":
        feeds, ywh_api = sources.load()
        progs = aggregate.aggregate(feeds)
        aggregate.enrich_ywh(progs, ywh_api)
        q = args.program.lower()
        m = [p for p in progs if q in p.name.lower() or q in p.handle.lower()]
        if not m:
            print(f"Programme '{args.program}' introuvable (lance `bb update`).", file=sys.stderr)
            return 1
        scope = m[0].scope
        domains = fleet.seed_domains(scope)
        if not domains:
            print("Aucun domaine-graine exploitable dans ce scope.", file=sys.stderr)
            return 1
        nodes = [fleet.Node(n.strip()) for n in args.nodes.split(",") if n.strip()]
        print(f"Distribution de {len(domains)} domaine(s) sur {len(nodes)} nœud(s) "
              f"{[n.name for n in nodes]}", file=sys.stderr)
        results = fleet.distribute(domains, scope, nodes, runner=fleet.ssh_runner)
        for r in results:
            print(f"  {'✅' if r.get('ok') else '❌'} {r['node']}: {r.get('error') or 'ok'}")
        journal.record("recon", args.program, mode="fleet",
                       nodes=[n.name for n in nodes], domains=len(domains),
                       ok_nodes=sum(1 for r in results if r.get("ok")))
        if args.out:
            Path(args.out).write_text(json.dumps(results, indent=2, ensure_ascii=False))
            print(f"Résultats: {args.out}", file=sys.stderr)
        return 0

    if args.cmd == "journal":
        if args.action == "add":
            e = journal.record(args.jtype or "note", args.target, note=args.note)
            print(f"Ajouté: {e['ts']} [{e['type']}] {e['target']} {e.get('note', '')}")
            return 0
        if args.action == "list":
            rows = journal.search(args.grep, args.jtype)[-args.limit:]
            for e in rows:
                extra = e.get("title") or e.get("note") or ""
                print(f"{e['ts']} [{e['type']:14}] {e.get('target', ''):32} {extra}")
            print(f"\n{len(rows)} événement(s)")
            return 0
        s = journal.summary()
        print(f"Journal: {s['events']} événements | par type: {s['by_type']}")
        print(f"Cibles ({len(s['targets'])}): {', '.join(s['targets'][:20])}")
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
        journal.record("report", finding.asset_url, title=finding.title,
                       severity=report_mod.cvss_label(finding.cvss_score),
                       validated=validation.complete())
        if args.out:
            Path(args.out).write_text(md)
            print(f"Rapport écrit: {args.out}")
        else:
            print(md)
        return 0

    if args.cmd == "recon":
        domains = [normalize_host(d) or d.strip().lower() for d in args.domains]
        # Résolution du scope : --scope-file (worker) | --program | --authorized
        if args.scope_file:
            raw = sys.stdin.read() if args.scope_file == "-" else Path(args.scope_file).read_text()
            sc = json.loads(raw)
            scope = Scope(in_scope=sc.get("in_scope", []), out_of_scope=sc.get("out_of_scope", []))
        elif args.program:
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
            scope = Scope(in_scope=[p for d in domains for p in (d, f"*.{d}")])
            print(f"⚠️  --authorized : tu affirmes être autorisé à tester {', '.join(domains)}.",
                  file=sys.stderr)
        else:
            print("Refus: fournis --scope-file, --program <nom>, ou --authorized.", file=sys.stderr)
            return 2

        reports = []
        for dom in domains:
            rep = recon_mod.run(dom, scope, passive_only=args.passive_only,
                                do_checks=not args.no_checks, do_scan=args.scan)
            reports.append(rep)
            journal.record("recon", dom, in_scope=rep["in_scope"], rejected=rep["rejected"],
                           alive=rep.get("alive"), passive_errors=rep.get("passive_errors") or [],
                           findings=sum(len(h.get("findings", [])) for h in rep["hosts"]))
            # Résumé lisible sur stderr (stdout réservé au JSON en mode worker)
            stream = sys.stderr if args.json else sys.stdout
            print(f"[{dom}] découverts={rep['discovered']} in-scope={rep['in_scope']} "
                  f"rejetés={rep['rejected']} vivants={rep.get('alive', '-')} outils={rep['tools']}",
                  file=stream)
            if rep.get("passive_errors"):
                print(f"  ⚠️  sources passives en échec: {', '.join(rep['passive_errors'])}", file=sys.stderr)
            if not args.json:
                for h in rep["hosts"][:40]:
                    line = f"  {h['host']}"
                    if h.get("status"):
                        line += f"  [{h['status']}] {h.get('title', '')[:48]}"
                    if h.get("findings"):
                        line += f"  ⚑ {len(h['findings'])} finding(s)"
                    print(line)

        payload = reports[0] if len(reports) == 1 else reports
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2, ensure_ascii=False))
            print(f"JSON: {args.out}", file=sys.stderr)
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
