"""Pipeline recon hybride — in-scope only.

Outils Go (subfinder/httpx/nuclei) si présents, sinon fallback pur Python.

GARDE-FOU LÉGAL (non négociable) : tout host passe par `Scope.allows` AVANT le
moindre paquet actif, et le filtre est ré-appliqué entre chaque étape (défense en
profondeur). Le recon passif (crt.sh) n'envoie aucun paquet à la cible. Les
redirections ne sont PAS suivies (une redirection pourrait pointer hors-scope).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field

from .scope import Scope, normalize_host

_UA = "bb-recon/0.1 (authorized bug bounty recon)"


_PD_CACHE: dict[str, str] = {}
_PD_DIRS = [os.path.expanduser(p) for p in
            ("~/.local/bin", "~/go/bin", "~/.pdtm/go/bin")] + ["/usr/local/bin"]


def pd_path(name: str) -> str:
    """Chemin du binaire ProjectDiscovery `name`, ou "" s'il est absent.

    Évite le piège réel de l'homonyme : la CLI de la lib Python `httpx` s'appelle
    aussi `httpx`. On teste les chemins PD explicites EN PREMIER (avant un `which`
    qui pourrait renvoyer l'homonyme), et on exige que `-version` dise 'projectdiscovery'.
    """
    if name in _PD_CACHE:
        return _PD_CACHE[name]
    candidates = [os.path.join(d, name) for d in _PD_DIRS]
    w = shutil.which(name)
    if w:
        candidates.append(w)
    found = ""
    for p in candidates:
        if not (os.path.isfile(p) and os.access(p, os.X_OK)):
            continue
        try:
            out = subprocess.run([p, "-version"], capture_output=True, text=True, timeout=10)
            blob = (out.stdout + out.stderr).lower()
            # Le vrai outil PD répond à `-version` avec une version ; l'homonyme
            # Python `httpx` répond par un usage/erreur d'option (rejeté ici).
            if "version" in blob and "usage:" not in blob and "no such option" not in blob:
                found = p
                break
        except (subprocess.SubprocessError, OSError):
            continue
    _PD_CACHE[name] = found
    return found


def pd_tool(name: str) -> bool:
    return bool(pd_path(name))


def _bin(name: str) -> str:
    """Chemin d'un binaire (PD ou non), par présence — pour gau/ffuf/katana etc."""
    p = os.path.expanduser(f"~/.local/bin/{name}")
    if os.path.isfile(p) and os.access(p, os.X_OK):
        return p
    return shutil.which(name) or ""


def resolve_dnsx(hosts, timeout: int = 120):
    """Résout via dnsx : retourne (hosts_qui_résolvent, {host: cname}).

    Filtre les faux hosts (wildcard DNS) et récupère le CNAME (signal de takeover).
    Si dnsx échoue, on ne filtre pas (conservateur : garder tout).
    """
    hosts = list(hosts)
    if not hosts:
        return set(), {}
    try:
        out = subprocess.run([pd_path("dnsx") or "dnsx", "-silent", "-a", "-cname", "-json"],
                             input="\n".join(hosts), capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        return set(hosts), {}
    resolved, cnames = set(), {}
    for line in out.stdout.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        h = (d.get("host") or "").lower()
        if not h:
            continue
        resolved.add(h)
        cn = d.get("cname")
        if cn:
            cnames[h] = cn[0] if isinstance(cn, list) and cn else cn
    return resolved, cnames


def _from_gau(domain: str) -> set[str]:
    gau = _bin("gau")
    if not gau:
        return set()
    out = subprocess.run([gau, "--subs", domain], capture_output=True, text=True, timeout=120)
    return {l.strip() for l in out.stdout.splitlines() if l.strip()}


def enforce_scope(hosts, scope: Scope):
    """Filtre : ne garde que les hosts in-scope. Retourne (gardés triés, rejetés)."""
    kept, rejected = set(), []
    for h in hosts:
        host = normalize_host(h)
        if host and scope.allows(host):
            kept.add(host)
        else:
            rejected.append(h)
    return sorted(kept), rejected


# ── Recon passif : sous-domaines ────────────────────────────────────────────
def parse_crtsh(data, domain: str) -> set[str]:
    """Extrait les sous-domaines d'une réponse JSON crt.sh (Certificate Transparency)."""
    domain = domain.lower().lstrip(".")
    subs = set()
    for entry in data or []:
        if not isinstance(entry, dict):
            continue
        for line in str(entry.get("name_value", "")).splitlines():
            name = line.strip().lstrip("*.").lower()
            if name == domain or name.endswith("." + domain):
                subs.add(name)
    return subs


def _http_get_json(url: str, timeout: int = 30):
    import requests

    r = requests.get(url, timeout=timeout, headers={"User-Agent": _UA})
    r.raise_for_status()
    return r.json()


def _from_subfinder(domain: str, max_minutes: int = 2) -> set[str]:
    # -max-time borne l'énumération (défaut subfinder = 10 min, trop long pour la fleet).
    out = subprocess.run(
        [pd_path("subfinder") or "subfinder", "-silent", "-d", domain, "-max-time", str(max_minutes)],
        capture_output=True, text=True, timeout=max_minutes * 60 + 30)
    return {l.strip().lower() for l in out.stdout.splitlines() if l.strip()}


def _from_crtsh(domain: str, fetch) -> set[str]:
    return parse_crtsh(fetch(f"https://crt.sh/?q=%25.{domain}&output=json"), domain)


def _from_hackertarget(domain: str) -> set[str]:
    import requests

    r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                     timeout=30, headers={"User-Agent": _UA})
    r.raise_for_status()
    txt = r.text or ""
    if "error" in txt.lower() or "api count" in txt.lower():
        return set()
    subs = set()
    for line in txt.splitlines():
        host = line.split(",")[0].strip().lower()
        if host == domain or host.endswith("." + domain):
            subs.add(host)
    return subs


def passive_subdomains(domain: str, *, fetch=_http_get_json):
    """Sous-domaines via subfinder (PD, si présent) + sources OSINT. Retourne (subs, errors).

    Plusieurs sources sont combinées (robustesse). Les erreurs sont REMONTÉES
    (jamais avalées silencieusement) pour que l'appelant sache ce qui a échoué.
    """
    subs, errors = set(), []
    srcs = []
    if pd_tool("subfinder"):
        srcs.append(("subfinder", lambda: _from_subfinder(domain)))
    srcs += [("crtsh", lambda: _from_crtsh(domain, fetch)),
             ("hackertarget", lambda: _from_hackertarget(domain))]
    for name, fn in srcs:
        try:
            subs |= fn()
        except Exception as e:  # noqa: BLE001
            errors.append(f"{name}: {type(e).__name__}")
    return subs, errors


def passive_urls(domain: str, scope: Scope, *, fetch=_http_get_json, limit: int = 3000,
                 with_gau: bool = True):
    """URLs historiques (Wayback CDX + gau), passif/OSINT, re-filtrées par scope.

    Multiplicateur de surface : IDOR, open redirect, XSS réfléchi, fichiers oubliés
    vivent dans des URL paramétrées. gau ajoute CommonCrawl/AlienVault/URLScan.
    Aucun paquet vers la cible. Chaque URL repasse par Scope.allows (défense en profondeur).
    """
    urls, errors = [], []
    cdx = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
           f"&output=json&fl=original&collapse=urlkey&limit={limit}")
    try:
        rows = fetch(cdx)
        for row in (rows or [])[1:]:  # 1re ligne = en-tête
            u = row[0] if isinstance(row, list) and row else (row if isinstance(row, str) else "")
            host = normalize_host(u)
            if host and scope.allows(host):
                urls.append(u)
    except Exception:  # noqa: BLE001
        errors.append("wayback: erreur")
    if with_gau:
        try:
            for u in _from_gau(domain):
                host = normalize_host(u)
                if host and scope.allows(host):
                    urls.append(u)
        except Exception:  # noqa: BLE001
            errors.append("gau: erreur")
    return sorted(set(urls)), errors


# ── Probe HTTP (actif léger, in-scope only) ─────────────────────────────────
@dataclass
class HostResult:
    host: str
    alive: bool = False
    status: int | None = None
    title: str = ""
    server: str = ""
    scheme: str = ""
    redirect: str = ""
    error: str = ""
    tech: list = field(default_factory=list)
    favicon: str = ""
    cdn: str = ""
    ip: str = ""
    cname: str = ""
    findings: list = field(default_factory=list)


def _probe_requests(host: str, timeout: int = 10) -> HostResult:
    import requests

    last_err = ""
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{host}", timeout=timeout, allow_redirects=False,
                             headers={"User-Agent": _UA})
        except Exception as e:  # noqa: BLE001
            last_err = type(e).__name__
            continue
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text or "", re.I | re.S)
        return HostResult(host=host, alive=True, status=r.status_code, scheme=scheme,
                          title=(m.group(1).strip()[:120] if m else ""),
                          server=r.headers.get("Server", ""),
                          redirect=r.headers.get("Location", "") if 300 <= r.status_code < 400 else "")
    return HostResult(host=host, alive=False, error=last_err)


def probe(hosts, scope: Scope, *, prober=_probe_requests):
    """Probe UNIQUEMENT les hosts in-scope (garde-fou ré-appliqué juste avant l'appel)."""
    kept, rejected = enforce_scope(hosts, scope)
    results = []
    for h in kept:
        if not scope.allows(h):  # défense en profondeur, juste avant le paquet
            continue
        results.append(prober(h))
    return results, rejected


def _probe_httpx(hosts, timeout: int = 120):
    """Probe en batch via httpx (Go). Les `hosts` sont DÉJÀ filtrés in-scope."""
    hosts = list(hosts)
    if not hosts:
        return []
    try:
        out = subprocess.run(
            # NB: pas de '-disable-redirects' (flag inexistant qui CASSE la sortie JSON) ;
            # httpx ne suit PAS les redirects par défaut, ce qu'on veut (anti hors-scope).
            [pd_path("httpx") or "httpx", "-silent", "-json", "-status-code", "-title",
             "-web-server", "-tech-detect", "-favicon", "-cdn", "-ip", "-cname",
             "-no-color", "-rate-limit", "100"],
            input="\n".join(hosts), capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        return [_probe_requests(h) for h in hosts]  # fallback Python, pas d'échec silencieux
    seen = {}
    for line in out.stdout.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        raw = d.get("input") or d.get("host") or d.get("url") or ""
        host = raw.split("://")[-1].split("/")[0].split(":")[0].lower()
        if not host:
            continue  # ligne JSON sans host exploitable → on ignore (pas de pollution)

        def _first(v):
            return (v[0] if isinstance(v, list) and v else v) or ""

        seen[host] = HostResult(
            host=host, alive=True, status=d.get("status_code") or d.get("status-code"),
            title=(d.get("title") or "")[:120], server=d.get("webserver", ""),
            scheme=d.get("scheme", ""), tech=d.get("tech") or [],
            favicon=str(d.get("favicon") or ""), cdn=d.get("cdn_name") or "",
            ip=_first(d.get("a")) or d.get("ip") or "", cname=_first(d.get("cname")))
    return [seen.get(h, HostResult(host=h, alive=False)) for h in hosts]


def _scan_nuclei(results, scope: Scope, timeout: int = 600):
    """Scan nuclei (Go) sur les hosts VIVANTS et in-scope. Findings attachés en place."""
    alive = [r for r in results if r.alive and scope.allows(r.host)]
    if not alive:
        return
    urls = "\n".join(f"{r.scheme or 'https'}://{r.host}" for r in alive)
    try:
        out = subprocess.run(
            [pd_path("nuclei") or "nuclei", "-silent", "-jsonl", "-duc",
             # Ciblé sur les classes rentables débutant (pas les ~9000 templates par défaut),
             # severity sans 'info' (spam), rate-limit pour rester poli (anti-ban).
             "-tags", "exposure,misconfig,takeover,default-login,cve",
             "-severity", "low,medium,high,critical", "-rate-limit", "50"],
            input=urls, capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        return
    by_host = {r.host: r for r in alive}
    for line in out.stdout.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        raw_h = d.get("host") or d.get("matched-at") or d.get("matched_at") or d.get("url") or ""
        host = raw_h.split("://")[-1].split("/")[0].split(":")[0].lower()
        info = d.get("info", {})
        if host in by_host:
            by_host[host].findings.append({
                "type": "nuclei", "detail": d.get("template-id", ""),
                "name": info.get("name", ""), "severity": info.get("severity", "info")})


# ── Checks Python basiques (low-hanging fruit débutant, in-scope only) ───────
_SENSITIVE = ("/.git/HEAD", "/.git/config", "/.env")
_SEC_HEADERS = ("content-security-policy", "strict-transport-security",
                "x-frame-options", "x-content-type-options")


def _get(url, timeout=10):
    import requests

    return requests.get(url, timeout=timeout, allow_redirects=False, headers={"User-Agent": _UA})


def katana_crawl(hosts, scope: Scope, *, depth: int = 2, timeout: int = 300):
    """Crawl (katana) des hosts in-scope → URLs/endpoints (Phase 2 mapping). Actif léger.

    Re-filtre chaque URL par scope (katana peut suivre des liens externes).
    """
    kat = _bin("katana")
    hosts = [h for h in hosts if scope.allows(h)]
    if not kat or not hosts:
        return []
    payload = "\n".join(f"https://{h}" for h in hosts)
    try:
        out = subprocess.run([kat, "-silent", "-d", str(depth), "-jc", "-no-color"],
                             input=payload, capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        return []
    found = []
    for line in out.stdout.splitlines():
        u = line.strip()
        h = normalize_host(u)
        if h and scope.allows(h):  # défense en profondeur
            found.append(u)
    return sorted(set(found))


def naabu_ports(hosts, scope: Scope, *, top_ports: str = "100", timeout: int = 300):
    """Scan de ports (naabu) sur les hosts in-scope. ACTIF/intrusif → opt-in (--ports).

    Retourne {host: [ports]}. Rate-limité (anti-ban). In-scope only.
    """
    nb = pd_path("naabu") or _bin("naabu")
    hosts = [h for h in hosts if scope.allows(h)]
    if not nb or not hosts:
        return {}
    try:
        out = subprocess.run([nb, "-silent", "-json", "-top-ports", top_ports, "-rate", "100"],
                             input="\n".join(hosts), capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        return {}
    ports = {}
    for line in out.stdout.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        h = (d.get("host") or "").lower()
        p = d.get("port")
        if h and p and scope.allows(h):
            ports.setdefault(h, set()).add(p)
    return {h: sorted(v) for h, v in ports.items()}   # dédupliqué + trié


def basic_checks(result: HostResult, scope: Scope, *, get=_get) -> list:
    """Checks non destructifs sur un host VIVANT et in-scope (headers, fichiers exposés)."""
    if not result.alive or not scope.allows(result.host):
        return []
    findings, base = [], f"{result.scheme or 'https'}://{result.host}"
    try:
        root = get(base)
        present = {k.lower() for k in root.headers}
        for h in _SEC_HEADERS:
            if h not in present:
                findings.append({"type": "missing-header", "detail": h, "severity": "info"})
    except Exception as e:  # noqa: BLE001
        findings.append({"type": "probe-error", "detail": type(e).__name__, "severity": "info"})
    for path in _SENSITIVE:
        try:
            r = get(base + path)
            if r.status_code != 200:
                continue
            body = (r.text or "")[:500]
            # Signature PAR type de fichier (réduit faux positifs ET faux négatifs) :
            #   .env -> au moins une ligne VARIABLE=...  (REDIS_HOST, JWT_SECRET, etc.)
            #   .git/config -> section [core] ; .git/HEAD -> commence par 'ref:'
            hit = ((path.endswith(".env") and re.search(r"(?m)^[A-Z][A-Z0-9_]{2,}=", body))
                   or (path.endswith("config") and "[core]" in body)
                   or (path.endswith("HEAD") and body.strip().startswith("ref:")))
            if hit:
                findings.append({"type": "exposed-file", "detail": path, "severity": "medium",
                                 "evidence": body[:80]})
        except Exception:  # noqa: BLE001
            pass
    return findings


# ── Orchestration ───────────────────────────────────────────────────────────
def run(domain: str, scope: Scope, *, passive_only: bool = False, do_checks: bool = True,
        do_scan: bool = False, do_ports: bool = False, prober=None, use_tools: bool = True,
        collect_urls: bool = True) -> dict:
    """Recon → probe → (checks/scan). Tout est filtré par le scope à chaque étape.

    Hybride : `prober=None` + httpx présent → httpx (Go) ; sinon fallback requests.
    Passer un `prober` explicite force la voie Python (utilisé par les tests).
    """
    subs, passive_errors = passive_subdomains(domain)
    in_scope, rejected = enforce_scope(subs | {domain}, scope)
    cnames = {}
    if prober is None and use_tools and pd_tool("dnsx") and in_scope:
        resolved, cnames = resolve_dnsx(in_scope)
        in_scope = [h for h in in_scope if h in resolved] or in_scope  # filtre les faux hosts
    urls = []
    if collect_urls:
        urls, url_errs = passive_urls(domain, scope)
        passive_errors = passive_errors + url_errs
    report = {
        "domain": domain,
        "discovered": len(subs),
        "in_scope": len(in_scope),
        "rejected": len(rejected),
        "urls": len(urls),
        "url_list": urls[:500],
        "cnames": cnames,  # host -> CNAME (signal de subdomain takeover)
        "passive_errors": passive_errors,  # remontée explicite (pas de silence)
        "tools": {n: pd_tool(n) for n in ("subfinder", "httpx", "nuclei", "dnsx", "katana", "naabu")},
        "hosts": [],
    }
    if passive_only:
        report["hosts"] = [{"host": h} for h in in_scope]
        return report

    if prober is None and use_tools and pd_tool("httpx"):
        results = _probe_httpx(in_scope)
    else:
        results, _ = probe(in_scope, scope, prober=prober or _probe_requests)
    # Défense en profondeur : un outil externe pourrait renvoyer un host inattendu.
    results = [r for r in results if scope.allows(r.host)]

    for res in results:
        if do_checks and res.alive:
            res.findings = basic_checks(res, scope)
    if do_scan and pd_tool("nuclei"):
        _scan_nuclei(results, scope)

    alive_hosts = [r.host for r in results if r.alive]
    # Phase 2 (mapping) : crawl katana des hosts vivants → URLs/endpoints supplémentaires
    if prober is None and collect_urls and use_tools and _bin("katana") and alive_hosts:
        crawled = katana_crawl(alive_hosts, scope)
        if crawled:
            merged = sorted(set(report.get("url_list", [])) | set(crawled))
            report["url_list"], report["urls"] = merged[:1000], len(merged)
    # Ports (naabu) — opt-in. Sur les hosts in-scope RÉSOLUS (pas seulement web-vivants :
    # un host peut n'avoir que SSH/22 ouvert, sans serveur web).
    if do_ports and prober is None and in_scope:
        report["ports"] = naabu_ports(in_scope, scope)

    report["hosts"] = [asdict(r) for r in results]
    report["alive"] = len(alive_hosts)
    return report
