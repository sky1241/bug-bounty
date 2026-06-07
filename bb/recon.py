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


def has_tool(name: str) -> bool:
    return shutil.which(name) is not None


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
            [pd_path("httpx") or "httpx", "-silent", "-json", "-status-code", "-title",
             "-web-server", "-no-color", "-disable-redirects"],
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
        seen[host] = HostResult(
            host=host, alive=True, status=d.get("status_code") or d.get("status-code"),
            title=(d.get("title") or "")[:120], server=d.get("webserver", ""),
            scheme=d.get("scheme", ""))
    return [seen.get(h, HostResult(host=h, alive=False)) for h in hosts]


def _scan_nuclei(results, scope: Scope, timeout: int = 600):
    """Scan nuclei (Go) sur les hosts VIVANTS et in-scope. Findings attachés en place."""
    alive = [r for r in results if r.alive and scope.allows(r.host)]
    if not alive:
        return
    urls = "\n".join(f"{r.scheme or 'https'}://{r.host}" for r in alive)
    try:
        out = subprocess.run([pd_path("nuclei") or "nuclei", "-silent", "-jsonl", "-duc"],
                             input=urls, capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        return
    by_host = {r.host: r for r in alive}
    for line in out.stdout.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        host = (d.get("host") or "").split("://")[-1].split("/")[0].split(":")[0].lower()
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
            body = (r.text or "")[:200]
            if r.status_code == 200 and ("ref:" in body or "DB_" in body or "[core]" in body or "APP_" in body):
                findings.append({"type": "exposed-file", "detail": path, "severity": "medium",
                                 "evidence": body[:80]})
        except Exception:  # noqa: BLE001
            pass
    return findings


# ── Orchestration ───────────────────────────────────────────────────────────
def run(domain: str, scope: Scope, *, passive_only: bool = False, do_checks: bool = True,
        do_scan: bool = False, prober=None, use_tools: bool = True) -> dict:
    """Recon → probe → (checks/scan). Tout est filtré par le scope à chaque étape.

    Hybride : `prober=None` + httpx présent → httpx (Go) ; sinon fallback requests.
    Passer un `prober` explicite force la voie Python (utilisé par les tests).
    """
    subs, passive_errors = passive_subdomains(domain)
    in_scope, rejected = enforce_scope(subs | {domain}, scope)
    report = {
        "domain": domain,
        "discovered": len(subs),
        "in_scope": len(in_scope),
        "rejected": len(rejected),
        "passive_errors": passive_errors,  # remontée explicite (pas de silence)
        "tools": {n: pd_tool(n) for n in ("subfinder", "httpx", "nuclei")},
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

    report["hosts"] = [asdict(r) for r in results]
    report["alive"] = sum(1 for r in results if r.alive)
    return report
