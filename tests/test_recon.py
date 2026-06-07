"""Tests du pipeline recon — le critère vital : ne JAMAIS toucher un host hors-scope."""
from bb.recon import HostResult, enforce_scope, parse_crtsh, probe, run
from bb.scope import Scope


def test_enforce_scope_filters():
    scope = Scope(in_scope=["*.example.com"])
    kept, rej = enforce_scope(["a.example.com", "evil.com", "b.example.com"], scope)
    assert kept == ["a.example.com", "b.example.com"]
    assert "evil.com" in rej


def test_parse_crtsh_stays_on_domain():
    data = [{"name_value": "a.example.com\n*.b.example.com"}, {"name_value": "evil.com"}]
    subs = parse_crtsh(data, "example.com")
    assert "a.example.com" in subs and "b.example.com" in subs
    assert "evil.com" not in subs           # crt.sh peut renvoyer du bruit : on filtre


def test_probe_never_touches_out_of_scope():
    touched = []

    def fake_prober(host):
        touched.append(host)
        return HostResult(host=host, alive=True, status=200)

    scope = Scope(in_scope=["*.example.com"])
    results, rej = probe(["a.example.com", "evil.com", "x.attacker.io"], scope, prober=fake_prober)
    assert touched == ["a.example.com"]     # SEUL le host in-scope est touché
    assert "evil.com" in rej and "x.attacker.io" in rej


def test_basic_checks_env_detection_robust():
    """Un vrai .env (REDIS_HOST/JWT_SECRET...) doit être détecté (fix faux négatif)."""
    from bb.recon import HostResult, basic_checks

    class Resp:
        def __init__(self, code, text):
            self.status_code, self.text, self.headers = code, text, {}

    def fake_get(url, timeout=10):
        return Resp(200, "REDIS_HOST=localhost\nJWT_SECRET=abc123") if url.endswith("/.env") else Resp(404, "")

    res = HostResult(host="app.example.com", alive=True, scheme="https")
    findings = basic_checks(res, Scope(in_scope=["*.example.com"]), get=fake_get)
    assert any(f.get("detail") == "/.env" for f in findings), "vrai .env non détecté"


def test_basic_checks_env_no_false_positive():
    """Une page HTML 200 sans variables d'env ne doit PAS être flaggée comme .env."""
    from bb.recon import HostResult, basic_checks

    class Resp:
        def __init__(self, code, text):
            self.status_code, self.text, self.headers = code, text, {}

    def fake_get(url, timeout=10):
        return Resp(200, "<html><body>Page not found custom</body></html>")

    res = HostResult(host="app.example.com", alive=True, scheme="https")
    findings = basic_checks(res, Scope(in_scope=["*.example.com"]), get=fake_get)
    assert not any(f.get("type") == "exposed-file" for f in findings)   # zéro faux positif


def test_naabu_ports_deduplicated(monkeypatch):
    """naabu sort plusieurs lignes par port → on déduplique (pas de 22,22,22)."""
    import bb.recon as recon

    class Out:
        stdout = ('{"host":"a.example.com","port":22}\n{"host":"a.example.com","port":22}\n'
                  '{"host":"a.example.com","port":80}\n{"host":"evil.com","port":443}\n')

    monkeypatch.setattr(recon, "pd_path", lambda n: "/fake/naabu")
    monkeypatch.setattr(recon.subprocess, "run", lambda *a, **k: Out())
    res = recon.naabu_ports(["a.example.com"], Scope(in_scope=["*.example.com"]))
    assert res == {"a.example.com": [22, 80]}   # dédupliqué, trié, evil.com hors-scope exclu


def test_passive_urls_filtered_by_scope():
    from bb.recon import passive_urls
    rows = [["original"],                                   # en-tête CDX
            ["https://app.example.com/a?id=1"],
            ["https://evil.com/x"],                          # hors-scope
            ["http://shop.example.com/b"]]
    urls, errs = passive_urls("example.com", Scope(in_scope=["*.example.com"]),
                              fetch=lambda u: rows, with_gau=False)
    assert "https://app.example.com/a?id=1" in urls
    assert "http://shop.example.com/b" in urls
    assert all("evil.com" not in u for u in urls)            # défense en profondeur
    assert errs == []


def test_run_passive_only_never_probes(monkeypatch):
    import bb.recon as recon
    touched = []
    monkeypatch.setattr(recon, "passive_subdomains", lambda d, **k: ({"a.example.com", "evil.com"}, []))
    scope = Scope(in_scope=["*.example.com"])
    rep = recon.run("example.com", scope, passive_only=True, collect_urls=False,
                    prober=lambda h: (touched.append(h), HostResult(host=h))[1])
    assert touched == []                    # passif = zéro paquet actif
    assert rep["in_scope"] >= 1 and rep["rejected"] >= 1


def test_run_filters_then_probes(monkeypatch):
    import bb.recon as recon
    touched = []
    monkeypatch.setattr(recon, "passive_subdomains",
                        lambda d, **k: ({"a.example.com", "evil.com", "b.example.com"}, []))

    def fake_prober(host):
        touched.append(host)
        return HostResult(host=host, alive=True, status=200)

    scope = Scope(in_scope=["*.example.com"])
    rep = recon.run("example.com", scope, do_checks=False, collect_urls=False, prober=fake_prober)
    assert "evil.com" not in touched
    assert set(touched) == {"a.example.com", "b.example.com"}
    assert rep["alive"] == 2
