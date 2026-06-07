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


def test_run_passive_only_never_probes(monkeypatch):
    import bb.recon as recon
    touched = []
    monkeypatch.setattr(recon, "passive_subdomains", lambda d, **k: ({"a.example.com", "evil.com"}, []))
    scope = Scope(in_scope=["*.example.com"])
    rep = recon.run("example.com", scope, passive_only=True,
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
    rep = recon.run("example.com", scope, do_checks=False, prober=fake_prober)
    assert "evil.com" not in touched
    assert set(touched) == {"a.example.com", "b.example.com"}
    assert rep["alive"] == 2
