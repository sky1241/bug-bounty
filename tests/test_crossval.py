"""Tests de la validation croisée anti-hallucination (delta de résultats indépendants)."""
from bb.crossval import cross_verify, delta
from bb.fleet import Node
from bb.scope import Scope


def test_delta_consensus_and_divergence():
    a = {"hosts": [{"host": "x.com"}, {"host": "y.com"}, {"host": "z.com"}]}
    b = {"hosts": [{"host": "x.com"}, {"host": "y.com"}, {"host": "w.com"}]}
    d = delta(a, b)
    assert d["consensus"] == ["x.com", "y.com"]      # vu par les 2 = confiance
    assert d["only_a"] == ["z.com"] and d["only_b"] == ["w.com"]  # delta = à revérifier
    assert 0 < d["agreement"] < 1


def test_delta_urls_key():
    a = {"url_list": ["http://a/1", "http://a/2"]}
    b = {"url_list": ["http://a/1"]}
    d = delta(a, b, key="url_list")
    assert d["consensus"] == ["http://a/1"] and d["only_a"] == ["http://a/2"]


def test_delta_perfect_agreement_is_reliable():
    a = {"hosts": [{"host": "x.com"}]}
    d = delta(a, a)
    assert d["agreement"] == 1.0 and "FIABLE" in d["verdict"]


def test_delta_strong_divergence_is_suspect():
    a = {"hosts": [{"host": "a.com"}, {"host": "b.com"}]}
    b = {"hosts": [{"host": "c.com"}, {"host": "d.com"}]}
    d = delta(a, b)
    assert d["agreement"] == 0.0 and "SUSPECT" in d["verdict"]


def test_cross_verify_runs_both_nodes_and_computes_delta():
    calls = []

    def fake(node, domain, scope):
        calls.append(node.name)
        return {"hosts": [{"host": "x.com"}, {"host": f"{node.name}.com"}]}

    d = cross_verify("ex.com", Scope(in_scope=["*.com"]), Node("pc1"), Node("pc3"), runner=fake)
    assert set(calls) == {"pc1", "pc3"}
    assert d["consensus"] == ["x.com"]               # le host commun
    assert d["nodes"] == ["pc1", "pc3"]
    assert {"pc1.com", "pc3.com"} <= set(d["only_a"] + d["only_b"])  # les uniques sont des deltas
