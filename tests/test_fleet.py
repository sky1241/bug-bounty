"""Tests de la distribution fleet (logique de répartition, sans réseau)."""
from bb.fleet import Node, distribute, plan, shard, scope_payload
from bb.scope import Scope


def test_shard_balanced_and_complete():
    items = list(range(10))
    shards = shard(items, 3)
    assert len(shards) == 3
    flat = [x for s in shards for x in s]
    assert sorted(flat) == items                    # aucune perte, aucun doublon
    assert max(len(s) for s in shards) - min(len(s) for s in shards) <= 1  # équilibré


def test_shard_more_nodes_than_items():
    shards = shard(["a", "b"], 5)
    assert sum(len(s) for s in shards) == 2         # pas d'invention


def test_plan_respects_weight():
    nodes = [Node("pc1", weight=2), Node("pc3", weight=1)]
    domains = [f"d{i}.example.com" for i in range(9)]
    by_node = plan(domains, nodes)
    # pc1 (poids 2) doit recevoir ~2x plus que pc3
    assert len(by_node["pc1"]) > len(by_node["pc3"])
    alld = sorted(by_node["pc1"] + by_node["pc3"])
    assert alld == sorted(domains)                  # couverture complète


def test_distribute_calls_runner_per_node():
    calls = []

    def fake_runner(node, doms, scope):
        calls.append((node.name, tuple(doms)))
        return {"node": node.name, "ok": True, "results": {"in_scope": len(doms)}}

    nodes = [Node("pc1"), Node("pc3")]
    domains = ["a.example.com", "b.example.com", "c.example.com"]
    res = distribute(domains, Scope(in_scope=["*.example.com"]), nodes, runner=fake_runner)
    assert {r["node"] for r in res} == {"pc1", "pc3"}
    # chaque domaine est assigné exactement une fois
    assigned = sorted(d for _, doms in calls for d in doms)
    assert assigned == sorted(domains)


def test_scope_payload_roundtrip():
    import json
    s = Scope(in_scope=["*.example.com"], out_of_scope=["admin.example.com"])
    d = json.loads(scope_payload(s))
    assert d["in_scope"] == ["*.example.com"] and d["out_of_scope"] == ["admin.example.com"]
