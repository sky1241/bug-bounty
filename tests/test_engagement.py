"""Tests de la gestion des engagements (dossier isolé par programme)."""
from bb.engagement import create, load_scope, slugify
from bb.scope import Scope


def test_slugify():
    assert slugify("BlaBlaCar Bug Bounty!") == "blablacar-bug-bounty"
    assert slugify("  Doctolib  ") == "doctolib"
    assert slugify("") == "engagement"


def test_create_and_load_scope(tmp_path):
    s = Scope(in_scope=["*.x.com"], out_of_scope=["admin.x.com"])
    d = create("Acme FR", s, base=tmp_path)
    assert (d / "scope.json").exists()
    assert (d / "recon").is_dir() and (d / "findings").is_dir()
    assert (d / "README.md").exists()
    loaded = load_scope("Acme FR", base=tmp_path)
    assert loaded.in_scope == ["*.x.com"] and loaded.out_of_scope == ["admin.x.com"]


def test_create_idempotent_preserves_data(tmp_path):
    create("X", Scope(in_scope=["*.x.com"]), base=tmp_path)
    keep = tmp_path / "x" / "findings" / "keep.txt"
    keep.write_text("data")
    create("X", Scope(in_scope=["*.x.com"]), base=tmp_path)  # re-création
    assert keep.read_text() == "data"                        # rien d'écrasé
