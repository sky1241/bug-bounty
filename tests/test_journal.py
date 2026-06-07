"""Tests du journal (historique append-only)."""
from bb import journal


def test_record_and_load_roundtrip(tmp_path):
    p = tmp_path / "log.jsonl"
    journal.record("recon", "example.com", path=p, in_scope=3, alive=2)
    journal.record("finding", "app.example.com", path=p, title="IDOR", severity="medium")
    events = journal.load(p)
    assert len(events) == 2
    assert events[0]["type"] == "recon" and events[0]["target"] == "example.com"
    assert events[0]["in_scope"] == 3
    assert all("ts" in e for e in events)          # tout est daté


def test_append_only(tmp_path):
    p = tmp_path / "log.jsonl"
    journal.record("note", "x", path=p, note="première")
    journal.record("note", "x", path=p, note="seconde")
    assert len(journal.load(p)) == 2               # rien n'est écrasé


def test_search_by_type_and_query(tmp_path):
    p = tmp_path / "log.jsonl"
    journal.record("finding", "a.example.com", path=p, title="IDOR")
    journal.record("false_positive", "b.example.com", path=p, note="self-XSS")
    journal.record("finding", "c.example.com", path=p, title="XSS stored")
    assert len(journal.search(event_type="finding", path=p)) == 2
    assert len(journal.search("self-xss", path=p)) == 1
    assert len(journal.search("idor", event_type="finding", path=p)) == 1


def test_summary_counts(tmp_path):
    p = tmp_path / "log.jsonl"
    journal.record("recon", "example.com", path=p)
    journal.record("finding", "a.example.com", path=p)
    journal.record("finding", "a.example.com", path=p)
    s = journal.summary(p)
    assert s["events"] == 3
    assert s["by_type"]["finding"] == 2
    assert "example.com" in s["targets"]


def test_corrupt_line_is_skipped(tmp_path):
    p = tmp_path / "log.jsonl"
    journal.record("note", "x", path=p, note="ok")
    with p.open("a") as f:
        f.write("{ ceci n'est pas du json\n")
    assert len(journal.load(p)) == 1               # l'historique reste lisible
