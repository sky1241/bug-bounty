"""Tests du retry réseau de `_fetch` (sources) — un blip ne doit pas alerter."""
from unittest import mock

import pytest
import requests

from bb import sources


class _FakeResp:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            e = requests.HTTPError(f"HTTP {self.status_code}")
            e.response = self
            raise e

    def json(self):
        return self._data


def test_fetch_retries_then_succeeds():
    """2 blips transitoires puis succès => _fetch retente et finit par réussir."""
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] < 3:
            raise requests.ConnectionError("blip")
        return _FakeResp({"ok": True})

    with mock.patch("requests.get", flaky):
        out = sources._fetch("http://x", retries=3, backoff=0)
    assert out == {"ok": True}
    assert calls["n"] == 3  # a bien retenté 2 fois avant de réussir


def test_fetch_4xx_no_retry():
    """Un 4xx est permanent => on lève tout de suite, sans retenter."""
    calls = {"n": 0}

    def http404(*a, **k):
        calls["n"] += 1
        return _FakeResp(None, status=404)

    with mock.patch("requests.get", http404):
        with pytest.raises(requests.HTTPError):
            sources._fetch("http://x", retries=3, backoff=0)
    assert calls["n"] == 1  # pas de retry inutile sur erreur permanente


def test_fetch_gives_up_after_retries():
    """Source vraiment down => lève après `retries` essais (l'alerte est préservée)."""
    calls = {"n": 0}

    def always_fail(*a, **k):
        calls["n"] += 1
        raise requests.ConnectionError("down")

    with mock.patch("requests.get", always_fail):
        with pytest.raises(requests.ConnectionError):
            sources._fetch("http://x", retries=3, backoff=0)
    assert calls["n"] == 3  # N essais puis abandon => update() loggue ÉCHEC


def test_fetch_5xx_retries():
    """Un 5xx serveur est transitoire => on retente."""
    calls = {"n": 0}

    def http503(*a, **k):
        calls["n"] += 1
        if calls["n"] < 2:
            return _FakeResp(None, status=503)
        return _FakeResp({"ok": 1})

    with mock.patch("requests.get", http503):
        out = sources._fetch("http://x", retries=3, backoff=0)
    assert out == {"ok": 1}
    assert calls["n"] == 2
