"""Tests des parsers d'agrégation, un par schéma de plateforme (formats réels)."""
from bb.aggregate import beginner, categorize, parse_program

H1 = {
    "handle": "acme", "name": "Acme", "url": "https://hackerone.com/acme",
    "offers_bounties": True, "submission_state": "open",
    "targets": {
        "in_scope": [
            {"asset_identifier": "*.acme.com", "asset_type": "WILDCARD"},
            {"asset_identifier": "https://api.acme.com/v1", "asset_type": "URL"},
            {"asset_identifier": "0xabc", "asset_type": "SMART_CONTRACT"},
        ],
        "out_of_scope": [{"asset_identifier": "internal.acme.com", "asset_type": "URL"}],
    },
}


def test_hackerone_scope_and_categories():
    p = parse_program("hackerone", H1)
    assert p.pays_cash and p.is_open and p.web_surface
    assert p.scope.allows("shop.acme.com")          # via *.acme.com
    assert not p.scope.allows("acme.com")           # apex NON couvert (conservateur)
    assert p.scope.allows("api.acme.com")           # via host de l'URL
    assert not p.scope.allows("internal.acme.com")  # out-of-scope l'emporte
    assert not p.scope.allows("evil.com")
    assert "web3" in p.categories                   # smart contract détecté, mais pas gaté
    assert p.wildcard_count >= 1


def test_yeswehack_parse():
    ywh = {
        "id": "acme-fr", "name": "Acme FR", "url": "https://yeswehack.com/programs/acme-fr",
        "public": True, "disabled": False, "min_bounty": 50, "max_bounty": 3000,
        "targets": {"in_scope": [
            {"target": "app.acme.fr", "type": "web-application"},
            {"target": "*.acme.fr", "type": "wildcard"},
        ]},
    }
    p = parse_program("yeswehack", ywh)
    assert p.pays_cash and p.max_bounty == 3000
    assert p.scope.allows("app.acme.fr")
    assert p.scope.allows("x.acme.fr")


def test_bugcrowd_parse():
    bc = {
        "name": "Bcorp", "url": "https://bugcrowd.com/bcorp", "max_payout": 5000,
        "targets": {"in_scope": [
            {"type": "api", "target": "http://api.bcorp.com/", "name": "API"},
            {"type": "website", "target": "*.bcorp.com"},
        ]},
    }
    p = parse_program("bugcrowd", bc)
    assert p.pays_cash and p.max_bounty == 5000
    assert p.scope.allows("api.bcorp.com")     # 'name' bruyant ignoré, 'target' utilisé
    assert p.scope.allows("z.bcorp.com")


def test_intigriti_parse():
    inti = {
        "handle": "icorp", "name": "Icorp", "url": "https://app.intigriti.com/programs/icorp",
        "status": "open", "min_bounty": 100, "max_bounty": 2000,
        "targets": {"in_scope": [{"type": "url", "endpoint": "app.icorp.io", "description": "main"}]},
    }
    p = parse_program("intigriti", inti)
    assert p.pays_cash and p.is_open
    assert p.scope.allows("app.icorp.io")


def test_federacy_parse():
    fed = {
        "id": "fcorp", "name": "Fcorp", "url": "https://federacy.com/fcorp", "offers_awards": True,
        "targets": {"in_scope": [{"type": "website", "target": "*.fcorp.com"}]},
    }
    p = parse_program("federacy", fed)
    assert p.pays_cash
    assert p.scope.allows("a.fcorp.com")


def test_beginner_filter():
    progs = [
        parse_program("hackerone", H1),
        parse_program("hackerone", {**H1, "offers_bounties": False}),      # pas de cash
        parse_program("hackerone", {**H1, "submission_state": "closed"}),  # fermé
    ]
    assert len(beginner(progs)) == 1


def test_construction_out_of_scope_is_inclusive():
    """À la construction, un out-of-scope sale/typé mobile doit QUAND MÊME bloquer."""
    raw = {
        "handle": "z", "name": "Z", "url": "u", "offers_bounties": True, "submission_state": "open",
        "targets": {
            "in_scope": [{"asset_identifier": "*.acme.com", "asset_type": "WILDCARD"}],
            "out_of_scope": [
                {"asset_identifier": "secret.acme.com", "asset_type": "mobile"},        # type non-web
                {"asset_identifier": "admin.acme.com (do not test)", "asset_type": ""},  # valeur sale
                {"asset_identifier": "danger.acme.com)", "asset_type": "url"},           # métacaractère
            ],
        },
    }
    p = parse_program("hackerone", raw)
    assert not p.scope.allows("secret.acme.com")   # bloqué malgré type mobile
    assert not p.scope.allows("admin.acme.com")    # host extrait de la valeur sale
    assert not p.scope.allows("danger.acme.com")   # ')' parasite nettoyé
    assert p.scope.allows("ok.acme.com")           # le reste du wildcard reste autorisé


def test_construction_rejects_catchall_from_feed():
    """Un asset de feed catch-all ('*', '*.com') ne doit JAMAIS ouvrir le scope."""
    for bad in ("*", "*.com", "https://*"):
        raw = {
            "name": "B", "url": "u", "offers_bounties": True, "submission_state": "open",
            "targets": {"in_scope": [{"asset_identifier": bad, "asset_type": "WILDCARD"}]},
        }
        p = parse_program("hackerone", raw)
        assert not p.scope.allows("evil.com"), f"fuite via {bad!r}"
        assert p.scope.in_scope == [], f"pattern dangereux {bad!r} non rejeté"


def test_starter_score_prefers_low_reports_and_fr():
    base = {
        "id": "x", "name": "X", "url": "u", "public": True,
        "min_bounty": 50, "max_bounty": 2000,
        "targets": {"in_scope": [{"target": "*.x.fr", "type": "wildcard"}]},
    }
    fresh = parse_program("yeswehack", base)
    fresh.country, fresh.reports_count = "FR", 40       # peu chassé
    saturated = parse_program("yeswehack", base)
    saturated.country, saturated.reports_count = "FR", 1800  # ratissé
    assert fresh.starter_score > saturated.starter_score

    # un méga-bounty US managed doit scorer moins qu'un petit FR frais
    mega = parse_program("hackerone", {
        "handle": "big", "name": "Big", "url": "u", "offers_bounties": True,
        "submission_state": "open", "managed_program": True,
        "targets": {"in_scope": [{"asset_identifier": "*.big.com", "asset_type": "WILDCARD"}]},
    })
    mega.max_bounty = 100000
    assert fresh.starter_score > mega.starter_score


def test_parse_program_handles_malformed_targets():
    """Un feed avec targets non-dict ne doit PAS crasher (robustesse)."""
    for bad in (["liste"], "chaine", 42, None):
        p = parse_program("hackerone", {"name": "T", "url": "u", "targets": bad})
        assert p is not None and p.scope.in_scope == []


def test_categorize():
    assert categorize("WILDCARD", "*.x.com") == "web"
    assert categorize("SMART_CONTRACT", "0xabc") == "web3"
    assert categorize("mobile-application-ios", "com.x") == "mobile"
    assert categorize("url", "app.x.com") == "web"
    assert categorize("HARDWARE", "device") == "hardware"
