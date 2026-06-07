"""Tests du scope guard — le cœur légal. Si ça casse, on ne scanne rien."""
from bb.scope import Scope, normalize_host


def test_normalize_host_variants():
    assert normalize_host("https://Sub.Example.com/path?q=1") == "sub.example.com"
    assert normalize_host("sub.example.com:8443") == "sub.example.com"
    assert normalize_host("example.com.") == "example.com"
    assert normalize_host("") == ""
    assert normalize_host("   ") == ""
    # Données sales du monde réel : ne doit JAMAIS crasher (urlparse IPv6).
    assert normalize_host("//[bad") == ""
    assert normalize_host("http://]:[") == ""


def test_wildcard_matches_subdomains():
    s = Scope(in_scope=["*.example.com"])
    assert s.allows("shop.example.com")
    assert s.allows("https://a.b.example.com/x")


def test_wildcard_does_not_match_apex_conservative():
    # Choix volontaire: *.example.com ne couvre PAS example.com.
    s = Scope(in_scope=["*.example.com"])
    assert not s.allows("example.com")


def test_apex_explicit():
    s = Scope(in_scope=["example.com"])
    assert s.allows("example.com")
    assert not s.allows("sub.example.com")  # exact, pas de sous-domaines


def test_out_of_scope_wins():
    s = Scope(in_scope=["*.example.com"], out_of_scope=["admin.example.com"])
    assert not s.allows("admin.example.com")
    assert s.allows("shop.example.com")


def test_unknown_host_refused():
    s = Scope(in_scope=["*.example.com"])
    assert not s.allows("evil.com")
    assert not s.allows("notexample.com")  # pas un suffixe de .example.com


def test_empty_scope_refuses_everything():
    s = Scope()
    assert not s.allows("example.com")
    assert not s.allows("anything.com")


def test_glob_pattern():
    s = Scope(in_scope=["api-*.example.com"])
    assert s.allows("api-v2.example.com")
    assert not s.allows("web.example.com")


def test_yeswehack_regex_style_scope():
    # Format réel YesWeHack: alternations + schéma + path.
    s = Scope(in_scope=[
        "www.decathlon.(fr|ch|co.uk|it|nl|de|pt|es|be)",
        "https://(navigate|api).shoppingapp.decathlon.com/*",
    ])
    assert s.allows("www.decathlon.fr")
    assert s.allows("www.decathlon.co.uk")
    assert s.allows("https://api.shoppingapp.decathlon.com/cart")
    assert not s.allows("www.decathlon.us")        # pas dans l'alternation
    assert not s.allows("evil.com")
    assert not s.allows("shop.decathlon.com")      # host hors scope


def test_audit_regressions_no_scope_leak():
    """Cas issus de l'audit adversarial : aucun ne doit autoriser une cible hors-scope."""
    # Wildcard '*' ne traverse JAMAIS les points
    assert not Scope(in_scope=["*.com"]).allows("evil.com")
    assert not Scope(in_scope=["*"]).allows("anything.evil.com")
    assert not Scope(in_scope=["example.*"]).allows("example.evil.com")
    assert not Scope(in_scope=["*example.com"]).allows("evilexample.com")
    assert not Scope(in_scope=["*.example.*"]).allows("a.example.com.evil.com")
    # Injection regex via données de feed
    assert not Scope(in_scope=["a.example.com|evil.com"]).allows("evil.com")
    assert not Scope(in_scope=["shop.example.com|*.io"]).allows("evil.io")
    # Normalisation : backslash userinfo + newline collapse
    assert not Scope(in_scope=["allowed.com"]).allows("http://evil.com\\@allowed.com")
    assert not Scope(in_scope=["*.example.com"], out_of_scope=["admin.example.com"]).allows(
        "admin.example.com\nshop.example.com")


def test_legit_wildcards_still_work():
    """Les wildcards partiels et alternations LÉGITIMES doivent rester valides."""
    assert Scope(in_scope=["api-*.example.com"]).allows("api-v2.example.com")
    assert not Scope(in_scope=["api-*.example.com"]).allows("web.example.com")
    assert Scope(in_scope=["*.example.com"]).allows("a.b.deep.example.com")  # multi-niveau


def test_ip_canonicalization_out_of_scope():
    """Une IP hors-scope reste bloquée quelle que soit sa forme (decimal-int/hex/octal)."""
    s = Scope(in_scope=["1.2.3.4", "127.0.0.1"], out_of_scope=["127.0.0.1"])
    assert not s.allows("2130706433")   # 127.0.0.1 en décimal entier
    assert not s.allows("0x7f000001")   # 127.0.0.1 en hexadécimal
    assert s.allows("1.2.3.4")


def test_reason_is_explanatory():
    s = Scope(in_scope=["*.example.com"], out_of_scope=["admin.example.com"])
    assert "out-of-scope" in s.reason("admin.example.com")
    assert "AUTORISÉ" in s.reason("shop.example.com")
    assert "aucune règle" in s.reason("evil.com")
