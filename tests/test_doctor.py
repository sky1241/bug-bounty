"""Tests du diagnostic doctor."""
from bb import doctor


def test_doctor_report_shape():
    rep = doctor.check()
    assert set(rep) >= {"python_deps", "pd_tools", "ready", "warnings"}
    assert set(rep["pd_tools"]) == {"subfinder", "httpx", "nuclei"}
    assert isinstance(rep["ready"], bool)
    assert "requests" in rep["python_deps"]      # dépendance requise listée
    assert isinstance(rep["warnings"], list)
