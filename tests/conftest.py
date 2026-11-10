import pytest


@pytest.fixture(autouse=True)
def no_update_check(monkeypatch):
    monkeypatch.setenv("LSWIFI_NO_UPDATE_CHECK", "1")
