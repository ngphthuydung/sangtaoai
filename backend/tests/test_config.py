import secrets

import pytest
from app.core.config import load_settings


def test_missing_secret_key_reports_configuration_error(monkeypatch, tmp_path):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(RuntimeError, match="SECRET_KEY must be set"):
        load_settings()


def test_secret_key_loads_from_environment_and_is_masked(monkeypatch):
    generated_secret = secrets.token_urlsafe(32)
    monkeypatch.setenv("SECRET_KEY", generated_secret)

    configuration = load_settings()

    assert secrets.compare_digest(
        configuration.SECRET_KEY.get_secret_value(), generated_secret
    )
    assert str(configuration.SECRET_KEY) == "**********"