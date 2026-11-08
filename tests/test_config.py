"""Tests for trustlens.config.Settings."""

from dataclasses import fields

import pytest

from trustlens.config import Settings, get_settings

# Every env var the settings object reads, taken from the field metadata.
ENV_VARS = tuple(f.metadata["env"] for f in fields(Settings) if "env" in f.metadata)


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a developer's real environment (or .env) out of these tests."""
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_defaults() -> None:
    settings = Settings()
    assert settings.anthropic_api_key == ""
    assert settings.urlhaus_api_key == ""
    assert settings.rpc_url == "http://127.0.0.1:8545"
    assert settings.contract_address == ""
    assert settings.private_key == ""
    assert settings.db_path == "trustlens.db"
    assert settings.offline_mode is False


@pytest.mark.parametrize("raw", ["1", "true", "TRUE", "yes", "on", " on "])
def test_offline_mode_true_values(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv("OFFLINE_MODE", raw)
    assert Settings().offline_mode is True


@pytest.mark.parametrize("raw", ["0", "false", "FALSE", "no", "", "off", "maybe"])
def test_offline_mode_false_values(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv("OFFLINE_MODE", raw)
    assert Settings().offline_mode is False


def test_env_values_override_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RPC_URL", "https://rpc.example.org")
    monkeypatch.setenv("DB_PATH", "/tmp/trustlens.db")
    settings = Settings()
    assert settings.rpc_url == "https://rpc.example.org"
    assert settings.db_path == "/tmp/trustlens.db"


def test_repr_masks_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    monkeypatch.setenv("URLHAUS_API_KEY", "urlhaus-secret")
    monkeypatch.setenv("PRIVATE_KEY", "0xdeadbeef")
    text = repr(Settings())
    assert "sk-ant-secret" not in text
    assert "urlhaus-secret" not in text
    assert "0xdeadbeef" not in text
    assert "sk-ant-secret" not in str(Settings())
    assert "***" in text


def test_repr_shows_non_secret_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DB_PATH", "custom.db")
    text = repr(Settings())
    assert "custom.db" in text
    assert "http://127.0.0.1:8545" in text


def test_repr_leaves_empty_secrets_empty() -> None:
    assert "***" not in repr(Settings())


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()
