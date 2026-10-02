import pytest

from auth.oauth21_session_store import OAuth21SessionStore
from core.server import complete_google_auth

REDIRECT_URI = "http://localhost:9876/oauth2callback"
CALLBACK_URL = f"{REDIRECT_URI}?state=state-1&code=code-1&scope=openid"


@pytest.fixture
def legacy_oauth(monkeypatch):
    monkeypatch.setattr("core.server.is_oauth21_enabled", lambda: False)
    monkeypatch.setattr("core.server.check_client_secrets", lambda: None)
    monkeypatch.setattr(
        "core.server.get_oauth_redirect_uri_for_current_mode", lambda: REDIRECT_URI
    )


def _fail_if_called(**kwargs):  # noqa: ARG001
    raise AssertionError("handle_auth_callback should not run")


@pytest.mark.asyncio
async def test_passes_the_pasted_address_to_the_callback_handler(
    monkeypatch, legacy_oauth
):
    captured = {}

    async def fake_handle_auth_callback(**kwargs):
        captured.update(kwargs)
        return "user@gmail.com", object()

    monkeypatch.setattr("core.server.handle_auth_callback", fake_handle_auth_callback)

    result = await complete_google_auth(CALLBACK_URL)

    assert captured["authorization_response"] == CALLBACK_URL
    assert captured["redirect_uri"] == REDIRECT_URI
    assert captured["session_id"] is None
    assert "user@gmail.com" in result


@pytest.mark.asyncio
async def test_refuses_an_address_without_code_and_state(monkeypatch, legacy_oauth):
    monkeypatch.setattr("core.server.handle_auth_callback", _fail_if_called)

    result = await complete_google_auth(f"{REDIRECT_URI}?code=code-1")

    assert "no `code` and `state`" in result


@pytest.mark.asyncio
async def test_reports_the_error_google_returned(monkeypatch, legacy_oauth):
    monkeypatch.setattr("core.server.handle_auth_callback", _fail_if_called)

    result = await complete_google_auth(
        f"{REDIRECT_URI}?error=access_denied&state=state-1"
    )

    assert "access_denied" in result


@pytest.mark.asyncio
async def test_is_disabled_under_oauth21(monkeypatch):
    monkeypatch.setattr("core.server.is_oauth21_enabled", lambda: True)
    monkeypatch.setattr("core.server.handle_auth_callback", _fail_if_called)

    result = await complete_google_auth(CALLBACK_URL)

    assert "disabled when OAuth 2.1 is enabled" in result


@pytest.mark.asyncio
async def test_refuses_a_state_this_server_did_not_issue(
    monkeypatch, legacy_oauth, tmp_path
):
    store = OAuth21SessionStore(oauth_state_file=str(tmp_path / "oauth_states.json"))
    store.store_oauth_state("issued-here")
    monkeypatch.setattr("auth.google_auth.get_oauth21_session_store", lambda: store)

    result = await complete_google_auth(CALLBACK_URL)

    assert "Invalid or expired OAuth state" in result
    assert store.validate_and_consume_oauth_state("issued-here") is not None
