"""Tests for legacy session-token auth helpers."""


def test_legacy_session_token_helpers_exist_and_work():
    from middleware import auth

    assert hasattr(auth, "get_session_token")
    assert hasattr(auth, "create_new_session")
    assert hasattr(auth, "verify_session")

    master = auth.get_session_token()
    assert isinstance(master, str)
    assert master
    assert auth.verify_session(master) is True

    session = auth.create_new_session()
    assert isinstance(session, str)
    assert session
    assert auth.verify_session(session) is True

    assert auth.verify_session("not-a-real-token") is False
