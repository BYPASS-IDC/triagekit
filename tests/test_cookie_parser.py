"""Regression tests: cookie attribute parsing must not use naive substring matching."""
from triagekit.core.analyzers.web_scan import _parse_set_cookie_headers, _parse_set_cookie


def test_value_containing_secure_is_not_secure_flag():
    h = ["session=abcsecuredef; Path=/; HttpOnly"]
    parsed = _parse_set_cookie_headers(h)
    assert len(parsed) == 1
    assert parsed[0]["name"] == "session"
    assert parsed[0]["secure"] is False
    assert parsed[0]["httponly"] is True


def test_secure_and_httponly_attributes():
    h = ["sid=xyz; Path=/; Secure; HttpOnly; SameSite=Lax"]
    p = _parse_set_cookie_headers(h)[0]
    assert p["secure"] is True
    assert p["httponly"] is True
    assert p["samesite"] == "Lax"


def test_multiple_headers_not_split_on_expires_comma():
    h = ["a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/"]
    p = _parse_set_cookie_headers(h)
    assert len(p) == 1
    assert p[0]["name"] == "a"


def test_missing_flags_detected():
    h = ["token=abcdef123456; Path=/"]
    p = _parse_set_cookie_headers(h)[0]
    assert p["secure"] is False
    assert p["httponly"] is False
    assert p["samesite"] is None


def test_httponly_not_matched_inside_value():
    h = ["x=httponly_value_here; Path=/"]
    p = _parse_set_cookie_headers(h)[0]
    assert p["httponly"] is False
    assert p["secure"] is False


def test_samesite_none():
    h = ["c=1; Secure; SameSite=None"]
    p = _parse_set_cookie_headers(h)[0]
    assert p["secure"] is True
    assert str(p["samesite"]).lower() == "none"


def test_wrapper_single_header():
    p = _parse_set_cookie("id=1; Secure")
    assert len(p) == 1
    assert p[0]["secure"] is True


def test_two_headers_independent():
    h = [
        "a=1; Path=/",
        "b=2; Path=/; Secure; HttpOnly",
    ]
    p = _parse_set_cookie_headers(h)
    assert len(p) == 2
    assert p[0]["secure"] is False
    assert p[1]["secure"] is True and p[1]["httponly"] is True
