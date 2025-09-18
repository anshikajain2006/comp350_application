import os
import sys
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

# Make sure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(_file_), "..")))

import auth_module as am


# --- Fixture: fresh temp DB for each test ---
@pytest.fixture
def fresh_module(tmp_path, monkeypatch):
    db_path = tmp_path / "pim.db"
    am.DB_FILE = str(db_path)

    # deterministic secret so HMAC signatures are stable
    fixed_secret = b"\x01" * 32
    monkeypatch.setenv("PIM_SERVER_SECRET_B64", fixed_secret.hex())

    # initialize schema
    con = am.get_db_connection()
    con.executescript(
        """
        CREATE TABLE Users(
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE FailedLogins(
            username TEXT PRIMARY KEY,
            fail_count INTEGER NOT NULL,
            last_failed_at TEXT
        );
        CREATE TABLE Sessions(
            session_token TEXT PRIMARY KEY,
            signature TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            user_agent TEXT,
            ip TEXT,
            FOREIGN KEY(user_id) REFERENCES Users(user_id) ON DELETE CASCADE
        );
        """
    )
    con.commit()
    con.close()
    return am


# ---------------------------- Tests ----------------------------

def test_hex_roundtrip(fresh_module):
    am = fresh_module
    data = b"hello world"
    hx = am.hex_encode(data)
    assert isinstance(hx, str)
    assert am.hex_decode(hx) == data


def test_hash_and_verify_password(fresh_module):
    am = fresh_module
    salt_hex, hash_hex = am.hash_password("s3cret!")
    assert len(salt_hex) == 2 * am.SALT_BYTES
    assert len(hash_hex) == 2 * am.HASH_BYTES
    assert am.verify_password("s3cret!", salt_hex, hash_hex)
    assert not am.verify_password("wrong", salt_hex, hash_hex)


def test_sign_deterministic(fresh_module):
    am = fresh_module
    s1 = am.sign("abc")
    s2 = am.sign("abc")
    assert s1 == s2
    assert len(s1) == 64
    assert int(s1, 16)  # valid hex


def test_create_new_user_and_duplicate(fresh_module):
    am = fresh_module
    user = am.create_new_user("alice", "pw")
    assert user.username == "alice"
    with pytest.raises(sqlite3.IntegrityError):
        am.create_new_user("alice", "other")


def test_validate_credentials_success_and_failure(fresh_module):
    am = fresh_module
    am.create_new_user("bob", "pw")
    uid = am.validate_credentials("bob", "pw")
    assert isinstance(uid, int)
    with pytest.raises(RuntimeError):
        am.validate_credentials("bob", "wrong")
    with pytest.raises(RuntimeError):
        am.validate_credentials("nosuch", "pw")


def test_login_and_session(fresh_module):
    am = fresh_module
    am.create_new_user("carl", "pw")
    token = am.login("carl", "pw", user_agent="UA", ip="127.0.0.1")
    assert token
    sessionid, sig = token.split("_", 1)
    assert sig == am.sign(sessionid)
    uid = am.db_get_session_user(sessionid)
    assert isinstance(uid, int)


def test_logout_and_access_revoked(fresh_module):
    am = fresh_module
    am.create_new_user("dina", "pw")
    token = am.login("dina", "pw")
    sessionid, _ = token.split("_", 1)
    assert am.logout(token)
    assert not am.logout(token)  # second logout = already gone
    with pytest.raises(RuntimeError):
        am.db_get_session_user(sessionid)

def test_cleanup_expired_sessions(fresh_module):
    am = fresh_module
    am.create_new_user("eva", "pw")
    good_token = am.login("eva", "pw")
    good_sessionid, _ = good_token.split("_", 1)

    # insert expired session manually
    con = am.get_db_connection()
    now = datetime.now(timezone.utc)
    con.execute(
        "INSERT INTO Sessions(session_token, signature, user_id, created_at, expires_at, user_agent, ip) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "expired123",
            am.sign("expired123"),
            1,
            (now - timedelta(days=2)).isoformat(),
            (now - timedelta(days=1)).isoformat(),
            "UA",
            "1.2.3.4",
        ),
    )
    con.commit()
    con.close()

    removed = am.cleanup_expired_sessions()
    assert removed >= 1
    assert am.db_get_session_user(good_sessionid)


def test_login_backoff_and_reset(fresh_module):
    am = fresh_module
    am.create_new_user("fred", "pw")
    for _ in range(3):
        assert am.login("fred", "wrong") is None
    assert am.login_backoff_seconds("fred") == 0

    # 4th failure triggers backoff (~2 minutes)
    assert am.login("fred", "wrong") is None
    wait = am.login_backoff_seconds("fred")
    assert wait > 0

    # simulate past unlock
    con = am.get_db_connection()
    past = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    con.execute(
        "UPDATE FailedLogins SET last_failed_at = ?, fail_count = ? WHERE username = ?",
        (past, 4, "fred"),
    )
    con.commit()
    con.close()

    token = am.login("fred", "pw")
    assert token
    assert am.login_backoff_seconds("fred") == 0


def test_session_expiry(fresh_module):
    am = fresh_module
    am.create_new_user("gina", "pw")
    token = am.login("gina", "pw")
    sessionid, _ = token.split("_", 1)
    con = am.get_db_connection()
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    con.execute("UPDATE Sessions SET expires_at = ? WHERE session_token = ?", (past, sessionid))
    con.commit()
    con.close()
    with pytest.raises(RuntimeError):
        am.db_get_session_user(sessionid)


def test_check_authorization(fresh_module):
    am = fresh_module
    assert am.check_authorization(1, "/foo")


def test_login_unknown_user_records_failure(fresh_module):
    am = fresh_module
    assert am.login("nosuch", "pw") is None
    con = am.get_db_connection()
    row = con.execute("SELECT fail_count FROM FailedLogins WHERE username=?", ("nosuch",)).fetchone()
    con.close()
    assert row and row[0] >= 1


def test_multiple_sessions_allowed(fresh_module):
    am = fresh_module
    am.create_new_user("harry", "pw")
    t1 = am.login("harry", "pw")
    t2 = am.login("harry", "pw")
    s1, _ = t1.split("_", 1)
    s2, _ = t2.split("_", 1)
    assert s1 != s2
    assert am.db_get_session_user(s1)
    assert am.db_get_session_user(s2)


def test_logout_invalid_format(fresh_module):
    am = fresh_module
    assert am.logout("notanunderscoretoken") is False