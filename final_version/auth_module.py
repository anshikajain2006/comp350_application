from __future__ import annotations
from typing import Optional
import os
import hmac
import uuid
import secrets
import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
import base64

# SQL Database configuration
DB_FILE = "pim.db"
COOKIE_NAME = "session"

# Password hashing details
PBKDF_ALGO = "sha256"
PBKDF_ITER = 200_000
SALT_BYTES = 32
HASH_BYTES = 32

# Generate server secret for session signing
b64 = os.environ.get("PIM_SERVER_SECRET_B64") 
if b64:
    server_secret = base64.urlsafe_b64decode(b64.encode())
else:
    server_secret = secrets.token_bytes(32)

# Data structure
@dataclass
class User:
    user_id: Optional[int]
    username: str
    password: str
    token: Optional[str]

def get_db_connection():
    """Get database connection with foreign key support."""
    con = sqlite3.connect(DB_FILE, check_same_thread=False)
    con.execute("PRAGMA foreign_keys = ON")
    return con

# Password encryption helper functions
def hex_encode(b: bytes) -> str:
    """Convert bytes to hexadecimal string.
    
    :param b: Byte string to convert
    :type b: bytes
    :return: Hexadecimal string
    :rtype: str
    """
    return b.hex()

def hex_decode(s: str) -> bytes:
    """Convert hexadecimal string to bytes.
    
    :param s: Hexadecimal string to convert
    :type s: str
    :return: Byte string
    :rtype: bytes
    """
    return bytes.fromhex(s or "")

def hash_password(plain: str) -> tuple[str, str]:
    """Hash a password with salt using PBKDF2.
    
    :param plain: Plain text password
    :type plain: str
    :return: Tuple of (salt_hex, hash_hex)
    :rtype: tuple[str, str]
    """
    salt = os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(PBKDF_ALGO, plain.encode(), salt, PBKDF_ITER, dklen=HASH_BYTES)
    return hex_encode(salt), hex_encode(digest)

def verify_password(plain: str, salt_hex: str, hash_hex: str) -> bool:
    """Verify a password against stored hash.
    
    :param plain: Plain text password to verify
    :type plain: str
    :param salt_hex: Stored salt in hex format
    :type salt_hex: str
    :param hash_hex: Stored hash in hex format
    :type hash_hex: str
    :return: True if password matches
    :rtype: bool
    """
    if not salt_hex or not hash_hex:
        return False
    
    test_digest = hashlib.pbkdf2_hmac(
        PBKDF_ALGO, 
        plain.encode(), 
        hex_decode(salt_hex), 
        PBKDF_ITER, 
        dklen=len(hex_decode(hash_hex))
    )
    return hmac.compare_digest(test_digest, hex_decode(hash_hex))

# Login lockout implementation functions
def login_backoff_seconds(username: str) -> int:
    """Calculate lockout seconds for a user based on failed attempts.
    
    :param username: Username to check
    :type username: str
    :return: Seconds until user can attempt login again
    :rtype: int
    """
    con = get_db_connection()
    row = con.execute(
        "SELECT fail_count, last_failed_at FROM FailedLogins WHERE username = ?", 
        (username,)
    ).fetchone()
    con.close()
    
    if not row:
        return 0
    
    fails, last = row
    if not last or fails <= 3:
        return 0
    
    last_dt = datetime.fromisoformat(last)
    minutes = min(2 ** (fails - 3), 30) 
    unlock_time = last_dt + timedelta(minutes=minutes)
    return max(0, int((unlock_time - datetime.now(timezone.utc)).total_seconds()))

def record_login_failure(username: str) -> None:
    """Record a failed login attempt.
    
    :param username: Username that failed to login
    :type username: str
    """
    con = get_db_connection()
    row = con.execute("SELECT fail_count FROM FailedLogins WHERE username = ?", (username,)).fetchone()
    now = datetime.now(timezone.utc).isoformat()
    
    if row:
        con.execute(
            "UPDATE FailedLogins SET fail_count = fail_count + 1, last_failed_at = ? WHERE username = ?", 
            (now, username)
        )
    else:
        con.execute(
            "INSERT INTO FailedLogins(username, fail_count, last_failed_at) VALUES (?, ?, ?)", 
            (username, 1, now)
        )
    
    con.commit()
    con.close()

def reset_login_failures(username: str) -> None:
    """Reset failed login attempts for a user.
    
    :param username: Username to reset
    :type username: str
    """
    con = get_db_connection()
    con.execute("DELETE FROM FailedLogins WHERE username = ?", (username,))
    con.commit()
    con.close()

# Session signature functions
def sign(text: str) -> str:
    """Generate HMAC signature for session token.
    
    :param text: Text to sign
    :type text: str
    :return: Hex-encoded signature
    :rtype: str
    """
    return hmac.digest(server_secret, text.encode(), 'sha256').hex()

# User authentication functions
def create_new_user(name: str, pw: str) -> User:
    """Create a new user with hashed password.
    
    :param name: Username
    :type name: str
    :param pw: Plain text password
    :type pw: str
    :return: Created user object
    :rtype: User
    :raises sqlite3.IntegrityError: If username already exists
    """
    salt_hex, hash_hex = hash_password(pw)
    con = get_db_connection()
    
    con.execute(
        "INSERT INTO Users(username, password_salt, password_hash) VALUES (?, ?, ?)",
        (name, salt_hex, hash_hex)
    )
    con.commit()

    user_id = con.execute(
        "SELECT user_id FROM Users WHERE username = ?",
        (name,)
    ).fetchone()[0]
    
    con.close()
    return User(user_id=user_id, username=name, password="*", token=None)

def login(username: str, password: str, user_agent: str = None, ip: str = None) -> Optional[str]:
    """Login user and create session."""
    # Check login backoff
    wait = login_backoff_seconds(username)
    if wait > 0:
        raise RuntimeError(f"Too many attempts. Try again in {wait} seconds.")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id, password_salt, password_hash FROM Users WHERE username=?", (username,))
    row = cur.fetchone()

    if not row:
        record_login_failure(username)
        conn.close()
        return None

    user_id, stored_salt, stored_hash = row
    if not verify_password(password, stored_salt, stored_hash):
        record_login_failure(username)
        conn.close()
        return None

    # Password is correct - reset login failures
    reset_login_failures(username)

    sessionid = secrets.token_urlsafe(16)
    signature = sign(sessionid)
    now_dt = datetime.now(timezone.utc)
    exp_dt = now_dt + timedelta(days=7)

    conn.execute("""
        INSERT INTO Sessions(session_token, signature, user_id, created_at, expires_at, user_agent, ip)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        sessionid,
        signature,
        user_id,
        now_dt.isoformat(),
        exp_dt.isoformat(),
        user_agent,
        ip
    ))
    conn.commit()
    conn.close()
    
    return f"{sessionid}_{signature}"

def logout(session_token: str) -> bool:
    """Log out user by deleting session.
    
    :param session_token: Full session token string
    :type session_token: str
    :return: True if session was deleted
    :rtype: bool
    """
    sessionid = session_token.split("_", 1)[0]
    con = get_db_connection()
    cur = con.execute("DELETE FROM Sessions WHERE session_token = ?", (sessionid,))
    con.commit()
    con.close()
    return cur.rowcount > 0

def db_get_session_user(sessionid: str) -> int:
    """Get user ID for a valid session.
    
    :param sessionid: Session ID (without signature)
    :type sessionid: str
    :return: User ID
    :rtype: int
    :raises RuntimeError: If session is expired or invalid
    """
    now = datetime.now(timezone.utc).isoformat()
    con = get_db_connection()
    row = con.execute(
        "SELECT user_id FROM Sessions WHERE session_token = ? AND expires_at > ?",
        (sessionid, now)
    ).fetchone()
    con.close()
    
    if not row:
        raise RuntimeError("Session expired or invalid")
    return row[0]

def validate_credentials(username: str, password: str) -> int:
    """Validate user credentials and return user ID.
    
    :param username: Username
    :type username: str
    :param password: Plain text password
    :type password: str
    :return: User ID if valid
    :rtype: int
    :raises RuntimeError: If credentials are invalid or user is locked out
    """
    wait = login_backoff_seconds(username)
    if wait > 0:
        raise RuntimeError(f"Too many attempts. Try again in {wait} seconds.")

    con = get_db_connection()
    row = con.execute(
        "SELECT user_id, password_salt, password_hash FROM Users WHERE username = ?",
        (username,)
    ).fetchone()
    con.close()
    
    if not row:
        record_login_failure(username)
        raise RuntimeError("Invalid credentials")

    user_id, salt_hex, hash_hex = row
    if not verify_password(password, salt_hex, hash_hex):
        record_login_failure(username)
        raise RuntimeError("Invalid credentials")

    reset_login_failures(username)
    return user_id

def check_authorization(userid: int, resource: str) -> bool:
    """Check if user is authorized for resource (placeholder implementation).
    
    :param userid: User ID
    :type userid: int
    :param resource: Resource path
    :type resource: str
    :return: True if authorized
    :rtype: bool
    """
    return True

# Session removed function
def cleanup_expired_sessions() -> int:
    """Remove expired sessions from database.
    
    :return: Number of sessions removed
    :rtype: int
    """
    now = datetime.now(timezone.utc).isoformat()
    con = get_db_connection()
    cur = con.execute("DELETE FROM Sessions WHERE expires_at <= ?", (now,))
    con.commit()
    con.close()
    return cur.rowcount