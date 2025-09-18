import sqlite3
from dataclasses import dataclass, asdict
from typing import Optional, List
from datetime import datetime
import json

# Database configuration
DB_FILE = "pim.db"

# Data structures
@dataclass
class User:
    user_id: Optional[int]
    username: str
    password: str
    token: Optional[str]

@dataclass
class Particle:
    particle_id: Optional[int]
    date_created: datetime
    date_updated: datetime
    title: str
    body: str
    tags: List[str]
    particle_references: List[str]

# Database initialization
def init_database(db_path: str = DB_FILE) -> None:
    """
    Initialize database schema if not present.
    
    :param db_path: Path to SQLite database file
    :type db_path: str
    """
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS Users(
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT,
            token TEXT,
            password_salt TEXT,
            password_hash TEXT
        );

        CREATE TABLE IF NOT EXISTS Sessions(
            session_token TEXT PRIMARY KEY,
            signature TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            user_agent TEXT,
            ip TEXT,
            FOREIGN KEY(user_id) REFERENCES Users(user_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS FailedLogins(
            username TEXT PRIMARY KEY,
            fail_count INTEGER NOT NULL DEFAULT 0,
            last_failed_at TEXT
        );
    """)

    # accounts for any inconsistencies in the code, which were causing issues previously
    cursor = conn.execute("PRAGMA table_info(Particles)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'Particles' in [name for name, in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]:
        if 'user_id' not in columns:
            conn.execute("DROP TABLE IF EXISTS Particles")
    
    conn.commit()
    conn.close()

# Helper functions for list/string conversion
def convert_to_csstring(lst: List[str]) -> str:
    """
    Convert a list of strings into a single comma-separated string.

    :param lst: List of string values to convert
    :type lst: List[str]
    :return: Comma-separated string representation of the list
    :rtype: str
    """
    return ",".join(lst) if lst else ""

def cstring_to_list(cstring: str) -> List[str]:
    """
    Convert a comma-separated string into a list of strings.

    :param cstring: Comma-separated string to convert
    :type cstring: str
    :return: List of strings obtained from the input string
    :rtype: List[str]
    """
    return cstring.split(",") if cstring else []

# Storage functions
def store_user(user: User, db_path: str = DB_FILE) -> None:
    """
    Store a User object into the Users table in the database.

    :param user: User object containing username, password, and token
    :type user: User
    :param db_path: Path to database file
    :type db_path: str
    :raises sqlite3.Error: If the INSERT operation fails
    :return: None
    :rtype: None
    """
    conn = sqlite3.connect(db_path, check_same_thread=False)
    cur = conn.cursor()
    
    user_dict = asdict(user)
    del user_dict["user_id"]
    
    cur.execute(
        'INSERT INTO Users(username, password, token) VALUES (?, ?, ?)', 
        (user_dict["username"], user_dict["password"], user_dict["token"])
    )
    conn.commit()
    conn.close()

def store_particle(particle: Particle, db_path: str = DB_FILE) -> None:
    """
    Store a Particle object into the Particles table in the database.
    Note: This function is deprecated - use particle_module functions instead.

    :param particle: Particle object containing metadata (title, body, tags, references, etc.)
    :type particle: Particle
    :param db_path: Path to database file
    :type db_path: str
    :raises sqlite3.Error: If the INSERT operation fails
    :return: None
    :rtype: None
    """
    # has been moved to particle module due to compatibility issues
    pass 

# Initialize database on import
init_database()