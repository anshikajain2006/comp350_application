import sqlite3
from dataclasses import asdict, dataclass
from typing import List,Optional
from datetime import datetime
import auth_module
import particle_module

# importing tables
DB_FILE = "pim.db"
con = sqlite3.connect(DB_FILE, check_same_thread=False) #added so that
# only the thread that issues this command may use it
con.execute("PRAGMA foreign_keys = ON") # ensures that you cannot insert/update/
#delete file if they are being references elsewhere

# creating the necessary tables: Users, Sessions
# FailedLogins table will be used to implement lockout as necessary
con.executescript(
"""
CREATE TABLE IF NOT EXISTS Users(
  user_id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  password TEXT,           -- legacy/unused
  token TEXT,              -- compatibility with particles.py
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
"""
)
cur = con.cursor()
con.commit()

# Necessary data structures to store Users and Particles
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

def convert_to_csstring(lst: list) -> str:
    """
    Convert a list of strings into a single comma-separated string.

    :param lst: List of string values to convert
    :type lst: list
    :return: Comma-separated string representation of the list
    :rtype: str
    """
    return ",".join(lst) if lst else ""


def cstring_to_list(cstring: str) -> list:
    """
    Convert a comma-separated string into a list of strings.

    :param cstring: Comma-separated string to convert
    :type cstring: str
    :return: List of strings obtained from the input string
    :rtype: list
    """
    return cstring.split(",") if cstring else []


def store_user(user: User) -> None:
    """
    Store a User object into the Users table in the database.

    :param user: User object containing username, password, and token
    :type user: User
    :raises sqlite3.Error: If the INSERT operation fails
    :return: None
    :rtype: None
    """
    user_dict = asdict(user)
    # Remove user_id as it is AUTOINCREMENT
    del user_dict["user_id"]
    return cur.execute(
        'INSERT INTO Users(username, password, token) VALUES (:username, :password, :token)', 
        user_dict
    ) and con.commit()


def store_particle(particle: Particle) -> None:
    """
    Store a Particle object into the Particles table in the database.

    :param particle: Particle object containing metadata (title, body, tags, references, etc.)
    :type particle: Particle
    :raises sqlite3.Error: If the INSERT operation fails
    :return: None
    :rtype: None
    """
    particle_dict = asdict(particle)
    del particle_dict["particle_id"]
    particle_dict["tags"] = convert_to_csstring(particle_dict["tags"])
    particle_dict["particle_references"] = convert_to_csstring(particle_dict["particle_references"])
    return cur.execute(
        'INSERT INTO Particles(date_created, date_updated, title, body, tags, particle_references) '
        'VALUES (:date_created, :date_updated, :title, :body, :tags, :particle_references)', 
        particle_dict
    ) and con.commit()

#test block 3
# tests have been commented out
#alvin = User(None, "alvin", "chipmunks", None)
#alvin_particle = Particle(None, datetime.now(), datetime.now(), "title", "body", [], [])
#store_user(alvin)
#store_particle(alvin_particle)
