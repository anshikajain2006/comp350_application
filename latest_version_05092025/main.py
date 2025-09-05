from __future__ import annotations
from fastapi import FastAPI, Request, Response, HTTPException, status, Cookie, Depends
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from dataclasses import dataclass, asdict
from typing import Optional, Iterable, Annotated, Tuple, List
import os
import hmac
import uuid
import json
import secrets
import hashlib
import sqlite3
from datetime import datetime, timedelta

import new_pim as pim

app = FastAPI()

app.mount("/static", StaticFiles(directory="static", html = True), name="static")

@app.get("/", response_class=HTMLResponse)
def display_pim_loginpage():
    return FileResponse("static/login.html")

@app.get("/search", response_class=HTMLResponse)
def display_pim_searchpage():
    return FileResponse("static/login.html")

@app.get("/extended_particle_viewer", response_class=HTMLResponse)
def display_pim_extended_particle_viewer():
    return FileResponse("static/viewer.html")

@app.get("/particle_editor", response_class=HTMLResponse)
def display_pim_particle_editor():
    return FileResponse("static/editor.html")

con = sqlite3.connect("pim.db", check_same_thread=False)
con.execute("PRAGMA foreign_keys = ON")

con.execute("""
CREATE TABLE IF NOT EXISTS Users(
  user_id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  -- legacy plaintext column (kept temporarily):
  password TEXT,
  password_salt TEXT,
  password_hash TEXT
);
""")

con.execute("""
CREATE TABLE IF NOT EXISTS Particles(
  particle_id INTEGER PRIMARY KEY AUTOINCREMENT,
  date_created TEXT,
  date_updated TEXT,
  title TEXT,
  body TEXT,
  tags TEXT,
  particle_references TEXT
);
""")

con.execute("""
CREATE TABLE IF NOT EXISTS Sessions(
  session_token TEXT PRIMARY KEY,         -- uuid4 string (we'll store full cookie 'sessionid')
  signature TEXT NOT NULL,                -- HMAC signature for the sessionid
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  user_agent TEXT,
  ip TEXT,
  FOREIGN KEY(user_id) REFERENCES Users(user_id) ON DELETE CASCADE
);
""")

con.execute("""
CREATE TABLE IF NOT EXISTS FailedLogins(
  username TEXT PRIMARY KEY,
  fail_count INTEGER NOT NULL DEFAULT 0,
  last_failed_at TEXT
);
""")

con.commit()


@dataclass
class User:
  id: int | None # will be added via sql
  username: str
  password: str
  token: str | None

@dataclass
class Particle:
  id: int | None # will be added via sql
  date_created: datetime
  date_updated: datetime
  title: str
  body: str
  tags: list[str]
  particle_references: list[str]

_PBKDF_ALGO = "sha256"
_PBKDF_ITER = 200_000
_SALT_BYTES = 32
_HASH_BYTES = 32
CSRF_COOKIE = "csrf"


# User Module
@app.get("/")
def handler_hex(b: bytes):
    return pim._hex(b)

@app.get("/")
def handler_unhex(s: str):
    return pim._unhex(s)

@app.get("/")
def handler_hash_password(plain: str):
    return pim.hash_password(plain)

@app.get("/")
def handler_verify_password(plain: str, salt_hex: str, hash_hex: str):
    return pim.verify_password(plain, salt_hex, hash_hex)

@app.get("/")
def handler_login_backoff_seconds(username: str):
    return pim._login_backoff_seconds(username)

@app.get("/")
def handler_record_login_failure(username: str):
    return pim._record_login_failure(username)

@app.put("/")
def handler_reset_login_failures(username: str):
    return pim._reset_login_failures(username)

# Cookie Funcions
@app.post("/")
def handler_set_csrf_cookie(resp: Response):
    return pim.set_csrf_cookie(resp)

@app.post("/")
def handler_csrf_protect(request: Request, csrf_cookie: Annotated[Optional[str], Cookie(alias=CSRF_COOKIE)] = None):
    return pim.csrf_protect(request, csrf_cookie, Cookie) # something is wrong with this

class Credentials(BaseModel):
    username: str
    password: str

server_secret_key = secrets.token_bytes(nbytes=32)

@app.get("/")
def sign(text: str):
    return pim.sign(text)

@app.get("/") 
def handler_login(username: str, password: str,  *, user_agent: Optional[str] = None, ip: Optional[str] = None):
    return pim.login(username, password, user_agent, ip)

@app.put("/")
def handler_logout(session_token: str):
    return pim.logout(session_token)

@app.post("/")
def handler_create_new_user(username: str, password: str): #type-casting it to User breaks the function
    return pim.create_new_user(username, password)

@app.get("/")
def handler_validate_credentials(username: str, password: str):
    return pim.validate_credentials(username, password)

@app.get("/")
def handler_db_get_session_user(sessionid: str):
    return pim.db_get_session_user(sessionid)

@app.get("/")
def handler_check_authorization(userid: int, resource: str):
    return pim.check_authorization(userid, resource)

@app.post("/")
def handler_seed_if_empty():
    return pim._seed_if_empty()

COOKIE_NAME = "session"

# >>> Your /signin and /someresource blocks (kept and completed) <<<
@app.post("/signin")
def signin(creds: Credentials, request: Request):
    # validate (updates rate-limit counters under the hood)
    user_id = handler_validate_credentials(creds.username, creds.password)
    # Your flow: create session id + signature, set cookie
    sessionid = secrets.token_urlsafe(nbytes=16)
    signature = sign(sessionid)

    # associate in DB (server-side session store)
    now = datetime.utcnow()
    exp = now + timedelta(days=1)  # 86400 seconds as in your example
    con.execute("""
      INSERT INTO Sessions(session_token, signature, user_id, created_at, expires_at, user_agent, ip)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (sessionid, signature, user_id, now.isoformat(), exp.isoformat(),
          request.headers.get("user-agent"), request.client.host if request.client else None))
    con.commit()

    response = JSONResponse(content={"status":"success"})
    # DIRECT use of your cookie pattern + add secure flags
    response.set_cookie(key="session", value=f"{sessionid}_{signature}", max_age=86400,
                        httponly=True, secure=True, samesite="lax", path="/")
    # also set CSRF cookie for state-changing calls (double-submit)
    handler_set_csrf_cookie(response)
    return response

@app.get("/someresource/{resid}")
def get_someresource(resid : str, session : Annotated[str, Cookie(alias=COOKIE_NAME)] = None):
    if not session:
        raise HTTPException(401, detail="Unauthorized")
    sessionid, signature = session.split("_")
    # Checking whether the given signature is the same as what
    # we'd produce if we signed the sessionid ensures that the
    # session was indeed created by us (with an overwhelmingly
    # high probability).
    if signature != sign(sessionid):
        # This is an invalid session since we know we didn't
        # generate it. Note that to reject invalid sessions,
        # we didn't actually need to touch the database.
        raise HTTPException(401, detail="Unauthorized")

    # Authenticated. Now we have to make sure that the
    # user has permission to access this resource.
    # This is often done using a faster and temporary
    # "session store" using an in-memory DB like Redis.
    # That way, the main database is not held up for
    # small tasks like this, besides Redis being much faster
    # than regular DBs for such use cases.
    userid = handler_db_get_session_user(sessionid)

    handler_check_authorization(userid, f"/someresource/{resid}")
    # We expect check_authorization to raise a 401/403 HTTPException
    # in case that failed.

    # All is well. Respond to the request.
    return {"resource": resid, "owner": userid, "ok": True}
# >>> end of your blocks <<<


@app.post("/logout")
def do_logout(session: Annotated[Optional[str], Cookie(alias=COOKIE_NAME)] = None):
    if session:
        handler_logout(session)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp

# Example of a state-changing endpoint protected by CSRF + cookie session
@app.post("/note", dependencies=[Depends(handler_csrf_protect)])
def create_note(payload: dict,
                session: Annotated[Optional[str], Cookie(alias=COOKIE_NAME)] = None):
    if not session:
        raise HTTPException(401, detail="Unauthorized")
    sessionid, signature = session.split("_")
    if signature != sign(sessionid):
        raise HTTPException(401, detail="Unauthorized")
    user_id = handler_db_get_session_user(sessionid)

    now = datetime.utcnow().isoformat()
    con.execute("""
      INSERT INTO Particles(date_created, date_updated, title, body, tags, particle_references)
      VALUES (?, ?, ?, ?, ?, ?)
    """, (now, now, payload.get("title",""), payload.get("body",""),
          json.dumps(payload.get("tags", [])), json.dumps(payload.get("refs", []))))
    con.commit()
    return {"ok": True, "user_id": user_id}

con = sqlite3.connect("pim.db", check_same_thread=False)
con.execute("PRAGMA foreign_keys = ON")
cur = con.cursor()

# Particle Module
@app.put("/")
def handler_convert_to_csstring(lst: Iterable[str] | None):
    return pim.convert_to_csstring(lst)

@app.put("/")
def handler_cstring_to_list(cstring: str | None):
    return pim.cstring_to_list(cstring)

@app.post("/")
def handler_exec(sql: str, params: Tuple | dict = ()):
    return pim._exec(sql, params)

@app.get("/")
def handler_row_to_particle(row):
    return pim._row_to_particle(row)  

@app.get("/")
def handler_init_particles_fts():
    return pim._init_particles_fts()

# _init_particles_fts()

@app.get("/")
def handler_countParticles(query: str = ""):
    return pim.countParticles(query)

@app.put("/")
def handler_update_particle(
    particle_id: int,
    *,
    title: Optional[str] = None,
    body: Optional[str] = None,
    tags: Optional[List[str]] = None,
    particle_references: Optional[List[str]] = None
):
    return pim.update_particle(particle_id, title, body, tags, particle_references
) #removed asterisk
    
#@app.put("/")
#async def handler_edit_particle(particle: Particle, new_content: Iterable[str] | str, *,
#                  save_to_disk: bool = True,
#                  filepath: Optional[str] = None):
#    return pim.edit_particle(particle, new_content, save_to_disk,filepath)

@app.put("/")
def delete_particle(particle_id: int):
    return pim.delete_particle(particle_id)

@app.post("/")
def handler_create_Particle(title: str, body: str):
    return pim.create_Particle(title, body)

@app.get("/")
def handler_listParticles(query: str = "", page: int = 1, pageSize: int = 10):
    return pim.listParticles(query, page, pageSize)

@app.get("/")
def handler_getParticle(id: int):
    return pim.getParticle(id)

@app.get("/")
def handler_view_particles(query: str = "", page: int = 1, pageSize: int = 10):
    return pim.view_particles(query, page, pageSize) 

@app.get("/")
def handler_extract_tags_and_particle_refs(particle: Particle):
    return pim.extract_tags_and_particle_refs(particle)

# Storage Module
@app.post("/")
def handler_store_user(user: User):
    return pim.store_user(user)

@app.post("/")
def handler_store_particle(particle: Particle):
    return pim.store_particle(particle)

