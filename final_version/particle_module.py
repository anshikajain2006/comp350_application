from __future__ import annotations
import datetime
import json
import logging
import re
import sqlite3
import unicodedata
import uuid
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

# ------------------------------------------------------------------------------
# Logging & constants
# ------------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DB_FILE = "pim.db"
ALLOWED_SORT = {"date_updated", "date_created", "title"}


# ------------------------------------------------------------------------------
# Data model
# ------------------------------------------------------------------------------

@dataclass
class Particle:
    """Data structure representing a note-like item.

    :param id: UUID string identifier
    :param date_created: ISO timestamp of creation
    :param date_updated: ISO timestamp of last update
    :param title: Title text
    :param body: Body/content text
    :param tags: List of tags (strings without '#')
    :param particle_references: List of referenced IDs (UUID or numeric)
    :param user_id: Owner user id
    """
    id: str
    date_created: datetime.datetime
    date_updated: datetime.datetime
    title: str
    body: str
    tags: List[str]
    particle_references: List[str]
    user_id: str = ""

    def to_dict(self) -> Dict:
        """Return a JSON-serializable dict for this particle.

        :returns: Serializable mapping with ISO timestamps
        :rtype: dict
        """
        data = asdict(self)
        data["date_created"] = self.date_created.isoformat()
        data["date_updated"] = self.date_updated.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict) -> "Particle":
        """Construct a :class:Particle from a dict.

        :param data: Mapping with ISO timestamps for date fields
        :type data: dict
        :returns: Particle instance
        :rtype: Particle
        """
        data["date_created"] = datetime.datetime.fromisoformat(data["date_created"])
        data["date_updated"] = datetime.datetime.fromisoformat(data["date_updated"])
        return cls(**data)


# ------------------------------------------------------------------------------
# DB init
# ------------------------------------------------------------------------------

def init_particles_db(db_path: str = DB_FILE) -> None:
    """Initialize the SQLite schema (and FTS5 if available).

    Idempotent. Also drops legacy tables if their schema is incompatible.

    :param db_path: Path to SQLite database file
    :type db_path: str
    """
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")

        # Drop legacy tables with incompatible schemas if present
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('Particles', 'particles')"
        )
        existing = [r[0] for r in cursor.fetchall()]
        for tbl in existing:
            cols = [c[1] for c in conn.execute(f"PRAGMA table_info({tbl})").fetchall()]
            if ('user_id' not in cols and tbl == 'Particles') or ('id' not in cols and tbl == 'particles'):
                conn.execute(f"DROP TABLE IF EXISTS {tbl}")
                conn.execute("DROP TABLE IF EXISTS particles_fts")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS particles(
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                date_created TEXT NOT NULL,
                date_updated TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                tags TEXT DEFAULT '[]',
                particle_references TEXT DEFAULT '[]'
            )
            """
        )

        # FTS5 setup (best-effort): external-content index over particles
        fts_available = False
        try:
            conn.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS particles_fts USING fts5(
                    id UNINDEXED,
                    title,
                    body,
                    tags,
                    content='particles',
                    content_rowid='rowid'
                )
                """
            )
            fts_available = True
        except sqlite3.OperationalError as e:
            logger.info(f"FTS5 not available: {e}")

        if fts_available:
            try:
                # Insert trigger
                conn.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS particles_fts_ai
                    AFTER INSERT ON particles BEGIN
                      INSERT INTO particles_fts(rowid,id,title,body,tags)
                      VALUES (new.rowid,new.id,new.title,new.body,new.tags);
                    END;
                    """
                )
                # Delete trigger (external-content delete syntax)
                conn.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS particles_fts_ad
                    AFTER DELETE ON particles BEGIN
                      INSERT INTO particles_fts(particles_fts,rowid)
                      VALUES ('delete',old.rowid);
                    END;
                    """
                )
                # Update trigger: delete old row, then insert new
                conn.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS particles_fts_au
                    AFTER UPDATE ON particles BEGIN
                      INSERT INTO particles_fts(particles_fts,rowid)
                      VALUES ('delete',old.rowid);
                      INSERT INTO particles_fts(rowid,id,title,body,tags)
                      VALUES (new.rowid,new.id,new.title,new.body,new.tags);
                    END;
                    """
                )
            except sqlite3.OperationalError as e:
                logger.warning(f"Could not create FTS triggers: {e}")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_particles_user_id ON particles(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_particles_date_updated ON particles(date_updated)")
        conn.commit()


# ------------------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------------------

def get_current_timestamp() -> datetime.datetime:
    """Return current timestamp.

    :returns: Current datetime
    :rtype: datetime.datetime
    """
    return datetime.datetime.now()


def safe_sort_column(sort_by: str) -> str:
    """Return a safe sort column name.

    :param sort_by: Column requested by the caller
    :type sort_by: str
    :returns: Validated column (defaults to `date_updated`)
    :rtype: str
    """
    return sort_by if sort_by in ALLOWED_SORT else "date_updated"


def normalize_query(q: str) -> str:
    """Normalize a user query (strip zero-width chars and collapse spaces).

    :param q: Raw query string
    :type q: str
    :returns: Normalized query
    :rtype: str
    """
    s = (q or "")
    # Remove format (Cf) chars (e.g., zero-width joiners)
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Cf")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def extract_tags_and_references(body: str) -> Tuple[List[str], List[str]]:
    """Extract tags and references from text.

    Tag rule: *must start with a letter* (A–Z), then letters/digits/`_/-`.

    :param body: Source text
    :type body: str
    :returns: `(tags, references)` where references are UUIDs or numeric `#123` refs
    :rtype: Tuple[List[str], List[str]]
    """
    tag_pattern = r"#([A-Za-z][A-Za-z0-9_-]*)"
    uuid_pattern = r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    numref_pattern = r"#(\d+)"

    tags = sorted(set(re.findall(tag_pattern, body or "")))
    uuids = re.findall(uuid_pattern, body or "")
    numrefs = re.findall(numref_pattern, body or "")
    refs = sorted(set(uuids or numrefs))
    return tags, refs


def format_particle_row(row: sqlite3.Row) -> Dict:
    """Convert a DB row into a UI-friendly dict.

    :param row: Row with columns from `particles` table
    :type row: sqlite3.Row
    :returns: Rendered particle summary
    :rtype: dict
    """
    body = row["body"]
    return {
        "id": row["id"],
        "title": row["title"],
        "body": body,
        "excerpt": (body[:200] + "...") if len(body) > 200 else body,
        "tags": json.loads(row["tags"]),
        "particle_references": json.loads(row["particle_references"]),
        "date_created": row["date_created"],
        "date_updated": row["date_updated"],
    }


def tokenize(text: str) -> List[str]:
    """Tokenize text into lowercase alphanum/underscore chunks.

    :param text: Input text
    :type text: str
    :returns: List of tokens
    :rtype: List[str]
    """
    t = (text or "").lower()
    return [tok for tok in re.split(r"[^a-z0-9_]+", t) if tok]


# ------------------------------------------------------------------------------
# Fuzzy helpers
# ------------------------------------------------------------------------------

def levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance.

    :param a: First string
    :type a: str
    :param b: Second string
    :type b: str
    :returns: Number of single-character edits (insert/delete/substitute)
    :rtype: int
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if len(a) > len(b):
        a, b = b, a
    prev = list(range(len(a) + 1))
    for j, bj in enumerate(b, 1):
        curr = [j]
        for i, ai in enumerate(a, 1):
            ins = curr[i - 1] + 1
            delete = prev[i] + 1
            sub = prev[i - 1] + (ai != bj)
            curr.append(min(ins, delete, sub))
        prev = curr
    return prev[-1]


def norm_distance(a: str, b: str) -> float:
    """Normalized distance in `[0,1]` (0 identical, 1 totally different).

    :param a: First string
    :type a: str
    :param b: Second string
    :type b: str
    :returns: Normalized distance
    :rtype: float
    """
    a = (a or "").strip().lower()
    b = (b or "").strip().lower()
    if not a and not b:
        return 0.0
    if not a or not b:
        return 1.0
    d = levenshtein(a, b)
    return d / max(len(a), len(b))


def norm_sim(a: str, b: str) -> float:
    """Normalized similarity in `[0,1]` (1 identical).

    :param a: First string
    :type a: str
    :param b: Second string
    :type b: str
    :returns: Similarity score
    :rtype: float
    """
    return 1.0 - norm_distance(a, b)


def min_token_distance(query_tokens: List[str], text_tokens: List[str]) -> float:
    """Minimum normalized distance from any text token to any query token.

    :param query_tokens: Tokens from the query
    :type query_tokens: List[str]
    :param text_tokens: Tokens from the candidate text
    :type text_tokens: List[str]
    :returns: Smallest normalized distance
    :rtype: float
    """
    if not query_tokens or not text_tokens:
        return 1.0
    best = 1.0
    for q in query_tokens:
        for t in text_tokens:
            best = min(best, norm_distance(q, t))
    return best


def best_token_sim(query: str, text: str) -> float:
    """Compare a phrase to tokens and token bigrams; return best similarity.

    :param query: Search phrase
    :type query: str
    :param text: Candidate text
    :type text: str
    :returns: Best similarity in `[0,1]`
    :rtype: float
    """
    q = (query or "").strip().lower()
    t = (text or "").strip().lower()
    if not q or not t:
        return 0.0
    toks = tokenize(t)
    if not toks:
        return 0.0
    best = 0.0
    for tok in toks:
        best = max(best, norm_sim(q, tok))
    for i in range(len(toks) - 1):
        bigram = toks[i] + " " + toks[i + 1]
        best = max(best, norm_sim(q, bigram))
    return best


def check_fts_available(db_path: str = DB_FILE) -> bool:
    """Return True if FTS5 table exists and is readable.

    :param db_path: Path to database
    :type db_path: str
    :returns: Whether FTS5 is available
    :rtype: bool
    """
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("SELECT 1 FROM particles_fts LIMIT 1")
        return True
    except sqlite3.OperationalError:
        return False


# ------------------------------------------------------------------------------
# CRUD
# ------------------------------------------------------------------------------

def create_particle(user_id: str, title: str, body: str, db_path: str = DB_FILE) -> Particle:
    """Create and persist a particle.

    :param user_id: Owner id
    :type user_id: str
    :param title: Title
    :type title: str
    :param body: Body/content
    :type body: str
    :param db_path: Database path
    :type db_path: str
    :returns: Created particle
    :rtype: Particle
    """
    particle_id = str(uuid.uuid4())
    now = get_current_timestamp()
    tags, refs = extract_tags_and_references(body)

    particle = Particle(
        id=particle_id,
        date_created=now,
        date_updated=now,
        title=title,
        body=body,
        tags=tags,
        particle_references=refs,
        user_id=user_id,
    )

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO particles (id,user_id,date_created,date_updated,title,body,tags,particle_references)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                particle.id,
                particle.user_id,
                particle.date_created.isoformat(),
                particle.date_updated.isoformat(),
                particle.title,
                particle.body,
                json.dumps(particle.tags),
                json.dumps(particle.particle_references),
            ),
        )
        conn.commit()

    logger.info(f"Created particle: {particle.id}")
    return particle


def get_particle(particle_id: str, user_id: str, db_path: str = DB_FILE) -> Optional[Particle]:
    """Fetch a particle by id for a user.

    :param particle_id: UUID string
    :type particle_id: str
    :param user_id: Owner id
    :type user_id: str
    :param db_path: Database path
    :type db_path: str
    :returns: Particle or None
    :rtype: Optional[Particle]
    """
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM particles WHERE id=? AND user_id=?",
            (particle_id, user_id),
        ).fetchone()
        if not row:
            return None
        return Particle(
            id=row["id"],
            user_id=row["user_id"],
            date_created=datetime.datetime.fromisoformat(row["date_created"]),
            date_updated=datetime.datetime.fromisoformat(row["date_updated"]),
            title=row["title"],
            body=row["body"],
            tags=json.loads(row["tags"]),
            particle_references=json.loads(row["particle_references"]),
        )


def update_particle(
    particle_id: str,
    user_id: str,
    title: Optional[str] = None,
    body: Optional[str] = None,
    db_path: str = DB_FILE,
) -> Optional[Particle]:
    """Update title/body for an existing particle.

    :param particle_id: UUID string
    :type particle_id: str
    :param user_id: Owner id
    :type user_id: str
    :param title: New title (optional)
    :type title: Optional[str]
    :param body: New body (optional)
    :type body: Optional[str]
    :param db_path: Database path
    :type db_path: str
    :returns: Updated particle or None
    :rtype: Optional[Particle]
    """
    particle = get_particle(particle_id, user_id, db_path)
    if not particle:
        return None

    if title is not None:
        particle.title = title
    if body is not None:
        particle.body = body
        particle.tags, particle.particle_references = extract_tags_and_references(body)
    particle.date_updated = get_current_timestamp()

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE particles
            SET title=?, body=?, tags=?, particle_references=?, date_updated=?
            WHERE id=? AND user_id=?
            """,
            (
                particle.title,
                particle.body,
                json.dumps(particle.tags),
                json.dumps(particle.particle_references),
                particle.date_updated.isoformat(),
                particle_id,
                user_id,
            ),
        )
        conn.commit()

    logger.info(f"Updated particle: {particle_id}")
    return particle


def delete_particle(particle_id: str, user_id: str, db_path: str = DB_FILE) -> bool:
    """Delete a particle.

    :param particle_id: UUID string
    :type particle_id: str
    :param user_id: Owner id
    :type user_id: str
    :param db_path: Database path
    :type db_path: str
    :returns: True if deleted, else False
    :rtype: bool
    """
    with sqlite3.connect(db_path) as conn:
        cur = conn.execute("DELETE FROM particles WHERE id=? AND user_id=?", (particle_id, user_id))
        conn.commit()
        return cur.rowcount > 0


# ------------------------------------------------------------------------------
# Listing & search
# ------------------------------------------------------------------------------

def list_particles(
    user_id: str,
    page: int = 1,
    page_size: int = 10,
    sort_by: str = "date_updated",
    db_path: str = DB_FILE,
) -> Dict:
    """List particles for a user (page number clamped to valid range).

    :param user_id: Owner id
    :type user_id: str
    :param page: 1-based page index
    :type page: int
    :param page_size: Items per page
    :type page_size: int
    :param sort_by: Sort column (`date_updated` | `date_created` | `title`)
    :type sort_by: str
    :param db_path: Database path
    :type db_path: str
    :returns: Paginated results mapping
    :rtype: dict
    """
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        safe_sort = safe_sort_column(sort_by)

        total = conn.execute(
            "SELECT COUNT(*) AS total FROM particles WHERE user_id=?",
            (user_id,),
        ).fetchone()["total"]

        total_pages = max(1, (total + page_size - 1) // page_size)
        page = max(1, min(page, total_pages))  # clamp
        offset = (page - 1) * page_size

        cur = conn.execute(
            f"""
            SELECT * FROM particles
            WHERE user_id = ?
            ORDER BY {safe_sort} DESC
            LIMIT ? OFFSET ?
            """,
            (user_id, page_size, offset),
        )
        particles = [format_particle_row(r) for r in cur]

    return {
        "particles": particles,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


def _like_rank_order_clause(safe_sort: str) -> str:
    """Build ORDER BY clause that prefers title/tag hits over body for LIKE fallback.

    :param safe_sort: Validated sort column
    :type safe_sort: str
    :returns: SQL ORDER BY string
    :rtype: str
    """
    # Weighted: title=2, tags=1, body=0.5
    return f"ORDER BY like_rank DESC, {safe_sort} DESC"


def search_particles(
    user_id: str,
    query: str = "",
    page: int = 1,
    page_size: int = 10,
    sort_by: str = "date_updated",
    db_path: str = DB_FILE,
) -> Dict:
    """Full-text search across title/body/tags (FTS5 if available; LIKE fallback).

    :param user_id: Owner id
    :type user_id: str
    :param query: Search phrase (normalized internally)
    :type query: str
    :param page: 1-based page index
    :type page: int
    :param page_size: Items per page
    :type page_size: int
    :param sort_by: Sort column
    :type sort_by: str
    :param db_path: Database path
    :type db_path: str
    :returns: Paginated results with `query` echo
    :rtype: dict
    """
    q = normalize_query(query)
    if not q:
        result = list_particles(user_id, page=page, page_size=page_size, sort_by=sort_by, db_path=db_path)
        result["query"] = q
        return result

    safe_sort = safe_sort_column(sort_by)
    offset = (page - 1) * page_size

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row

        if check_fts_available(db_path):
            try:
                phrase = f'"{q}"'
                total = conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM particles_fts
                    JOIN particles p ON particles_fts.id = p.id
                    WHERE particles_fts MATCH ? AND p.user_id=?
                    """,
                    (phrase, user_id),
                ).fetchone()[0]

                cur = conn.execute(
                    f"""
                    SELECT p.*, bm25(particles_fts) AS rank
                    FROM particles_fts
                    JOIN particles p ON particles_fts.id = p.id
                    WHERE particles_fts MATCH ? AND p.user_id=?
                    ORDER BY rank ASC, p.{safe_sort} DESC
                    LIMIT ? OFFSET ?
                    """,
                    (phrase, user_id, page_size, offset),
                )
                particles = [format_particle_row(r) for r in cur]
            except sqlite3.OperationalError:
                # fall through to LIKE ranking
                total, particles = _like_search(conn, user_id, q, page_size, offset, safe_sort)
        else:
            total, particles = _like_search(conn, user_id, q, page_size, offset, safe_sort)

    return {
        "particles": particles,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
        "query": q,
    }


def _like_search(conn: sqlite3.Connection, user_id: str, q: str, page_size: int, offset: int, safe_sort: str):
    """LIKE fallback with simple ranking that prefers title and tags over body."""
    like = f"%{q}%"
    total = conn.execute(
        """
        SELECT COUNT(*)
        FROM particles
        WHERE user_id=? AND (title LIKE ? OR body LIKE ? OR tags LIKE ?)
        """,
        (user_id, like, like, like),
    ).fetchone()[0]

    cur = conn.execute(
        f"""
        SELECT *,
               (CASE WHEN title LIKE ? THEN 2.0 ELSE 0 END) +
               (CASE WHEN tags  LIKE ? THEN 1.0 ELSE 0 END) +
               (CASE WHEN body  LIKE ? THEN 0.5 ELSE 0 END) AS like_rank
        FROM particles
        WHERE user_id=? AND (title LIKE ? OR body LIKE ? OR tags LIKE ?)
        {_like_rank_order_clause(safe_sort)}
        LIMIT ? OFFSET ?
        """,
        (like, like, like, user_id, like, like, like, page_size, offset),
    )
    particles = [format_particle_row(r) for r in cur]
    return total, particles


def fuzzy_search_particles(
    user_id: str,
    query: str,
    page: int = 1,
    page_size: int = 10,
    db_path: str = DB_FILE,
    candidate_limit: int = 1000,
) -> Dict:
    """Fuzzy search using edit distance against title/tags/body prefix.

    A small *title bonus* is applied when any title token is within a small
    normalized edit distance of any query token (to favor near-typos).

    :param user_id: Owner id
    :type user_id: str
    :param query: Search phrase (normalized internally)
    :type query: str
    :param page: 1-based page index
    :type page: int
    :param page_size: Items per page
    :type page_size: int
    :param db_path: Database path
    :type db_path: str
    :param candidate_limit: Number of DB rows to score in memory
    :type candidate_limit: int
    :returns: Paginated fuzzy results
    :rtype: dict
    """
    q = normalize_query(query)
    if not q:
        return list_particles(user_id, page=page, page_size=page_size, db_path=db_path)

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, title, body, tags, particle_references, date_created, date_updated
            FROM particles
            WHERE user_id=?
            ORDER BY date_updated DESC
            LIMIT ?
            """,
            (user_id, candidate_limit),
        ).fetchall()

    q_tokens = tokenize(q)
    scored = []
    for r in rows:
        title = r["title"] or ""
        body = r["body"] or ""
        try:
            tags = json.loads(r["tags"]) or []
        except Exception:
            tags = []

        s_title_exact = norm_sim(q, title)
        s_title_tokens = best_token_sim(q, title)
        s_tags = max((norm_sim(q, t) for t in tags), default=0.0)
        s_body = best_token_sim(q, body[:1000])  # cap for speed

        # Title near-typo bonus (favor NOTEES ~ NOTES over body matches)
        title_tokens = tokenize(title)
        dmin = min_token_distance(q_tokens, title_tokens)
        title_bonus = 0.15 if dmin <= 0.25 else 0.0  # one small edit away

        score = 0.60 * max(s_title_exact, s_title_tokens) + title_bonus + 0.25 * s_tags + 0.15 * s_body
        if score > 0.20:
            scored.append((score, r))

    scored.sort(key=lambda x: (x[0], x[1]["date_updated"]), reverse=True)

    total = len(scored)
    start = max(0, (page - 1) * page_size)
    end = start + page_size
    page_rows = [format_particle_row(row) for _, row in scored[start:end]]

    return {
        "particles": page_rows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
        "query": q,
        "fuzzy": True,
    }


# ------------------------------------------------------------------------------
# Tags / references / counts
# ------------------------------------------------------------------------------

def get_particles_by_tag(user_id: str, tag: str, page: int = 1, page_size: int = 10, db_path: str = DB_FILE) -> Dict:
    """Return particles containing a given tag.

    :param user_id: Owner id
    :type user_id: str
    :param tag: Tag without '#'
    :type tag: str
    :param page: 1-based page index
    :type page: int
    :param page_size: Items per page
    :type page_size: int
    :param db_path: Database path
    :type db_path: str
    :returns: Paginated results for the tag
    :rtype: dict
    """
    like = f'%"{tag}"%'
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute(
            "SELECT COUNT(*) AS total FROM particles WHERE user_id=? AND tags LIKE ?",
            (user_id, like),
        ).fetchone()["total"]

        total_pages = max(1, (total + page_size - 1) // page_size)
        page = max(1, min(page, total_pages))
        offset = (page - 1) * page_size

        cur = conn.execute(
            """
            SELECT * FROM particles
            WHERE user_id=? AND tags LIKE ?
            ORDER BY date_updated DESC
            LIMIT ? OFFSET ?
            """,
            (user_id, like, page_size, offset),
        )
        particles = [format_particle_row(r) for r in cur]

    return {
        "particles": particles,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "tag": tag,
    }


def get_all_tags(user_id: str, db_path: str = DB_FILE) -> List[str]:
    """Return sorted distinct tags used by a user.

    :param user_id: Owner id
    :type user_id: str
    :param db_path: Database path
    :type db_path: str
    :returns: Sorted list of tags
    :rtype: List[str]
    """
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("SELECT tags FROM particles WHERE user_id=?", (user_id,)).fetchall()
    out: set[str] = set()
    for (tags_json,) in rows:
        try:
            out.update(json.loads(tags_json))
        except Exception:
            pass
    return sorted(out)


def get_particle_references(particle_id: str, user_id: str, db_path: str = DB_FILE) -> List[Particle]:
    """Return particles that reference `particle_id` in their `particle_references`.

    :param particle_id: Target particle ID (UUID string)
    :type particle_id: str
    :param user_id: Owner id
    :type user_id: str
    :param db_path: Database path
    :type db_path: str
    :returns: List of referencing Particle objects
    :rtype: List[Particle]
    """
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            """
            SELECT * FROM particles
            WHERE user_id=? AND particle_references LIKE ?
            """,
            (user_id, f'%"{particle_id}"%'),
        )
        out: List[Particle] = []
        for row in cur:
            out.append(
                Particle(
                    id=row["id"],
                    user_id=row["user_id"],
                    date_created=datetime.datetime.fromisoformat(row["date_created"]),
                    date_updated=datetime.datetime.fromisoformat(row["date_updated"]),
                    title=row["title"],
                    body=row["body"],
                    tags=json.loads(row["tags"]),
                    particle_references=json.loads(row["particle_references"]),
                )
            )
    return out


def count_particles(user_id: str, query: str = "", db_path: str = DB_FILE) -> int:
    """Count particles, optionally filtered by a search phrase.

    :param user_id: Owner id
    :type user_id: str
    :param query: Optional search phrase
    :type query: str
    :param db_path: Database path
    :type db_path: str
    :returns: Count
    :rtype: int
    """
    q = normalize_query(query)
    with sqlite3.connect(db_path) as conn:
        if q:
            if check_fts_available(db_path):
                try:
                    phrase = f'"{q}"'
                    return (
                        conn.execute(
                            """
                            SELECT COUNT(*)
                            FROM particles_fts
                            JOIN particles p ON particles_fts.id = p.id
                            WHERE particles_fts MATCH ? AND p.user_id=?
                            """,
                            (phrase, user_id),
                        ).fetchone()[0]
                    )
                except sqlite3.OperationalError:
                    like = f"%{q}%"
                    return (
                        conn.execute(
                            """
                            SELECT COUNT(*)
                            FROM particles
                            WHERE user_id=? AND (title LIKE ? OR body LIKE ? OR tags LIKE ?)
                            """,
                            (user_id, like, like, like),
                        ).fetchone()[0]
                    )
            else:
                like = f"%{q}%"
                return (
                    conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM particles
                        WHERE user_id=? AND (title LIKE ? OR body LIKE ? OR tags LIKE ?)
                        """,
                        (user_id, like, like, like),
                    ).fetchone()[0]
                )
        else:
            return conn.execute("SELECT COUNT(*) FROM particles WHERE user_id=?", (user_id,)).fetchone()[0]


# Initialize on import
init_particles_db()