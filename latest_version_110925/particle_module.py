"""
Enhanced PIM Particle Module 

- FTS5 ranking via bm25()
- Real-time FTS sync using delete+insert triggers
- Safe ORDER BY whitelist
- UUID-aware reference extraction
- Centralized timestamp helper

This module provides a small “Particles” backend (notes with tags, refs)
stored in SQLite with Full-Text Search (FTS5).
"""

import sqlite3
import datetime
import uuid
import re
import json
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class Particle:
    """
    Immutable representation of a stored particle (note).

    :param id: Unique particle identifier (UUID string)
    :type id: str
    :param date_created: Creation timestamp (ISO-like in DB)
    :type date_created: datetime.datetime
    :param date_updated: Last modification timestamp
    :type date_updated: datetime.datetime
    :param title: Particle title
    :type title: str
    :param body: Particle body text
    :type body: str
    :param tags: List of extracted tag strings (e.g. ``["work","todo"]``)
    :type tags: List[str]
    :param particle_references: List of referenced particle ids (UUIDs or numeric short refs)
    :type particle_references: List[str]
    :param user_id: Owner user id
    :type user_id: str
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
        """
        Convert instance to JSON-serializable dict.

        :return: Dictionary with ISO formatted timestamps
        :rtype: dict
        """
        data = asdict(self)
        data['date_created'] = self.date_created.isoformat()
        data['date_updated'] = self.date_updated.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict) -> 'Particle':
        """
        Construct a :class:`Particle` from a dictionary.

        :param data: Mapping with ``date_created``/``date_updated`` as ISO strings
        :type data: dict
        :return: Particle instance
        :rtype: Particle
        """
        data['date_created'] = datetime.datetime.fromisoformat(data['date_created'])
        data['date_updated'] = datetime.datetime.fromisoformat(data['date_updated'])
        return cls(**data)


class ParticleManager:
    """
    Particle manager backed by SQLite with real-time FTS5 indexing.

    :param db_path: Path to SQLite database file, defaults to ``"pim.db"``
    :type db_path: str, optional
    """

    _ALLOWED_SORT = {"date_updated", "date_created", "title"}

    def __init__(self, db_path: str = "pim.db"):
        self.db_path = db_path
        self._init_database()

    # ---------- utilities ----------

    def _now(self) -> datetime.datetime:
        """
        Current timestamp factory.

        :return: Current local datetime
        :rtype: datetime.datetime
        """
        return datetime.datetime.now()

    def _safe_sort(self, sort_by: str) -> str:
        """
        Whitelist enforcement for ORDER BY.

        :param sort_by: Requested sort key
        :type sort_by: str
        :return: Safe SQL column name
        :rtype: str
        """
        return sort_by if sort_by in self._ALLOWED_SORT else "date_updated"

    # ---------- setup ----------

    def _init_database(self) -> None:
        """
        Initialize schema and FTS5 triggers if not present.

        Creates:
          - ``particles`` table
          - ``particles_fts`` virtual table (FTS5)
          - triggers to keep FTS in sync
          - helpful indexes

        :raises sqlite3.Error: If schema creation fails
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS particles (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    date_created TEXT NOT NULL,
                    date_updated TEXT NOT NULL,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    tags TEXT DEFAULT '[]',
                    particle_references TEXT DEFAULT '[]',
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """)

            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS particles_fts USING fts5(
                    id UNINDEXED,
                    title,
                    body,
                    tags,
                    content='particles',
                    content_rowid='rowid'
                )
            """)

            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS particles_fts_insert
                AFTER INSERT ON particles
                BEGIN
                  INSERT INTO particles_fts(rowid, id, title, body, tags)
                  VALUES (new.rowid, new.id, new.title, new.body, new.tags);
                END;
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS particles_fts_delete
                AFTER DELETE ON particles
                BEGIN
                  INSERT INTO particles_fts(particles_fts, rowid, id, title, body, tags)
                  VALUES ('delete', old.rowid, old.id, old.title, old.body, old.tags);
                END;
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS particles_fts_update
                AFTER UPDATE ON particles
                BEGIN
                  INSERT INTO particles_fts(particles_fts, rowid, id, title, body, tags)
                  VALUES ('delete', old.rowid, old.id, old.title, old.body, old.tags);
                  INSERT INTO particles_fts(rowid, id, title, body, tags)
                  VALUES (new.rowid, new.id, new.title, new.body, new.tags);
                END;
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_particles_user_id ON particles(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_particles_date_updated ON particles(date_updated)")
            conn.commit()

    # ---------- parsing helpers ----------

    def extract_tags_and_references(self, body: str) -> Tuple[List[str], List[str]]:
        """
        Extract tags (``#word``) and particle references from free text.

        - Tags match ``#([A-Za-z][A-Za-z0-9_-]*)``
        - References prefer UUIDs in the text; if none are found, numeric
          short refs like ``#123`` are captured.

        :param body: Source text to parse
        :type body: str
        :return: Tuple of (tags, references)
        :rtype: Tuple[List[str], List[str]]
        """
        tag_pattern = r'#([A-Za-z][A-Za-z0-9_-]*)'
        uuid_pattern = r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
        numref_pattern = r'#(\d+)'

        tags = sorted(set(re.findall(tag_pattern, body)))
        uuids = re.findall(uuid_pattern, body)
        numrefs = re.findall(numref_pattern, body)
        refs = sorted(set(uuids or numrefs))
        return tags, refs

    def _format_particle_row(self, row) -> Dict:
        """
        Convert a DB row into a UI/API-friendly dictionary.

        :param row: Row with columns from ``particles`` table
        :type row: sqlite3.Row
        :return: Rendered particle summary
        :rtype: dict
        """
        return {
            'id': row['id'],
            'title': row['title'],
            'body': row['body'],
            'excerpt': row['body'][:200] + '...' if len(row['body']) > 200 else row['body'],
            'tags': json.loads(row['tags']),
            'particle_references': json.loads(row['particle_references']),
            'date_created': row['date_created'],
            'date_updated': row['date_updated']
        }

    # ---------- CRUD ----------

    def create_particle(self, user_id: str, title: str, body: str) -> Particle:
        """
        Create and persist a new particle for a user.

        :param user_id: Owner user id
        :type user_id: str
        :param title: Particle title
        :type title: str
        :param body: Particle body (can include ``#tags`` and UUID references)
        :type body: str
        :raises sqlite3.Error: If the INSERT fails
        :return: Newly created particle
        :rtype: Particle
        """
        particle_id = str(uuid.uuid4())
        now = self._now()
        tags, refs = self.extract_tags_and_references(body)

        particle = Particle(
            id=particle_id,
            date_created=now,
            date_updated=now,
            title=title,
            body=body,
            tags=tags,
            particle_references=refs,
            user_id=user_id
        )

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO particles (id, user_id, date_created, date_updated, title, body, tags, particle_references)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                particle.id,
                particle.user_id,
                particle.date_created.isoformat(),
                particle.date_updated.isoformat(),
                particle.title,
                particle.body,
                json.dumps(particle.tags),
                json.dumps(particle.particle_references)
            ))
            conn.commit()

        logger.info(f"Created particle: {particle.id}")
        return particle

    def get_particle(self, particle_id: str, user_id: str) -> Optional[Particle]:
        def get_all_tags(self, user_id: str) -> List[str]:
            """
            Get all unique tags used by a user.
            :param user_id: The ID of the user whose tags are being retrieved
            :type user_id: str
            :raises sqlite3.Error: If the query fails
            :return: A sorted list of unique tags
            :rtype: List[str]
            """

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("""
                SELECT * FROM particles
                WHERE id = ? AND user_id = ?
            """, (particle_id, user_id)).fetchone()
            if not row:
                return None
            return Particle(
                id=row['id'],
                user_id=row['user_id'],
                date_created=datetime.datetime.fromisoformat(row['date_created']),
                date_updated=datetime.datetime.fromisoformat(row['date_updated']),
                title=row['title'],
                body=row['body'],
                tags=json.loads(row['tags']),
                particle_references=json.loads(row['particle_references'])
            )

    def update_particle(self, particle_id: str, user_id: str,
                        title: Optional[str] = None, body: Optional[str] = None) -> Optional[Particle]:
        """
        Update title/body (and derived tags/refs) for an existing particle.

        :param particle_id: Particle UUID
        :type particle_id: str
        :param user_id: Owner user id
        :type user_id: str
        :param title: New title, defaults to ``None`` (no change)
        :type title: str, optional
        :param body: New body, defaults to ``None`` (no change)
        :type body: str, optional
        :raises sqlite3.Error: If the UPDATE fails
        :return: Updated particle or ``None`` if not found
        :rtype: Optional[Particle]
        """
        particle = self.get_particle(particle_id, user_id)
        if not particle:
            return None

        if title is not None:
            particle.title = title
        if body is not None:
            particle.body = body
            particle.tags, particle.particle_references = self.extract_tags_and_references(body)

        particle.date_updated = self._now()

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE particles
                SET title = ?, body = ?, tags = ?, particle_references = ?, date_updated = ?
                WHERE id = ? AND user_id = ?
            """, (
                particle.title,
                particle.body,
                json.dumps(particle.tags),
                json.dumps(particle.particle_references),
                particle.date_updated.isoformat(),
                particle_id,
                user_id
            ))
            conn.commit()

        logger.info(f"Updated particle: {particle_id}")
        return particle

    def delete_particle(self, particle_id: str, user_id: str) -> bool:
        """
        Delete a particle owned by a user.

        :param particle_id: Particle UUID
        :type particle_id: str
        :param user_id: Owner user id
        :type user_id: str
        :raises sqlite3.Error: If the DELETE fails
        :return: ``True`` if a row was deleted, else ``False``
        :rtype: bool
        """
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("""
                DELETE FROM particles
                WHERE id = ? AND user_id = ?
            """, (particle_id, user_id))
            conn.commit()
            deleted = cur.rowcount > 0
        if deleted:
            logger.info(f"Deleted particle: {particle_id}")
        return deleted

    # ---------- listing & search ----------

    def list_particles(self, user_id: str, page: int = 1, page_size: int = 10,
                       sort_by: str = "date_updated") -> Dict:
        """
        List particles for a user with pagination.

        :param user_id: Owner user id
        :type user_id: str
        :param page: 1-based page index, defaults to ``1``
        :type page: int, optional
        :param page_size: Number of items per page, defaults to ``10``
        :type page_size: int, optional
        :param sort_by: Sort key (``"date_updated"``, ``"date_created"``, ``"title"``), defaults to ``"date_updated"``
        :type sort_by: str, optional
        :raises sqlite3.Error: If queries fail
        :return: Paginated payload (``particles``, ``total``, ``page``, ``page_size``, ``total_pages``)
        :rtype: dict
        """
        offset = (page - 1) * page_size
        safe_sort = self._safe_sort(sort_by)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            total = conn.execute(
                "SELECT COUNT(*) AS total FROM particles WHERE user_id = ?",
                (user_id,)
            ).fetchone()['total']

            cur = conn.execute(f"""
                SELECT * FROM particles
                WHERE user_id = ?
                ORDER BY {safe_sort} DESC
                LIMIT ? OFFSET ?
            """, (user_id, page_size, offset))

            particles = [self._format_particle_row(r) for r in cur]

        return {
            'particles': particles,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': (total + page_size - 1) // page_size
        }

    def search_particles(self, user_id: str, query: str = "", page: int = 1,
                         page_size: int = 10, sort_by: str = "date_updated") -> Dict:
        """
        Full-text search across title/body/tags using FTS5.

        Uses ``bm25()`` to rank results (lower is better), then
        secondary sort by the chosen column.

        :param user_id: Owner user id
        :type user_id: str
        :param query: Search query string, defaults to ``""`` (falls back to :meth:`list_particles`)
        :type query: str, optional
        :param page: 1-based page index, defaults to ``1``
        :type page: int, optional
        :param page_size: Number of items per page, defaults to ``10``
        :type page_size: int, optional
        :param sort_by: Sort key (``"date_updated"``, ``"date_created"``, ``"title"``), defaults to ``"date_updated"``
        :type sort_by: str, optional
        :raises sqlite3.Error: If queries fail
        :return: Paginated, ranked results with ``query`` echoed back
        :rtype: dict
        """
        if not query.strip():
            result = self.list_particles(user_id, page, page_size, sort_by)
            result['query'] = query
            return result

        offset = (page - 1) * page_size
        safe_sort = self._safe_sort(sort_by)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            search_query = f'"{query}"'  # phrase search

            total = conn.execute("""
                SELECT COUNT(*)
                FROM particles_fts
                JOIN particles p ON particles_fts.id = p.id
                WHERE particles_fts MATCH ? AND p.user_id = ?
            """, (search_query, user_id)).fetchone()[0]

            cur = conn.execute(f"""
                SELECT p.*, bm25(particles_fts) AS rank
                FROM particles_fts
                JOIN particles p ON particles_fts.id = p.id
                WHERE particles_fts MATCH ? AND p.user_id = ?
                ORDER BY rank ASC, p.{safe_sort} DESC
                LIMIT ? OFFSET ?
            """, (search_query, user_id, page_size, offset))

            particles = [self._format_particle_row(r) for r in cur]

        return {
            'particles': particles,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': (total + page_size - 1) // page_size,
            'query': query
        }

    # ---------- tags & references ----------

    def get_particles_by_tag(self, user_id: str, tag: str,
                             page: int = 1, page_size: int = 10) -> Dict:
        """
        Filter particles that contain a given tag (simple JSON LIKE).

        :param user_id: Owner user id
        :type user_id: str
        :param tag: Tag value (without ``#``)
        :type tag: str
        :param page: 1-based page index, defaults to ``1``
        :type page: int, optional
        :param page_size: Number of items per page, defaults to ``10``
        :type page_size: int, optional
        :raises sqlite3.Error: If queries fail
        :return: Paginated results for the tag
        :rtype: dict
        """
        offset = (page - 1) * page_size
        like = f'%"{tag}"%'

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            total = conn.execute("""
                SELECT COUNT(*) AS total
                FROM particles
                WHERE user_id = ? AND tags LIKE ?
            """, (user_id, like)).fetchone()['total']

            cur = conn.execute("""
                SELECT * FROM particles
                WHERE user_id = ? AND tags LIKE ?
                ORDER BY date_updated DESC
                LIMIT ? OFFSET ?
            """, (user_id, like, page_size, offset))

            particles = [self._format_particle_row(r) for r in cur]

        return {
            'particles': particles,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': (total + page_size - 1) // page_size,
            'tag': tag
        }

    def get_all_tags(self, user_id: str) -> List[str]:
        """
        Collect all unique tags used by a user.

        :param user_id: Owner user id
        :type user_id: str
        :raises sqlite3.Error: If the SELECT fails
        :return: Sorted list of distinct tag strings
        :rtype: List[str]
        """
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT tags FROM particles WHERE user_id = ?",
                (user_id,)
            ).fetchall()

        all_tags = set()
        for (tags_json,) in rows:
            try:
                all_tags.update(json.loads(tags_json))
            except Exception:
                pass

        return sorted(all_tags)

    def get_particle_references(self, particle_id: str, user_id: str) -> List[Particle]:
        """
        Find particles that reference the given ``particle_id`` (UUID) in their
        ``particle_references`` JSON array.

        :param particle_id: Target particle UUID
        :type particle_id: str
        :param user_id: Owner user id
        :type user_id: str
        :raises sqlite3.Error: If the SELECT fails
        :return: Referencing particles
        :rtype: List[Particle]
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute("""
                SELECT * FROM particles
                WHERE user_id = ? AND particle_references LIKE ?
            """, (user_id, f'%"{particle_id}"%'))

            out: List[Particle] = []
            for row in cur:
                out.append(Particle(
                    id=row['id'],
                    user_id=row['user_id'],
                    date_created=datetime.datetime.fromisoformat(row['date_created']),
                    date_updated=datetime.datetime.fromisoformat(row['date_updated']),
                    title=row['title'],
                    body=row['body'],
                    tags=json.loads(row['tags']),
                    particle_references=json.loads(row['particle_references'])
                ))
        return out


# ---------- Example quick test ----------
if __name__ == "__main__":
    pm = ParticleManager("test_pim.db")
    user = "user123"
    p1 = pm.create_particle(user, "My First Note", "This is a test note with #important and #work tags.")
    p2 = pm.create_particle(user, "Python Tutorial",
                            "Learning Python basics #programming #tutorial. Great for #beginners")
    p3 = pm.create_particle(user, "Meeting Notes",
                            "Project discussion about #api #development. Need to check with #team")

    print("All:", pm.list_particles(user))
    print("Search 'Python':", pm.search_particles(user, "Python"))
    print("By tag 'programming':", pm.get_particles_by_tag(user, "programming"))
    print("All tags:", pm.get_all_tags(user))
