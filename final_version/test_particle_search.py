# tests/test_particle_search.py
"""
End-to-end tests for particle_module search (fast + fuzzy), ranking helpers,
CRUD basics, tags/refs, pagination, and edge cases.

Self-contained: adds sys.path and defines its own fixtures/helpers.
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(_file_)))

import json
import sqlite3
import uuid
import datetime as dt
import pytest

import particle_module as pm


# ------------------------------- Fixtures & helpers -------------------------------

@pytest.fixture
def db_path(tmp_path):
    db = tmp_path / "pim.db"
    pm.init_particles_db(str(db))
    return str(db)


def now(offset_sec: int = 0) -> dt.datetime:
    base = dt.datetime(2025, 1, 1, 12, 0, 0)
    return base + dt.timedelta(seconds=offset_sec)


def make_particle(user_id: str, title: str, body: str, when: dt.datetime) -> pm.Particle:
    tags, refs = pm.extract_tags_and_references(body)
    return pm.Particle(
        id=str(uuid.uuid4()),    # UUID so reverse-ref extractor can see it
        user_id=str(user_id),
        date_created=when,
        date_updated=when,
        title=title,
        body=body,
        tags=tags,
        particle_references=refs,
    )


def seed(db_path: str, particles: list[pm.Particle]) -> None:
    with sqlite3.connect(db_path) as conn:
        for p in particles:
            conn.execute(
                """INSERT INTO particles
                   (id,user_id,date_created,date_updated,title,body,tags,particle_references)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    p.id,
                    p.user_id,
                    p.date_created.isoformat(),
                    p.date_updated.isoformat(),
                    p.title,
                    p.body,
                    json.dumps(p.tags),
                    json.dumps(p.particle_references),
                ),
            )
        conn.commit()


def get_ids(result: dict) -> list[str]:
    return [r["id"] for r in result["particles"]]


# -------------------------------- Sanity / helpers --------------------------------

def test_probe_collects():
    assert True


def test_tokenize_and_levenshtein_basics():
    assert pm.tokenize("My First NOTE!") == ["my", "first", "note"]
    assert pm.levenshtein("abc", "def") == 3
    assert pm.levenshtein("", "abc") == 3
    assert pm.norm_distance("notes", "notees") < 0.25
    assert 0.7 < pm.norm_sim("notes", "notees") <= 1.0


def test_best_token_sim_bigrams():
    s = pm.best_token_sim("computer class", "my note for computer class today")
    assert s > 0.6


# --------------------------------- CRUD flow ---------------------------------

def test_create_get_update_delete_cycle(db_path):
    p = pm.create_particle("u1", "Title A", "Body A #tag1", db_path=db_path)
    got = pm.get_particle(p.id, "u1", db_path=db_path)
    assert got and got.title == "Title A"
    upd = pm.update_particle(p.id, "u1", title="New Title", body="Body B #t2", db_path=db_path)
    assert upd and upd.title == "New Title" and "t2" in upd.tags
    assert pm.delete_particle(p.id, "u1", db_path=db_path)
    assert pm.get_particle(p.id, "u1", db_path=db_path) is None


# ----------------------------- Listing / pagination -----------------------------

def test_list_pagination_and_sorting(db_path):
    items = [make_particle("u1", f"T{i:02d}", f"Body {i}", now(i)) for i in range(25)]
    seed(db_path, items)
    res = pm.list_particles("u1", page=2, page_size=10, sort_by="date_updated", db_path=db_path)
    assert res["page"] == 2
    assert len(res["particles"]) == 10
    dts = [r["date_updated"] for r in res["particles"]]
    assert dts == sorted(dts, reverse=True)


def test_pagination_bounds_are_safe(db_path):
    items = [make_particle("u1", f"T{i}", "body", now(i)) for i in range(5)]
    seed(db_path, items)
    r = pm.search_particles("u1", query="", page=99, page_size=10, db_path=db_path)
    assert r["page"] == r["total_pages"]


# --------------------------- Fast search (FTS/LIKE) ---------------------------

def test_search_empty_query_lists_all(db_path):
    items = [make_particle("u1", "A", "x", now(1)), make_particle("u1", "B", "y", now(2))]
    seed(db_path, items)
    r = pm.search_particles("u1", query="", db_path=db_path)
    assert r["total"] == 2
    assert len(r["particles"]) == 2


def test_search_title_phrase_beats_body_match(db_path):
    p_title = make_particle("u1", "My First Note", "random", now(10))
    p_body  = make_particle("u1", "Notes", "…my first note appears in content…", now(20))
    seed(db_path, [p_title, p_body])

    r = pm.search_particles("u1", query="my first note", db_path=db_path)
    ids = get_ids(r)
    assert ids.index(p_title.id) < ids.index(p_body.id)


def test_search_token_boost_over_body_when_close(db_path):
    p_typo = make_particle("u1", "NOTEES", "short body", now(10))
    p_long = make_particle("u1", "My note for computer class", "lorem ipsum", now(5))
    seed(db_path, [p_typo, p_long])

    # typo title won't match FTS; use fuzzy path to ensure it is considered
    r = pm.fuzzy_search_particles("u1", query="my notes", db_path=db_path)
    ids = get_ids(r)
    assert ids.index(p_typo.id) < ids.index(p_long.id)


def test_like_search_forced_when_no_fts(db_path, monkeypatch):
    monkeypatch.setattr(pm, "check_fts_available", lambda *a, **k: False)
    p1 = make_particle("u1", "Alpha Project", "body", now(1))
    p2 = make_particle("u1", "Beta", "Alpha mentioned in body", now(2))
    seed(db_path, [p1, p2])

    r = pm.search_particles("u1", query="Alpha", db_path=db_path)
    assert len(r["particles"]) == 2
    assert r["particles"][0]["title"] == "Alpha Project"


def test_user_isolation(db_path):
    items = [
        make_particle("u1", "Shared", "alpha", now(10)),
        make_particle("u2", "Shared", "beta", now(20)),
    ]
    seed(db_path, items)
    r1 = pm.search_particles("u1", query="Shared", db_path=db_path)
    r2 = pm.search_particles("u2", query="Shared", db_path=db_path)
    assert len(r1["particles"]) == 1 and len(r2["particles"]) == 1
    assert r1["particles"][0]["body"] == "alpha"
    assert r2["particles"][0]["body"] == "beta"


def test_tie_breaker_recent_first_when_scores_equal(db_path):
    p_old = make_particle("u1", "Project Alpha", "x", now(1))
    p_new = make_particle("u1", "Project Alpha", "x", now(999))
    seed(db_path, [p_old, p_new])
    r = pm.search_particles("u1", query="Project Alpha", db_path=db_path)
    ids = get_ids(r)
    assert ids.index(p_new.id) < ids.index(p_old.id)


# ------------------------------ Fuzzy search path ------------------------------

def test_fuzzy_typo_and_title_priority(db_path):
    p1 = make_particle("u1", "NOTEES", "short", now(3))
    p2 = make_particle("u1", "My note for computer class", "longer body", now(2))
    p3 = make_particle("u1", "Random", "my notes appear here", now(1))
    seed(db_path, [p1, p2, p3])

    r = pm.fuzzy_search_particles("u1", query="my notes", db_path=db_path)
    ids = get_ids(r)
    assert ids.index(p1.id) < ids.index(p3.id)


def test_fuzzy_empty_query_falls_back_to_list(db_path):
    p1 = make_particle("u1", "A", "x", now(1))
    p2 = make_particle("u1", "B", "y", now(2))
    seed(db_path, [p1, p2])

    r = pm.fuzzy_search_particles("u1", query="", db_path=db_path)
    assert r["total"] == 2
    assert len(r["particles"]) == 2


def test_fuzzy_candidate_limit(db_path):
    ps = [make_particle("u1", f"T{i}", "body", now(i)) for i in range(150)]
    seed(db_path, ps)
    r = pm.fuzzy_search_particles("u1", query="T", db_path=db_path, candidate_limit=50)
    assert r["total"] <= 50


# --------------------------- Tags / refs / counting ---------------------------

def test_extract_tags_and_references():
    body = (
        "This is a #ProjectX note referencing 123 and "
        "UUID 123e4567-e89b-12d3-a456-426614174000 and #2025_plan"
    )
    tags, refs = pm.extract_tags_and_references(body)
    # Module intentionally ignores digit-leading tags like #2025_plan
    assert tags == ["ProjectX"]
    assert ("123" in refs) or any(r.startswith("123e4567") for r in refs)


def test_get_particles_by_tag(db_path):
    p1 = make_particle("u1", "A", "Body #projectX", now(1))
    p2 = make_particle("u1", "B", "Body #projectY", now(2))
    p3 = make_particle("u1", "C", "Body #projectX more", now(3))
    seed(db_path, [p1, p2, p3])

    r = pm.get_particles_by_tag("u1", "projectX", db_path=db_path)
    titles = [x["title"] for x in r["particles"]]
    assert set(titles) == {"A", "C"}


def test_get_all_tags(db_path):
    p1 = make_particle("u1", "A", "Body #t1 #t2", now(1))
    p2 = make_particle("u1", "B", "Body #t2 #t3", now(2))
    seed(db_path, [p1, p2])
    tags = pm.get_all_tags("u1", db_path=db_path)
    assert tags == ["t1", "t2", "t3"]


def test_get_particle_references(db_path):
    p1 = make_particle("u1", "A", "Body", now(1))
    p2 = make_particle("u1", "B", f"Refers {p1.id}", now(2))
    p2.tags, p2.particle_references = pm.extract_tags_and_references(p2.body)
    seed(db_path, [p1, p2])
    refs = pm.get_particle_references(p1.id, "u1", db_path=db_path)
    assert any(r.id == p2.id for r in refs)


def test_count_particles_with_and_without_query(db_path):
    p1 = make_particle("u1", "Alpha", "body", now(1))
    p2 = make_particle("u1", "Beta", "Alpha here", now(2))
    p3 = make_particle("u1", "Gamma", "body", now(3))
    seed(db_path, [p1, p2, p3])

    total = pm.count_particles("u1", "", db_path=db_path)
    assert total == 3

    total_alpha = pm.count_particles("u1", "Alpha", db_path=db_path)
    assert total_alpha in (1, 2)


# ---------------------------------- Edge cases ----------------------------------

def test_numbers_and_hashtags(db_path):
    p = make_particle("u1", "FY2025 Plan", "Body #OKR #Q1 target 50%", now(1))
    seed(db_path, [p])
    r = pm.search_particles("u1", query="FY2025", db_path=db_path)
    assert r["total"] == 1
    r2 = pm.get_particles_by_tag("u1", "OKR", db_path=db_path)
    assert r2["total"] == 1


def test_very_short_queries(db_path):
    p1 = make_particle("u1", "A", "short", now(1))
    p2 = make_particle("u1", "B", "short", now(2))
    seed(db_path, [p1, p2])
    r = pm.search_particles("u1", query="A", db_path=db_path)
    assert r["total"] >= 1


def test_whitespace_and_zero_width_spaces(db_path):
    p = make_particle("u1", "My Note", "body", now(1))
    seed(db_path, [p])
    q = "  my   note\u200b  "
    r = pm.search_particles("u1", query=q, db_path=db_path)
    assert r["total"] >= 1