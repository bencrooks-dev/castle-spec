"""Schema-Core conformance checks (OS-1 .. OS-7).

Each test maps to a numbered requirement in conformance/README.md and to the
Castle Obligation Schema (SPEC.md sections 2 through 5).
The checks are deliberately falsifiable from outside the implementation: the
fingerprint is recomputed with nothing but ``hashlib``, and tampering is done
with raw SQL so no ORM guard can mask a detection failure.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

import castle.obligation_graph as og
from castle.database import get_session, init_db
from castle.event_log import verify_event_chain
from castle.graph.models import Remediation, Risk, System, Vendor
from castle.models import Engagement

# The node envelope every node table must carry (OS-1, schema section 1).
ENVELOPE_COLUMNS = {
    "node_uid",
    "engagement_id",
    "content_sha256",
    "content_sha256_at",
    "source_ref",
    "created_at",
    "updated_at",
}

NODE_MODELS = (Risk, Remediation, System, Vendor)


@pytest.fixture()
def session(tmp_path):
    init_db(f"sqlite:///{tmp_path / 'conformance.db'}")
    return get_session()


@pytest.fixture()
def engagement(session):
    eng = Engagement(client_name="Conformance", client_email="kit@example.test")
    session.add(eng)
    session.flush()
    return eng


@pytest.fixture()
def stamped_risk(session, engagement):
    risk = Risk(
        node_uid=f"risk:conformance:eng{engagement.id}",
        engagement_id=engagement.id,
        title="Unencrypted backups",
        likelihood="high",
        impact="high",
        status="open",
    )
    session.add(risk)
    session.flush()
    og.stamp_node(session, risk, object_type="risk")
    session.commit()
    return risk


# -- OS-1 ---------------------------------------------------------------------


def test_node_envelope_columns_present():
    for model in NODE_MODELS:
        columns = set(model.__table__.c.keys())
        missing = ENVELOPE_COLUMNS - columns
        assert not missing, f"{model.__tablename__} is missing envelope columns: {missing}"


def test_node_uid_uniqueness_enforced(session, engagement, stamped_risk):
    duplicate = Risk(
        node_uid=stamped_risk.node_uid,
        engagement_id=engagement.id,
        title="Duplicate uid",
        status="open",
    )
    session.add(duplicate)
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


# -- OS-2 ---------------------------------------------------------------------


def test_canonical_serialization_is_deterministic_json(stamped_risk):
    canonical = og.canonical_serialization(stamped_risk)
    parsed = json.loads(canonical)
    # Sorted keys + compact separators: re-serializing reproduces the bytes.
    assert canonical == json.dumps(parsed, sort_keys=True, separators=(",", ":"), default=str)
    # Envelope/bookkeeping and documented lifecycle columns are excluded.
    for excluded in ("id", "content_sha256", "content_sha256_at", "created_at", "updated_at"):
        assert excluded not in parsed
    for lifecycle in ("status", "residual_score"):  # risks lifecycle exclusions
        assert lifecycle not in parsed
    # Identity fields are included.
    assert parsed["node_uid"] == stamped_risk.node_uid
    assert parsed["title"] == "Unencrypted backups"


# -- OS-3 ---------------------------------------------------------------------


def test_fingerprint_recomputable_with_stdlib_sha256(stamped_risk):
    recomputed = hashlib.sha256(
        og.canonical_serialization(stamped_risk).encode("utf-8")
    ).hexdigest()
    assert recomputed == stamped_risk.content_sha256


# -- OS-4 ---------------------------------------------------------------------


def test_stamp_is_write_once(session, stamped_risk):
    original = stamped_risk.content_sha256
    again = og.stamp_node(session, stamped_risk, object_type="risk")
    assert again == original
    # Even after an edit, re-stamping must NOT overwrite: the edit has to
    # surface as a verify mismatch instead (OS-6), never a silent re-hash.
    stamped_risk.title = "Edited title"
    assert og.stamp_node(session, stamped_risk, object_type="risk") == original
    stamped_risk.title = "Unencrypted backups"
    session.commit()


# -- OS-5 ---------------------------------------------------------------------


def test_lifecycle_fields_mutate_without_breaking_verification(session, engagement, stamped_risk):
    stamped_risk.status = "accepted"
    stamped_risk.residual_score = 2.5
    session.commit()
    assert og.verify_graph(session, engagement_id=engagement.id) == []


# -- OS-6 ---------------------------------------------------------------------


def test_identity_tampering_is_detected(session, engagement, stamped_risk):
    stamped = stamped_risk.content_sha256
    # Raw SQL: simulate out-of-band tampering that bypasses every ORM guard.
    session.execute(
        text("UPDATE risks SET title = :t WHERE id = :i"),
        {"t": "Tampered title", "i": stamped_risk.id},
    )
    session.commit()
    session.expire_all()
    mismatches = og.verify_graph(session, engagement_id=engagement.id)
    hits = [m for m in mismatches if m.node_uid == stamped_risk.node_uid]
    assert hits, "tampered node was not reported"
    assert hits[0].stamped_sha == stamped
    assert hits[0].current_sha != stamped


# -- OS-7 ---------------------------------------------------------------------


def test_stamp_lands_on_intact_event_chain(session, engagement, stamped_risk):
    types = [e.event_type for e in engagement.events]
    assert "node_integrity_stamped" in types
    assert verify_event_chain(session, engagement.id) == []
