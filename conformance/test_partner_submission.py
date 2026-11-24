"""Partner Document Submission conformance checks (PS-1 .. PS-6).

Implementation neutral: these run against the schema, the samples and the
stdlib reference receiver in verifier/pds_check.py, with no Castle import.
PS-7 (vocabulary in step with the reference implementation) runs only when
Castle is importable.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import re
import zipfile
from datetime import date
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "schemas/partner-submission-v0.1.schema.json").read_text("utf-8"))
SPEC = (ROOT / "PARTNER-SUBMISSION.md").read_text("utf-8")
_spec = importlib.util.spec_from_file_location("pds_check", ROOT / "verifier/pds_check.py")
assert _spec and _spec.loader
pds = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pds)
V = jsonschema.Draft202012Validator(SCHEMA)
TODAY = date(2026, 11, 24)


def _bundle(items_files, **manifest_over):
    items = []
    for item, data in items_files:
        item = {"media_type": "text/plain", "document_date": "2026-10-01", **item}
        item.setdefault("sha256", hashlib.sha256(data).hexdigest())
        item.setdefault("size_bytes", len(data))
        items.append(item)
    manifest = {
        "pds_version": "0.1",
        "partner": {"legal_name": "Keystone", "kind": "mga"},
        "recipient": {"legal_name": "Northwind"},
        "submitted_by": {"name": "Hannah Becker"},
        "submitted_at": "2026-11-24T15:00:00Z",
        "items": items,
        **manifest_over,
    }
    files = {i["filename"]: d for i, d in zip(items, (d for _, d in items_files), strict=True)}
    return manifest, files


def _receive(manifest, files, today=TODAY):
    mb = json.dumps(manifest).encode()
    return pds.receive(mb, files.get, today)


def test_ps1_schema_is_valid_and_samples_validate():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    sample = json.loads((ROOT / "samples/sample-submission.json").read_text("utf-8"))
    assert V.is_valid(sample)


def test_ps2_sample_bundle_is_received_and_receipt_validates(capsys):
    assert pds.main([str(ROOT / "samples/sample-submission.zip"), "--today", "2026-11-24"]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert V.is_valid(receipt)
    assert [i["status"] for i in receipt["items"]] == ["received", "received"]
    with zipfile.ZipFile(ROOT / "samples/sample-submission.zip") as zf:
        assert receipt["manifest_sha256"] == hashlib.sha256(zf.read("manifest.json")).hexdigest()


def test_ps3_digest_size_and_missing_file_are_rejected_per_item():
    m, f = _bundle(
        [
            ({"requirement": "doc_bcp", "filename": "ok.txt"}, b"plan"),
            ({"requirement": "doc_dr", "filename": "bad.txt"}, b"dr"),
            ({"requirement": "doc_infosec", "filename": "size.txt", "size_bytes": 99}, b"sec"),
            ({"requirement": "doc_privacy", "filename": "gone.txt"}, b"p"),
        ]
    )
    f["bad.txt"] = b"changed"
    del f["gone.txt"]
    got = {i["filename"]: (i["status"], i.get("reason")) for i in _receive(m, f)["items"]}
    assert got == {
        "ok.txt": ("received", None),
        "bad.txt": ("rejected", "digest_mismatch"),
        "size.txt": ("rejected", "size_mismatch"),
        "gone.txt": ("rejected", "missing_file"),
    }


def test_ps4_vocabulary_and_expiry_rules():
    m, f = _bundle(
        [
            ({"requirement": "doc_nope", "filename": "a.txt"}, b"a"),
            ({"requirement": "x-flood-procedures", "filename": "b.txt"}, b"b"),
            ({"requirement": "doc_coi_eo", "filename": "c.txt"}, b"c"),
            ({"requirement": "doc_license", "filename": "d.txt", "expires_on": "2026-11-23"}, b"d"),
            ({"requirement": "doc_bcp", "filename": "e.txt", "document_date": "2024-01-01"}, b"e"),
        ]
    )
    got = {i["filename"]: (i["status"], i.get("reason")) for i in _receive(m, f)["items"]}
    assert got == {
        "a.txt": ("rejected", "unknown_requirement"),
        "b.txt": ("received", None),
        "c.txt": ("rejected", "missing_expiry"),
        "d.txt": ("rejected", "expired"),
        "e.txt": ("stale", None),  # received, flagged, not rejected
    }


def test_ps5_unusable_manifests_and_path_names(tmp_path):
    m, f = _bundle([({"requirement": "doc_bcp", "filename": "a.txt"}, b"a")])
    for bad in (
        {**m, "pds_version": "9"},
        {**m, "submitted_by": {"name": "system"}},
        {**m, "items": []},
        {**m, "items": m["items"] * 2},  # duplicate filename
    ):
        with pytest.raises(pds.Unusable):
            _receive(bad, f)
    m2, f2 = _bundle([({"requirement": "doc_bcp", "filename": "../a.txt"}, b"a")])
    assert _receive(m2, f2)["items"][0]["status"] == "rejected"
    zpath = tmp_path / "no-manifest.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("a.txt", b"a")
    assert pds.main([str(zpath)]) == 2


def test_ps6_checker_and_schema_agree_with_the_spec_table():
    enum = set(SCHEMA["$defs"]["requirement"]["anyOf"][0]["enum"])
    assert enum == set(pds.VOCABULARY)
    expiring = set(
        SCHEMA["$defs"]["manifest"]["properties"]["items"]["items"]["allOf"][0]["if"]["properties"][
            "requirement"
        ]["enum"]
    )
    assert expiring == {k for k, (_, e) in pds.VOCABULARY.items() if e}
    for key, (age, exp) in pds.VOCABULARY.items():
        row = re.search(rf"^\| `{key}` \| [^|]+ \| (\d+) \| (yes)? *\|$", SPEC, re.M)
        assert row and int(row.group(1)) == age and bool(row.group(2)) == exp, key


def test_ps7_vocabulary_matches_the_reference_implementation():
    pd = pytest.importorskip("castle.insurance.partner_documents")
    assert {r.key: (r.max_age_days, r.expires) for r in pd.CHECKLIST} == pds.VOCABULARY


def test_zip_reader_ignores_nested_paths(tmp_path):
    buf = io.BytesIO()
    data = b"plan"
    m, _ = _bundle([({"requirement": "doc_bcp", "filename": "a.txt"}, data)])
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps(m))
        zf.writestr("sub/a.txt", data)  # not at the root: not read
    p = tmp_path / "b.zip"
    p.write_bytes(buf.getvalue())
    assert pds.main([str(p), "--today", "2026-11-24"]) == 1
