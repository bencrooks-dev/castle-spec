#!/usr/bin/env python3
"""Partner Document Submission (PDS) v0.1 reference receiver for the bundle binding.

Standard library only. Applies PARTNER-SUBMISSION.md section 5 to a manifest and
its files and prints the receipt as JSON.

    python pds_check.py bundle.zip [--today YYYY-MM-DD]
    python pds_check.py manifest.json [--dir FOLDER] [--today YYYY-MM-DD]

Exit codes: 0 every item received (some may be stale), 1 at least one item
rejected, 2 the manifest itself is unusable. A received item is never accepted:
acceptance is a separate decision by a named person at the receiver.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from datetime import UTC, date, datetime
from pathlib import Path

# key: (max age in days, expires)
VOCABULARY = {
    "doc_bcp": (365, False),
    "doc_dr": (365, False),
    "doc_infosec": (365, False),
    "doc_incident": (365, False),
    "doc_privacy": (365, False),
    "doc_ai_policy": (365, False),
    "doc_ai_inventory": (182, False),
    "doc_vendor": (365, False),
    "doc_change": (365, False),
    "doc_procedures": (365, False),
    "doc_coi_eo": (400, True),
    "doc_coi_cyber": (400, True),
    "doc_license": (1100, True),
    "doc_financials": (400, False),
    "doc_soc": (400, False),
    "doc_ownership": (365, False),
    "doc_references": (365, False),
    "doc_agreement": (1100, False),
}
_PRIVATE = re.compile(r"^x-[a-z0-9][a-z0-9-]{0,62}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
MAX_ITEMS = 500


class Unusable(Exception):
    """The manifest cannot be processed at all (exit 2)."""


def _date(value: object, field: str) -> date:
    if not isinstance(value, str):
        raise ValueError(field)
    return date.fromisoformat(value)


def check_manifest(manifest: object) -> list[dict]:
    """Structural checks on the whole manifest; returns its items."""
    if not isinstance(manifest, dict) or manifest.get("pds_version") != "0.1":
        raise Unusable("not a PDS 0.1 manifest")
    for key in ("partner", "recipient", "submitted_by", "submitted_at", "items"):
        if key not in manifest:
            raise Unusable(f"missing {key}")
    name = (manifest["submitted_by"] or {}).get("name") if isinstance(manifest["submitted_by"], dict) else None
    if not isinstance(name, str) or len(name.split()) < 2:
        raise Unusable("submitted_by.name must be a named person")
    items = manifest["items"]
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_ITEMS:
        raise Unusable(f"items must be a list of 1 to {MAX_ITEMS}")
    names = [i.get("filename") for i in items if isinstance(i, dict)]
    if len(names) != len(items) or len(set(names)) != len(names):
        raise Unusable("every item needs a unique filename")
    return items


def receive_item(item: dict, data: bytes | None, today: date) -> dict:
    """Section 5 rules for one item; never raises."""
    fname = item.get("filename")
    out: dict = {"filename": fname if isinstance(fname, str) else "?"}

    def reject(reason: str) -> dict:
        return {**out, "status": "rejected", "reason": reason}

    if not isinstance(fname, str) or not fname or "/" in fname or "\\" in fname or len(fname) > 255:
        return reject("other")
    req = item.get("requirement")
    if not isinstance(req, str) or not (req in VOCABULARY or _PRIVATE.match(req)):
        return reject("unknown_requirement")
    sha = item.get("sha256")
    if not isinstance(sha, str) or not _SHA.match(sha):
        return reject("other")
    try:
        doc_date = _date(item.get("document_date"), "document_date")
        expires = _date(item["expires_on"], "expires_on") if "expires_on" in item else None
    except (ValueError, TypeError):
        return reject("other")
    if data is None:
        return reject("missing_file")
    actual = hashlib.sha256(data).hexdigest()
    out["sha256"] = actual
    if actual != sha:
        return reject("digest_mismatch")
    if item.get("size_bytes") != len(data):
        return reject("size_mismatch")
    max_age, must_expire = VOCABULARY.get(req, (None, False))
    if must_expire and expires is None:
        return reject("missing_expiry")
    if expires is not None and expires < today:
        return reject("expired")
    if max_age is not None and (today - doc_date).days > max_age:
        return {**out, "status": "stale"}
    return {**out, "status": "received"}


def receive(manifest_bytes: bytes, read_file, today: date) -> dict:
    """Build the receipt. ``read_file(filename)`` returns bytes or None."""
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError as exc:
        raise Unusable("manifest is not JSON") from exc
    items = check_manifest(manifest)
    results = []
    for item in items:
        fname = item.get("filename")
        safe = isinstance(fname, str) and fname and "/" not in fname and "\\" not in fname
        results.append(receive_item(item, read_file(fname) if safe else None, today))
    return {
        "pds_receipt_version": "0.1",
        "received_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "items": results,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", help="bundle .zip or manifest .json")
    ap.add_argument("--dir", help="folder holding the files (manifest mode; default: the manifest's folder)")
    ap.add_argument("--today", help="date of receipt, YYYY-MM-DD (default: today, UTC)")
    args = ap.parse_args(argv)
    today = date.fromisoformat(args.today) if args.today else datetime.now(UTC).date()
    path = Path(args.path)
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                names = set(zf.namelist())
                if "manifest.json" not in names:
                    raise Unusable("bundle has no manifest.json at its root")

                def read_zip(name: str) -> bytes | None:
                    return zf.read(name) if name in names else None

                receipt = receive(zf.read("manifest.json"), read_zip, today)
        else:
            folder = Path(args.dir) if args.dir else path.parent

            def read_dir(name: str) -> bytes | None:
                f = folder / name
                return f.read_bytes() if f.is_file() else None

            receipt = receive(path.read_bytes(), read_dir, today)
    except (Unusable, OSError, zipfile.BadZipFile) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(receipt, indent=2))
    return 1 if any(i["status"] == "rejected" for i in receipt["items"]) else 0


if __name__ == "__main__":
    sys.exit(main())
