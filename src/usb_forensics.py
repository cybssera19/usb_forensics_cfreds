"""Educational correlation engine. Input: exports and reviewed normalized evidence.
Does not parse raw disk images or infer copying from file timestamps.
Python 3.9+, standard library only.
"""
import argparse
import hashlib
import json
import math
import random
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_id(media, relative_path):
    value = json.dumps([media, relative_path], ensure_ascii=False)
    return hashlib.sha256(value.encode()).hexdigest()


def scan_export(folder, media, complete=False):
    """complete=True is an examiner assertion, not an automatic recovery check."""
    folder = Path(folder)
    if not folder.is_dir():
        raise ValueError("Folder ekspor tidak ditemukan: " + str(folder))
    result = []
    for path in sorted(folder.rglob("*")):
        if path.is_symlink():
            raise ValueError("Symlink dalam folder ekspor: " + str(path))
        if not path.is_file():
            continue
        before = path.stat()
        digest = sha256_file(path)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("File berubah selama dibaca: " + str(path))
        relative = path.relative_to(folder).as_posix()
        identifier = file_id(media, relative)
        result.append({
            "id": identifier, "root_id": identifier, "depends_on": [],
            "kind": "file", "group": "content", "media_id": media,
            "export_path": relative, "sha256": digest, "size": before.st_size,
            "complete": complete, "source": "export:" + media,
            "locator": relative
        })
    return result


def utc(value):
    value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("Timestamp harus menyertakan zona waktu.")
    return value.astimezone(timezone.utc)


def validate(records):
    by_id = {}
    for row in records:
        for key in ("id", "root_id", "kind", "group", "source", "locator"):
            if not isinstance(row.get(key), str) or not row[key]:
                raise ValueError("Field wajib tidak valid: " + key)
        deps = row.get("depends_on")
        if not isinstance(deps, list) or not all(isinstance(x, str) for x in deps):
            raise ValueError("depends_on harus berupa daftar ID.")
        if row["kind"] == "file":
            for key in ("media_id", "export_path"):
                if not isinstance(row.get(key), str) or not row[key]:
                    raise ValueError("Field file tidak valid: " + key)
            if type(row.get("complete")) is not bool:
                raise ValueError("complete harus boolean.")
            if type(row.get("size")) is not int or row["size"] < 0:
                raise ValueError("Ukuran file tidak valid.")
            digest = row.get("sha256", "")
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("SHA-256 tidak valid.")
        elif row["kind"] == "file_reference":
            utc(row["time"])
            if not row.get("time_semantic") or not row.get("file_id"):
                raise ValueError("Referensi membutuhkan file_id dan time_semantic.")
        elif row["kind"] == "copy_operation":
            if utc(row["start"]) > utc(row["end"]):
                raise ValueError("Awal interval melebihi akhir.")
            if not row.get("source_file_id") or not row.get("target_file_id"):
                raise ValueError("Operasi membutuhkan ID sumber dan tujuan.")
        else:
            raise ValueError("Kind tidak didukung: " + row["kind"])
        if row["id"] in by_id and row != by_id[row["id"]]:
            raise ValueError("ID sama memiliki isi berbeda: " + row["id"])
        by_id[row["id"]] = row
    for row in by_id.values():
        if any(dep not in by_id for dep in row["depends_on"]):
            raise ValueError("Dependensi bukti tidak ditemukan.")
    return list(by_id.values())


def evidence(row):
    return {key: row[key] for key in ("id", "root_id", "source", "locator")}


def analyze(records, pc_id="PC"):
    records = validate(records)
    files = [row for row in records if row["kind"] == "file"]
    targets = defaultdict(list)
    for row in files:
        if row["media_id"] != pc_id:
            targets[(row["sha256"], row["size"])].append(row)
    references, operations = defaultdict(list), defaultdict(list)
    seen = set()
    for row in records:
        if row["kind"] == "file_reference":
            key = ("ref", row["root_id"], row["file_id"], row["time"], row["time_semantic"])
            if key not in seen:
                references[row["file_id"]].append(row)
                seen.add(key)
        elif row["kind"] == "copy_operation":
            key = ("op", row["root_id"], row["source_file_id"],
                   row["target_file_id"], row["start"], row["end"])
            if key not in seen:
                operations[(row["source_file_id"], row["target_file_id"])].append(row)
                seen.add(key)

    matches = []
    for pc in files:
        if pc["media_id"] != pc_id:
            continue
        for usb in targets[(pc["sha256"], pc["size"])]:
            full = pc["complete"] and usb["complete"]
            forward = operations[(pc["id"], usb["id"])] if full else []
            reverse = operations[(usb["id"], pc["id"])] if full else []
            direction = "unknown"
            if forward and reverse:
                direction = "operation_records_in_both_directions"
            elif forward:
                direction = "pc_to_usb_reported_by_operation_record"
            elif reverse:
                direction = "usb_to_pc_reported_by_operation_record"
            def operation_view(rows):
                return [{
                    "start": utc(r["start"]).isoformat(),
                    "end": utc(r["end"]).isoformat(),
                    "evidence": evidence(r)
                } for r in rows]
            activity = references[pc["id"]] + references[usb["id"]]
            matches.append({
                "pair_id": pc["id"] + ":" + usb["id"],
                "pc_file_id": pc["id"], "usb_file_id": usb["id"],
                "pc_path": pc["export_path"], "usb_path": usb["export_path"],
                "usb_image_id": usb["media_id"],
                "physical_device": "requires acquisition/volume mapping",
                "sha256": pc["sha256"], "size": pc["size"],
                "identity_status": "identical_content" if full else "identical_exported_bytes_only",
                "direction": direction,
                "forward_copy_operations": operation_view(forward),
                "reverse_copy_operations": operation_view(reverse),
                "related_activity": [{
                    "time": utc(r["time"]).isoformat(),
                    "meaning": r["time_semantic"], "evidence": evidence(r)
                } for r in sorted(activity, key=lambda r: utc(r["time"]))],
                "content_evidence": [evidence(pc), evidence(usb)]
            })
    return {"method": "educational_exact_match_v1", "observations": len(records),
            "matches": matches,
            "limitation": "Equal contents alone do not establish copying direction or time."}


def mask_records(records, fraction=0.0, seed=42, drop_group=None):
    """Mask evidence roots and all dependent records; never mutate originals."""
    records = validate(records)
    if not 0 <= fraction <= 1:
        raise ValueError("fraction harus antara 0 dan 1.")
    roots = sorted({r["root_id"] for r in records})
    removed_roots = set(random.Random(seed).sample(roots, math.floor(len(roots) * fraction)))
    if drop_group:
        removed_roots.update(r["root_id"] for r in records if r["group"] == drop_group)
    removed = {r["id"] for r in records if r["root_id"] in removed_roots}
    while True:
        added = {r["id"] for r in records if set(r["depends_on"]) & removed}
        if added <= removed:
            break
        removed.update(added)
    return [r for r in records if r["id"] not in removed], sorted(removed)


def identity_metrics(report, truth_pairs):
    predicted = {m["pair_id"] for m in report["matches"] if m["identity_status"] == "identical_content"}
    truth = set(truth_pairs)
    tp, fp, fn = len(predicted & truth), len(predicted - truth), len(truth - predicted)
    return {"scope": "document_identity_pairs_only", "tp": tp, "fp": fp, "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None}


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_records(paths):
    records = []
    for path in paths:
        rows = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(rows, list):
            raise ValueError("Input harus JSON array.")
        records.extend(rows)
    return validate(records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("--folder", required=True)
    scan.add_argument("--media", required=True)
    scan.add_argument("--complete", action="store_true",
                      help="Gunakan hanya untuk ekspor yang telah diverifikasi utuh.")
    scan.add_argument("--out", required=True)
    for name in ("analyze", "experiment"):
        p = sub.add_parser(name)
        p.add_argument("--inputs", nargs="+", required=True)
        p.add_argument("--pc-id", default="PC")
        p.add_argument("--out", required=True)
        if name == "experiment":
            p.add_argument("--fraction", type=float, default=0)
            p.add_argument("--seed", type=int, default=42)
            p.add_argument("--drop-group")
            p.add_argument("--truth")
    args = parser.parse_args()
    try:
        output = Path(args.out).resolve()
        if args.command == "scan":
            if Path(args.folder).resolve() in (output, *output.parents):
                raise ValueError("Output harus di luar folder ekspor.")
            result = scan_export(args.folder, args.media, args.complete)
        else:
            protected = list(args.inputs)
            if getattr(args, "truth", None):
                protected.append(args.truth)
            if output in [Path(p).resolve() for p in protected]:
                raise ValueError("Output tidak boleh menimpa input.")
            records = read_records(args.inputs)
            removed = []
            if args.command == "experiment":
                records, removed = mask_records(records, args.fraction, args.seed, args.drop_group)
            result = analyze(records, args.pc_id)
            if args.command == "experiment":
                result["removed_record_ids"] = removed
                if args.truth:
                    truth = json.loads(Path(args.truth).read_text(encoding="utf-8"))
                    result["metrics"] = identity_metrics(result, truth)
        write_json(output, result)
        print(output)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(2, str(exc) + "\n")


if __name__ == "__main__":
    main()
