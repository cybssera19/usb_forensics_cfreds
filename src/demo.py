"""Generate a synthetic fixture. This is NOT a result from the NIST dataset."""
import argparse
from pathlib import Path
from usb_forensics import scan_export, file_id, write_json, analyze, mask_records, identity_metrics


def build_demo(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    pc, usb = root / "exports/pc", root / "exports/usb02"
    pc.mkdir(parents=True)
    usb.mkdir(parents=True)
    content = b"SYNTHETIC TRAINING DOCUMENT: Project budget 12345.\n"
    (pc / "anggaran.txt").write_bytes(content)
    (usb / "foto_liburan.jpg").write_bytes(content)  # Renamed text; not a real JPEG.
    (pc / "catatan.txt").write_text("Isi pada komputer.", encoding="utf-8")
    (usb / "catatan.txt").write_text("Isi berbeda pada USB.", encoding="utf-8")
    source, target = file_id("PC", "anggaran.txt"), file_id("USB02", "foto_liburan.jpg")
    pc_rows, usb_rows = scan_export(pc, "PC", True), scan_export(usb, "USB02", True)
    events = [
        {"id": "access-1", "root_id": "access-1", "depends_on": [],
         "kind": "file_reference", "group": "access", "file_id": target,
         "time": "2020-01-01T10:05:00+00:00",
         "time_semantic": "synthetic reference to file; not a copy time",
         "source": "SYNTHETIC_FIXTURE", "locator": "demo:event:1"},
        {"id": "operation-1", "root_id": "operation-1", "depends_on": [],
         "kind": "copy_operation", "group": "operation_log",
         "source_file_id": source, "target_file_id": target,
         "start": "2020-01-01T10:02:00+00:00", "end": "2020-01-01T10:03:00+00:00",
         "source": "SYNTHETIC_FIXTURE", "locator": "demo:event:2"}
    ]
    records = pc_rows + usb_rows + events
    # Labels are known from fixture construction, not generated from predictions.
    truth = [source + ":" + target]
    for name, data in (("pc.json", pc_rows), ("usb02.json", usb_rows),
                       ("events.json", events), ("truth_identity_pairs.json", truth)):
        write_json(root / name, data)
    summary = {}
    scenarios = {"full": {}, "without_access": {"drop_group": "access"},
                 "without_operation_log": {"drop_group": "operation_log"},
                 "without_content": {"drop_group": "content"},
                 "random_30pct": {"fraction": .3, "seed": 42}}
    for name, options in scenarios.items():
        visible, removed = mask_records(records, **options)
        report = analyze(visible)
        report["dataset"] = "SYNTHETIC_DEMO_NOT_NIST"
        report["removed_record_ids"] = removed
        report["metrics"] = identity_metrics(report, truth)
        write_json(root / "results" / (name + ".json"), report)
        summary[name] = {
            "matches": len(report["matches"]),
            "directions": [m["direction"] for m in report["matches"]],
            "metrics": report["metrics"]
        }
    write_json(root / "summary.json", summary)
    return root


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="demo-output")
    args = parser.parse_args()
    print(build_demo(args.out))
