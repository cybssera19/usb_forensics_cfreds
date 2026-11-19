import copy
import tempfile
import unittest
from pathlib import Path
from demo import build_demo
from usb_forensics import analyze, read_records, mask_records, scan_export, validate, identity_metrics


class ForensicTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = build_demo(Path(self.tmp.name) / "case")
        self.records = read_records([self.root / n for n in ("pc.json", "usb02.json", "events.json")])

    def test_renamed_document_found_same_name_different_content_excluded(self):
        matches = analyze(self.records)["matches"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["pc_path"], "anggaran.txt")
        self.assertEqual(matches[0]["usb_path"], "foto_liburan.jpg")

    def test_access_reference_does_not_prove_copy(self):
        visible, _ = mask_records(self.records, drop_group="operation_log")
        match = analyze(visible)["matches"][0]
        self.assertEqual(match["direction"], "unknown")
        self.assertEqual(match["forward_copy_operations"], [])
        self.assertEqual(len(match["related_activity"]), 1)

    def test_explicit_log_has_interval(self):
        match = analyze(self.records)["matches"][0]
        self.assertEqual(match["forward_copy_operations"][0]["start"], "2020-01-01T10:02:00+00:00")

    def test_partial_content_not_full_identity(self):
        for row in self.records:
            if row["kind"] == "file" and row["media_id"] == "USB02":
                row["complete"] = False
        match = analyze(self.records)["matches"][0]
        self.assertEqual(match["identity_status"], "identical_exported_bytes_only")
        self.assertEqual(match["direction"], "unknown")

    def test_removed_content_cannot_be_reused(self):
        visible, _ = mask_records(self.records, drop_group="content")
        self.assertEqual(analyze(visible)["matches"], [])

    def test_dependency_removal_transitive(self):
        self.records[-1]["depends_on"] = ["access-1"]
        visible, removed = mask_records(self.records, drop_group="access")
        self.assertIn("operation-1", removed)
        self.assertEqual(analyze(visible)["matches"][0]["direction"], "unknown")

    def test_duplicate_origin_not_double_counted(self):
        duplicate = copy.deepcopy(self.records[-1])
        duplicate["id"] = "duplicate-export"
        self.records.append(duplicate)
        self.assertEqual(len(analyze(self.records)["matches"][0]["forward_copy_operations"]), 1)

    def test_conflicting_id_rejected(self):
        duplicate = copy.deepcopy(self.records[-1])
        duplicate["end"] = "2020-01-01T11:00:00Z"
        with self.assertRaises(ValueError):
            validate(self.records + [duplicate])

    def test_timezone_required(self):
        self.records[-2]["time"] = "2020-01-01T10:05:00"
        with self.assertRaises(ValueError):
            validate(self.records)

    def test_reverse_copy_not_called_forward(self):
        op = self.records[-1]
        op["source_file_id"], op["target_file_id"] = op["target_file_id"], op["source_file_id"]
        match = analyze(self.records)["matches"][0]
        self.assertEqual(match["direction"], "usb_to_pc_reported_by_operation_record")
        self.assertEqual(match["forward_copy_operations"], [])

    def test_mask_reproducible_truth_denominator_fixed(self):
        self.assertEqual(mask_records(self.records, .3, 42), mask_records(self.records, .3, 42))
        truth = [m["pair_id"] for m in analyze(self.records)["matches"]]
        visible, _ = mask_records(self.records, drop_group="content")
        metrics = identity_metrics(analyze(visible), truth)
        self.assertEqual(metrics["fn"], 1)
        self.assertEqual(metrics["recall"], 0)
        self.assertIsNone(metrics["precision"])

    def test_distinct_instances_preserved(self):
        row = copy.deepcopy(next(r for r in self.records if r.get("export_path") == "anggaran.txt"))
        row.update(id="another-instance", root_id="another-instance", export_path="copy/anggaran.txt")
        matches = analyze(self.records + [row])["matches"]
        self.assertEqual(len(matches), 2)
        self.assertEqual(matches[1]["direction"], "unknown")

    def test_scanner_conservative_default(self):
        self.assertFalse(scan_export(self.root / "exports/pc", "PC")[0]["complete"])

    def test_missing_export_folder_rejected(self):
        with self.assertRaises(ValueError):
            scan_export(self.root / "missing", "PC")

    def test_missing_dependency_rejected(self):
        self.records[-1]["depends_on"] = ["does-not-exist"]
        with self.assertRaises(ValueError):
            validate(self.records)


if __name__ == "__main__":
    unittest.main()
