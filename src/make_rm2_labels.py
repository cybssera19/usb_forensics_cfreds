"""Buat label sisi RM#2 dari kunci jawaban NIST (Q53, Q54, Q55, Q59).

Label disusun dari dokumen NIST, BUKAN dari hasil prediksi program.
Format ID file sama dengan usb_forensics.file_id(media, relative_path).

Jalankan:
    python make_rm2_labels.py
Output:
    D:\\RM\\data\\labels\\rm2_labels.json
"""
import hashlib
import json
from pathlib import Path

DATA = Path(r"D:\RM\data")
USB_EXPORT = DATA / "exports" / "usb02"
OUT = DATA / "labels" / "rm2_labels.json"
MEDIA = "USB02"

# (path relatif hasil tsk_recover, format asli menurut NIST Q53, jejak JumpList/ShellBag di PC menurut NIST Q55)
TARGETS = [
    ("$OrphanFiles/design/winter_storm.amr", "PPT", None),
    ("$OrphanFiles/design/winter_whether_advisory.zip", "PPTX",
     r"E:\Secret Project Data\design\winter_whether_advisory.zip"),
    ("$OrphanFiles/PRICIN~1/my_favorite_cars.db", "XLS", None),
    ("$OrphanFiles/PRICIN~1/my_favorite_movies.7z", "XLSX", None),
    ("$OrphanFiles/PRICIN~1/new_years_day.jpg", "XLSX", None),
    ("$OrphanFiles/PRICIN~1/super_bowl.avi", "XLS", None),
    ("$OrphanFiles/progress/my_friends.svg", "DOC", None),
    ("$OrphanFiles/progress/my_smartphone.png", "DOCX", None),
    ("$OrphanFiles/progress/new_year_calendar.one", "DOCX", None),
    ("$OrphanFiles/proposal/a_gift_from_you.gif", "DOCX", None),
    ("$OrphanFiles/proposal/landscape.png", "DOCX", None),
    ("$OrphanFiles/TECHNI~1/diary_#1d.txt", "DOCX", None),
    ("$OrphanFiles/TECHNI~1/diary_#1p.txt", "PPTX", None),
    ("$OrphanFiles/TECHNI~1/diary_#2d.txt", "DOCX", None),
    ("$OrphanFiles/TECHNI~1/diary_#2p.txt", "PPT", None),
    ("$OrphanFiles/TECHNI~1/diary_#3d.txt", "DOC", None),
    ("$OrphanFiles/TECHNI~1/diary_#3p.txt", "PPT", None),
]


def file_id(media, relative_path):
    # Identik dengan usb_forensics.file_id
    value = json.dumps([media, relative_path], ensure_ascii=False)
    return hashlib.sha256(value.encode()).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def describe(rel):
    path = USB_EXPORT / Path(rel)
    return {
        "usb_file_id": file_id(MEDIA, rel),
        "export_path": rel,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def main():
    if not USB_EXPORT.is_dir():
        raise SystemExit("Folder ekspor tidak ditemukan: " + str(USB_EXPORT))

    target_paths = {rel for rel, _, _ in TARGETS}
    targets, missing = [], []
    for rel, real_format, trace in TARGETS:
        if not (USB_EXPORT / Path(rel)).is_file():
            missing.append(rel)
            continue
        row = describe(rel)
        row.update({
            "label": "target_copied_pc_to_rm2",
            "real_format_nist_q53": real_format,
            "pc_jumplist_shellbag_nist_q55": trace,
            "nist_reference": "Q53, Q55",
        })
        targets.append(row)

    negatives = []
    for path in sorted(USB_EXPORT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(USB_EXPORT).as_posix()
        if rel in target_paths:
            continue
        row = describe(rel)
        row.update({
            "label": "negative_not_related_to_scenario",
            "nist_reference": "Q53 ('All other files do not have a relationship with this scenario')",
        })
        negatives.append(row)

    labels = {
        "dataset": "NIST CFReDS Data Leakage Case",
        "label_source": "leakage-answers.pdf (Last Saved 2018-07-23), Q53, Q54, Q55, Q59",
        "note": "Label disusun dari dokumen NIST, bukan dari prediksi program. "
                "Jangan dibaca oleh analyze; hanya untuk evaluasi.",
        "media_id": MEDIA,
        "copy_event_reported_by_nist": {
            "direction": "PC -> RM#2",
            "date": "2015-03-24",
            "time_window": "09:58 ~ 10:00",
            "timezone_note": "NIST menulis 'Timezone is applied'. Log lain di kasus ini memakai "
                             "offset -04:00 (lihat Q52). Verifikasi zona waktu sebelum dipakai "
                             "untuk evaluasi waktu.",
            "nist_reference": "Q59",
        },
        "anti_forensics_rm2": {"action": "quick format", "nist_reference": "Q54"},
        "pair_labels_status": "BELUM: butuh lokasi file sumber di PC (NIST Q25/Q26) "
                              "untuk membentuk pasangan pc_file_id:usb_file_id.",
        "targets": targets,
        "negatives": negatives,
        "missing_targets": missing,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(labels, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("Label tersimpan :", OUT)
    print("Target          :", len(targets), "/ 17")
    print("Contoh negatif  :", len(negatives))
    if missing:
        print("PERINGATAN, target tidak ditemukan:", *missing, sep="\n  ")


if __name__ == "__main__":
    main()
