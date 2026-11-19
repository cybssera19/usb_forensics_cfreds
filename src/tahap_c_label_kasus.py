"""TAHAP C (README dosen bagian 7 dan 9): label kasus dan peta akuisisi.

Membuat dua file dari dokumentasi NIST, BUKAN dari hasil program:

1. data\\normalized\\device_map.json  (dokumentasi akuisisi: image -> nomor seri)
   Ini input mesin korelasi, sama seperti catatan akuisisi di lab forensik.
2. data\\labels\\case_labels.json     (kunci jawaban untuk evaluasi saja)
   Berisi label file dari rm2_labels.json (Q53-Q55) + perangkat, arah,
   jendela waktu (Q59), dan urutan kejadian dari narasi skenario NIST.

PENTING: cocokkan dulu nomor seri dengan dokumen NIST (Ctrl+F "4C53").
Setelah cocok, jalankan dengan --serial-verified.

Pakai:
    python tahap_c_label_kasus.py --serial-verified
"""
import argparse
import json
from pathlib import Path

from usb_forensics import write_json


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rm2-labels", default=r"D:\RM\data\labels\rm2_labels.json")
    p.add_argument("--serial", default="4C530012550531106501")
    p.add_argument("--serial-verified", action="store_true",
                   help="Pakai hanya setelah nomor seri dicocokkan dengan dokumen NIST.")
    p.add_argument("--device-map", default=r"D:\RM\data\normalized\device_map.json")
    p.add_argument("--out", default=r"D:\RM\data\labels\case_labels.json")
    a = p.parse_args()

    base = json.loads(Path(a.rm2_labels).read_text(encoding="utf-8"))
    status = "verified_against_nist_documentation" if a.serial_verified else "NOT_YET_VERIFIED"

    write_json(a.device_map, {
        "USB02": {"image": "cfreds_2015_data_leakage_rm#2.dd", "case_name": "RM#2",
                  "serial": a.serial, "source": "dokumentasi akuisisi NIST",
                  "status": status}
    })
    write_json(a.out, {
        "dataset": base.get("dataset"),
        "label_source": base.get("label_source"),
        "note": "Hanya untuk evaluasi. Tidak boleh dibaca oleh tahap A, B, dan D.",
        "targets": [t["usb_file_id"] for t in base["targets"]],
        "target_paths": [t["export_path"] for t in base["targets"]],
        "negatives": [n["usb_file_id"] for n in base["negatives"]],
        "device_serial": a.serial, "device_serial_status": status,
        "direction": "pc_to_usb",
        "copy_window_utc": ["2015-03-24T13:58:00+00:00", "2015-03-24T14:00:59+00:00"],
        "copy_window_note": "NIST Q59: 09:58-10:00 EDT (UTC-4), resolusi menit",
        "event_order": ["pc_ingest", "pc_rename", "device_connect", "usb_copy", "pc_delete"],
        "event_order_note": "Narasi NIST 24 Mar 2015 (EDT): 09:40 salin RM#1 ke PC, "
                            "09:50-09:56 ganti nama, 09:58 RM#2 dicolok, 09:59 salin ke RM#2, "
                            "10:07 folder dihapus",
    })
    print("device_map  :", a.device_map, "(" + status + ")")
    print("case_labels :", a.out)
    print("Target      :", len(base["targets"]), " Negatif:", len(base["negatives"]))


if __name__ == "__main__":
    main()
