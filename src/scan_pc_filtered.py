# Untuk mengekstrak file PC yang ukurannya sama dengan file USB02, lalu menghitung hash SHA256
# dari file tersebut dan menyimpannya dalam format JSON.
#
# Perubahan dari versi asli (cadangan: scan_pc_filtered.py.bak):
#   1. Baris komentar "//" diganti "#" (Python tidak mengenal "//" sebagai komentar).
#   2. Path bisa diisi lewat argumen. Kalau argumen tidak diisi, dipakai path default yang sama
#      dengan versi asli, jadi perilaku lama tidak berubah.
# Logika filter dan format output TIDAK diubah.

import argparse
import json
import time
from pathlib import Path

from usb_forensics import file_id, sha256_file, write_json

DEFAULT_PC_EXPORT = r"D:\RM\data\exports\pc"
DEFAULT_USB_JSON = r"D:\RM\data\normalized\usb02.json"
DEFAULT_OUT = r"D:\RM\data\normalized\pc.json"
DEFAULT_STATS = r"D:\RM\data\normalized\pc_filter_stats.json"
MEDIA = "PC"


def main():
    parser = argparse.ArgumentParser(description="Hash file PC yang ukurannya sama dengan file USB02.")
    parser.add_argument("--pc-export", default=DEFAULT_PC_EXPORT, help="Folder hasil tsk_recover image PC")
    parser.add_argument("--usb", default=DEFAULT_USB_JSON, help="usb02.json hasil usb_forensics.py scan")
    parser.add_argument("--out", default=DEFAULT_OUT, help="File output pc.json")
    parser.add_argument("--stats", default=DEFAULT_STATS, help="File output pc_filter_stats.json")
    args = parser.parse_args()

    PC_EXPORT = Path(args.pc_export)
    USB_JSON = Path(args.usb)
    OUT = Path(args.out)
    STATS = Path(args.stats)

    print("PC export :", PC_EXPORT)
    print("USB json  :", USB_JSON)
    print("Output    :", OUT)

    start = time.time()
    usb_rows = json.loads(USB_JSON.read_text(encoding="utf-8"))
    usb_sizes = {row["size"] for row in usb_rows if row.get("kind") == "file"}

    total, candidates, records = 0, 0, []
    for path in sorted(PC_EXPORT.rglob("*")):
        if not path.is_file():
            continue
        total += 1
        before = path.stat()
        if before.st_size not in usb_sizes:
            continue
        candidates += 1
        digest = sha256_file(path)
        relative = path.relative_to(PC_EXPORT).as_posix()
        identifier = file_id(MEDIA, relative)
        records.append({
            "id": identifier, "root_id": identifier, "depends_on": [],
            "kind": "file", "group": "content", "media_id": MEDIA,
            "export_path": relative, "sha256": digest, "size": before.st_size,
            "complete": False, "source": "export:" + MEDIA,
            "locator": relative,
        })

    write_json(OUT, records)
    stats = {
        "pc_files_total": total,
        "distinct_usb_sizes": len(usb_sizes),
        "pc_files_hashed_same_size": candidates,
        "filter_rule": "PC file di-hash hanya jika ukurannya sama dengan salah satu file USB02",
        "seconds": round(time.time() - start, 1),
    }
    write_json(STATS, stats)
    print("Total file PC        :", total)
    print("Ukuran unik di USB02 :", len(usb_sizes))
    print("File PC di-hash      :", candidates)
    print("Waktu (detik)        :", stats["seconds"])


if __name__ == "__main__":
    main()
