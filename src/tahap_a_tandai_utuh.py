"""TAHAP A (README dosen bagian 5): tandai record USB yang terbukti utuh.

complete=True adalah pernyataan pemeriksa. Di sini pernyataan itu hanya
diberikan pada file USB yang SHA-256 dan ukurannya identik dengan salah satu
file di seed files (dokumen asli NIST). File lain tetap complete=False.

Seed files hanya dipakai untuk memeriksa keutuhan isi. Kecocokan dengan seed
TIDAK dipakai sebagai bukti bahwa file pernah ada di PC.

Pakai (dari folder kode dosen):
    python tahap_a_tandai_utuh.py
Output:
    D:\\RM\\data\\normalized\\usb02_complete.json   (record USB, format kode dosen)
    D:\\RM\\data\\normalized\\usb02_complete_check.json   (catatan pemeriksaan)
"""
import argparse
import json
from pathlib import Path

from usb_forensics import sha256_file, validate, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--usb", default=r"D:\RM\data\normalized\usb02.json")
    parser.add_argument("--seed", default=r"D:\RM\cfreds_2015_data_leakage_seed_files")
    parser.add_argument("--out", default=r"D:\RM\data\normalized\usb02_complete.json")
    parser.add_argument("--check", default=r"D:\RM\data\normalized\usb02_complete_check.json")
    args = parser.parse_args()

    usb_rows = validate(json.loads(Path(args.usb).read_text(encoding="utf-8")))
    seed_dir = Path(args.seed)
    if not seed_dir.is_dir():
        raise SystemExit("Folder seed tidak ditemukan: " + str(seed_dir))

    seeds = {}
    for path in sorted(seed_dir.rglob("*")):
        if path.is_file():
            key = (sha256_file(path), path.stat().st_size)
            seeds.setdefault(key, []).append(path.relative_to(seed_dir).as_posix())

    out, marked = [], []
    for row in usb_rows:
        row = dict(row)
        if row["kind"] == "file":
            hit = seeds.get((row["sha256"], row["size"]))
            if hit:
                row["complete"] = True
                marked.append({"usb_file_id": row["id"], "export_path": row["export_path"],
                               "sha256": row["sha256"], "size": row["size"],
                               "seed_match": hit})
        out.append(row)

    write_json(args.out, validate(out))
    write_json(args.check, {
        "rule": "complete=True hanya jika (sha256, size) identik dengan file seed NIST",
        "usb_input": args.usb, "seed_folder": str(seed_dir),
        "seed_files_hashed": sum(len(v) for v in seeds.values()),
        "usb_files": sum(1 for r in out if r["kind"] == "file"),
        "marked_complete": len(marked), "files": marked,
    })
    print("File seed di-hash   :", sum(len(v) for v in seeds.values()))
    print("File USB            :", sum(1 for r in out if r["kind"] == "file"))
    print("Ditandai complete   :", len(marked))
    print("Output              :", args.out)


if __name__ == "__main__":
    main()
