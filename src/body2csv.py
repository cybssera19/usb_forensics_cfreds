"""Ubah body file hasil fls -m menjadi CSV timeline yang bisa dibaca.

Pakai:
    python body2csv.py usb02_body.txt usb02_timeline.csv fat
    python body2csv.py pc_body.txt    pc_timeline.csv    ntfs

fat  : FAT32 menyimpan jam lokal komputer pelaku (Eastern) tanpa zona waktu.
       fls dijalankan dengan -z UTC0, jadi angka di body = jam dinding Eastern.
       Pada 24 Maret 2015 berlaku EDT (UTC-4, DST 8 Mar - 1 Nov 2015),
       sehingga ditambah 4 jam untuk mendapat UTC.
ntfs : NTFS sudah menyimpan UTC, tidak digeser.
"""
import csv
import sys
from datetime import datetime, timedelta, timezone

src, out, kind = sys.argv[1], sys.argv[2], sys.argv[3].lower()
shift = timedelta(hours=4) if kind == "fat" else timedelta(0)
edt = timezone(timedelta(hours=-4))

rows = []
with open(src, encoding="utf-8-sig", errors="replace") as stream:
    for line in stream:
        f = line.rstrip("\r\n").split("|")
        if len(f) < 11:
            continue
        name = "|".join(f[1:-9])
        inode, size = f[-9], f[-5]
        atime, mtime, ctime, crtime = f[-4], f[-3], f[-2], f[-1]
        for label, value in (("M", mtime), ("A", atime), ("C", ctime), ("B", crtime)):
            try:
                t = int(value)
            except ValueError:
                continue
            if t <= 0:
                continue
            utc = datetime.fromtimestamp(t, timezone.utc) + shift
            rows.append((utc, label, name, size, inode))

rows.sort(key=lambda r: (r[0], r[2], r[1]))
with open(out, "w", newline="", encoding="utf-8-sig") as stream:
    writer = csv.writer(stream)
    writer.writerow(["utc", "eastern_edt", "jenis", "path", "size", "inode"])
    for utc, label, name, size, inode in rows:
        writer.writerow([utc.strftime("%Y-%m-%d %H:%M:%S"),
                         utc.astimezone(edt).strftime("%Y-%m-%d %H:%M:%S"),
                         label, name, size, inode])
print(len(rows), "baris ->", out)
