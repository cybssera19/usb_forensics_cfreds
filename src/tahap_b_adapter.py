"""TAHAP B (README dosen bagian 6-7): adapter normalisasi artefak.

Mengubah artefak mentah menjadi record JSON berskema kode dosen
(kind = "file_reference"), supaya bisa dibaca analyze/mask_records.
Adapter TIDAK menyimpulkan apa pun: setiap timestamp disimpan dengan
arti aslinya (time_semantic). Kesimpulan dibuat di tahap D.

Sumber dan kelompok bukti (field "group" = unit yang dihilangkan di eksperimen):
  fs_usb    metadata FAT RM#2 dari body file fls (-z UTC0)
  usnjrnl   $UsnJrnl PC dari Dissect (hanya file yang namanya ada di RM#2)
  jumplist  Jump List PC dari Dissect (hanya target yang namanya ada di RM#2)
  lnk       LNK PC dari Dissect (hanya target yang namanya ada di RM#2)
  setupapi  setupapi.dev.log PC: pemasangan pertama perangkat USBSTOR

Registry USB dari Dissect tidak punya timestamp pada image ini, jadi hanya
dicatat ke device_inventory.json, bukan sebagai record bukti.

Pakai (dari folder kode dosen, Python 3.14 biasa, tidak perlu venv):
    python tahap_b_adapter.py
"""
import argparse
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath

from usb_forensics import sha256_file, validate, write_json

GENERIC_NAMES = {"desktop.ini", "thumbs.db"}  # file sistem umum, tidak ditelusuri di PC
ART = r"D:\RM\data\artifacts\pc-run2"


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat()


def valid_time(value):
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None or dt.year < 1990:
        return None
    return dt


def dissect_rows(path):
    with open(path, encoding="utf-8-sig", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            line = line.strip()
            if not line.startswith("{"):
                continue
            row = json.loads(line)
            if row.get("_type") == "recorddescriptor":
                continue
            yield number, row


def basename(path):
    return PureWindowsPath(path).name.lower() if path else ""


# ---------------------------------------------------------------- FAT RM#2
def adapt_fat(body_path, usb_by_path, offset_hours):
    """fls -m -z UTC0: angka = jam dinding lokal. UTC = angka - offset."""
    shift = timedelta(hours=-offset_hours)
    rows = []
    with open(body_path, encoding="utf-8-sig", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            f = line.rstrip("\r\n").split("|")
            if len(f) < 11:
                continue
            name, inode, mode = "|".join(f[1:-9]), f[-9], f[-8]
            if mode.startswith(("d/", "V/")):
                continue
            rel = name.split("/", 1)[1] if "/" in name else name
            rel = rel.removesuffix(" (deleted)")
            usb = usb_by_path.get(rel)
            if not usb:
                continue
            root = "fat:" + usb["media_id"] + ":" + inode
            for label, value, meaning in (("B", f[-1], "fat_created"),
                                          ("M", f[-3], "fat_modified")):
                if not value.isdigit() or int(value) <= 0:
                    continue
                t = datetime.fromtimestamp(int(value), timezone.utc) + shift
                rows.append({
                    "id": root + ":" + label, "root_id": root, "depends_on": [],
                    "kind": "file_reference", "group": "fs_usb",
                    "file_id": usb["id"], "time": iso(t), "time_semantic": meaning,
                    "source": "fls body " + Path(body_path).name,
                    "locator": "line " + str(number) + ", inode " + inode,
                    "artifact": "fat_metadata", "name": PureWindowsPath(rel).name,
                    "time_precision": "FAT: dibuat 10 ms, diubah 2 detik; zona dikonversi dari UTC"
                                      + format(offset_hours, "+d"),
                })
    return rows


# ---------------------------------------------------------------- $UsnJrnl
def adapt_usn(path, names):
    segments = set()
    for _, row in dissect_rows(path):
        if basename(row.get("path")) in names:
            segments.add(row.get("segment_id"))
    rows = []
    for number, row in dissect_rows(path):
        seg = row.get("segment_id")
        if seg not in segments:
            continue
        t = valid_time(row.get("ts"))
        if not t:
            continue
        rid = "usn:" + str(row["usn"])
        rows.append({
            "id": rid, "root_id": rid, "depends_on": [],
            "kind": "file_reference", "group": "usnjrnl",
            "file_id": "pc-mft:" + seg, "time": iso(t),
            "time_semantic": "usn:" + row.get("reason", ""),
            "source": Path(path).name + " (Dissect usnjrnl, $UsnJrnl:$J PC)",
            "locator": "line " + str(number) + ", usn " + str(row["usn"]),
            "artifact": "usnjrnl", "name": PureWindowsPath(row.get("path") or "").name,
            "reason": row.get("reason", ""), "path": row.get("path"),
        })
    return rows


# ---------------------------------------------------------------- LNK / Jump List
def lnk_target(row):
    if row.get("local_base_path"):
        return row["local_base_path"]
    parts = [p for p in (row.get("lnk_net_name"), row.get("common_path_suffix")) if p]
    return "\\".join(parts) if parts else ""


def adapt_links(path, names, group):
    rows = []
    for number, row in dissect_rows(path):
        target = lnk_target(row)
        if basename(target) not in names:
            continue
        root = group + ":line" + str(number)
        common = {"depends_on": [], "kind": "file_reference", "group": group,
                  "file_id": "path:" + target,
                  "source": Path(path).name + " (Dissect " + group + ")",
                  "locator": "line " + str(number) + ", " + str(row.get("lnk_path")),
                  "artifact": group, "name": PureWindowsPath(target).name,
                  "path": target, "drive": PureWindowsPath(target).drive.upper()}
        created = valid_time(row.get("target_ctime"))
        modified = valid_time(row.get("target_mtime"))
        if created:
            rows.append(dict(common, id=root + ":target_created", root_id=root,
                             time=iso(created),
                             time_semantic="target_created_as_recorded_in_link",
                             target_modified=iso(modified) if modified else None))
        if group == "lnk":
            made = valid_time(row.get("lnk_ctime"))
            if made:
                rows.append(dict(common, id=root + ":lnk_created", root_id=root,
                                 time=iso(made),
                                 time_semantic="lnk_file_created_first_open_of_this_name"))
    return rows


# ---------------------------------------------------------------- setupapi
DEVICE = re.compile(r">>>\s+\[Device Install \(Hardware initiated\) - (USBSTOR\\[^\]]+)\]")
START = re.compile(r">>>\s+Section start (\d{4})/(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d)\.(\d+)")


def adapt_setupapi(path, offset_hours):
    lines = Path(path).read_text(encoding="latin-1").splitlines()
    tz = timezone(timedelta(hours=offset_hours))
    rows = []
    for i, line in enumerate(lines):
        m = DEVICE.search(line)
        if not m or i + 1 >= len(lines):
            continue
        s = START.search(lines[i + 1])
        if not s:
            continue
        y, mo, d, h, mi, se, frac = s.groups()
        t = datetime(int(y), int(mo), int(d), int(h), int(mi), int(se),
                     int(frac[:3]) * 1000, tzinfo=tz)
        parts = m.group(1).split("\\")
        serial = parts[-1].split("&")[0]
        desc = dict(p.split("_", 1) for p in parts[1].split("&") if "_" in p)
        rid = "setupapi:line" + str(i + 1)
        rows.append({
            "id": rid, "root_id": rid, "depends_on": [],
            "kind": "file_reference", "group": "setupapi",
            "file_id": "device:" + serial, "time": iso(t),
            "time_semantic": "device_first_install (hanya pemasangan pertama)",
            "source": "Windows/inf/setupapi.dev.log (PC)",
            "locator": "line " + str(i + 1),
            "artifact": "setupapi", "serial": serial,
            "vendor": desc.get("Ven"), "product": desc.get("Prod"),
            "local_time": "%s-%s-%s %s:%s:%s" % (y, mo, d, h, mi, se),
        })
    return rows


def registry_devices(path):
    devices = {}
    for number, row in dissect_rows(path):
        serial = (row.get("serial") or "").split("&")[0]
        if serial:
            devices.setdefault(serial, {"serial": serial, "vendor": row.get("vendor"),
                                        "product": row.get("product"),
                                        "first_insert": row.get("first_insert"),
                                        "last_insert": row.get("last_insert"),
                                        "last_removal": row.get("last_removal"),
                                        "source": row.get("source"),
                                        "locator": "line " + str(number)})
    return list(devices.values())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--usb-inventory", default=r"D:\RM\data\normalized\usb02_complete.json")
    p.add_argument("--fat-body", default=r"D:\RM\data\metadata\usb02_body.txt")
    p.add_argument("--fat-utc-offset", type=int, default=-4,
                   help="Offset jam lokal pelaku (EDT = -4, berlaku 8 Mar - 1 Nov 2015)")
    p.add_argument("--usn", default=ART + r"\artifact-3.jsonl")
    p.add_argument("--jumplist", default=ART + r"\artifact-1.jsonl")
    p.add_argument("--lnk", default=ART + r"\artifact-2.jsonl")
    p.add_argument("--usb-registry", default=ART + r"\artifact-0.jsonl")
    p.add_argument("--setupapi", default=r"D:\RM\data\exports\pc\Windows\inf\setupapi.dev.log")
    p.add_argument("--setupapi-utc-offset", type=int, default=-4)
    p.add_argument("--out-dir", default=r"D:\RM\data\normalized")
    a = p.parse_args()

    usb = [r for r in json.loads(Path(a.usb_inventory).read_text(encoding="utf-8"))
           if r["kind"] == "file"]
    usb_by_path = {r["export_path"]: r for r in usb}
    names = {PureWindowsPath(r["export_path"]).name.lower() for r in usb} - GENERIC_NAMES

    groups = {
        "fs_usb": adapt_fat(a.fat_body, usb_by_path, a.fat_utc_offset),
        "usnjrnl": adapt_usn(a.usn, names),
        "jumplist": adapt_links(a.jumplist, names, "jumplist"),
        "lnk": adapt_links(a.lnk, names, "lnk"),
        "setupapi": adapt_setupapi(a.setupapi, a.setupapi_utc_offset),
    }
    events = validate([r for rows in groups.values() for r in rows])
    out = Path(a.out_dir)
    write_json(out / "events.json", events)
    write_json(out / "device_inventory.json", {
        "registry_usbstor": registry_devices(a.usb_registry),
        "setupapi_first_install": [{k: r[k] for k in ("serial", "vendor", "product",
                                                      "local_time", "time", "locator")}
                                   for r in groups["setupapi"]],
        "note": "Waktu Registry kosong (plugin Dissect tidak dapat membaca properti pada image ini).",
    })
    inputs = [a.usb_inventory, a.fat_body, a.usn, a.jumplist, a.lnk, a.usb_registry, a.setupapi]
    write_json(out / "events_report.json", {
        "records_per_group": {g: len(r) for g, r in groups.items()},
        "evidence_roots_per_group": {g: len({x["root_id"] for x in r}) for g, r in groups.items()},
        "usb_names_traced": sorted(names), "generic_names_not_traced": sorted(GENERIC_NAMES),
        "inputs_sha256": {x: sha256_file(x) for x in inputs},
    })
    for g, r in groups.items():
        print(f"{g:9s}: {len(r):6d} record, {len({x['root_id'] for x in r}):6d} root")
    print("Output   :", out / "events.json")


if __name__ == "__main__":
    main()
