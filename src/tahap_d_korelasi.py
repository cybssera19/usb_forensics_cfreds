"""TAHAP D (README dosen bagian 7): korelasi artefak dan interval waktu bersyarat.

Untuk setiap file di media USB, mesin ini menilai empat hal secara terpisah
dan memberi status "belum diketahui" bila bukti tidak cukup:

1. Identitas sisi PC  : record $UsnJrnl yang memberi file PC nama yang sama
                        SEBELUM file lahir di USB, dan belum dihapus saat itu.
2. Perangkat          : nomor seri dari dokumentasi akuisisi (device_map) dicek
                        terhadap catatan koneksi PC (setupapi) dan tautan Jump
                        List/LNK yang timestamp target-nya sama dengan file di image.
3. Arah               : PC -> USB hanya jika (a) file di USB adalah salinan
                        (waktu diubah lebih tua dari waktu dibuat, FAT) DAN
                        (b) file bernama sama sudah ada di PC sebelum itu.
4. Waktu              : interval [batas bawah, batas atas]. Batas atas = waktu
                        file dibuat di USB (+2 detik ketelitian). Batas bawah =
                        yang paling akhir dari: perangkat terhubung, file PC
                        terakhir diganti nama/dibuat. Tanpa batas -> unknown.

Mesin TIDAK membaca label. Semua kesimpulan menyimpan record pendukungnya.

Pakai:
    python tahap_d_korelasi.py
"""
import argparse
import json
from collections import defaultdict
from datetime import timedelta
from pathlib import Path, PureWindowsPath

from usb_forensics import read_records, utc, validate, write_json

FAT_TOL = timedelta(seconds=2)  # ketelitian waktu FAT


def ev(row):
    return {"id": row["id"], "source": row["source"], "locator": row["locator"],
            "time": row["time"], "meaning": row["time_semantic"]}


def correlate(records, device_map, pc_id="PC"):
    records = validate(records)
    files = [r for r in records if r["kind"] == "file" and r["media_id"] != pc_id]
    refs = defaultdict(list)
    for r in records:
        if r["kind"] == "file_reference":
            refs[r["file_id"]].append(r)

    usn_by_seg = {k: sorted(v, key=lambda r: utc(r["time"]))
                  for k, v in refs.items() if k.startswith("pc-mft:")}
    connect = defaultdict(list)
    for k, v in refs.items():
        if k.startswith("device:"):
            connect[k[len("device:"):]] += [r for r in v if r["group"] == "setupapi"]
    links = [r for k, v in refs.items() if k.startswith("path:") for r in v
             if r["time_semantic"] == "target_created_as_recorded_in_link"]

    # waktu FAT per file USB, untuk tautan Jump List/LNK ke image
    fat = {}
    for f in files:
        b = [r for r in refs[f["id"]] if r["time_semantic"] == "fat_created"]
        m = [r for r in refs[f["id"]] if r["time_semantic"] == "fat_modified"]
        fat[f["id"]] = (b[0] if b else None, m[0] if m else None)

    def image_links(media):
        """Tautan PC -> image: target link dengan nama, waktu dibuat, dan waktu diubah sama."""
        out = []
        for link in links:
            for f in files:
                if f["media_id"] != media:
                    continue
                b, m = fat[f["id"]]
                if not b or PureWindowsPath(f["export_path"]).name.lower() != link["name"].lower():
                    continue
                same_b = abs(utc(link["time"]) - utc(b["time"])) <= FAT_TOL
                same_m = (m is not None and link.get("target_modified") is not None
                          and abs(utc(link["target_modified"]) - utc(m["time"])) <= FAT_TOL)
                if same_b and same_m:
                    out.append({"link": ev(link), "path": link["path"], "usb_file": f["export_path"],
                                "fat_created": ev(b), "fat_modified": ev(m)})
        return out

    link_cache = {}
    results = []
    for f in files:
        name = PureWindowsPath(f["export_path"]).name.lower()
        b, m = fat[f["id"]]
        born = utc(b["time"]) if b else None
        res = {"usb_file_id": f["id"], "usb_path": f["export_path"], "media_id": f["media_id"]}

        # salinan atau bukan (pola waktu FAT)
        if b and m:
            copy_pattern = utc(m["time"]) < born - FAT_TOL
            res["copy_pattern"] = "modified_before_created" if copy_pattern else "created_on_media"
        else:
            copy_pattern = None
            res["copy_pattern"] = "unknown"
        res["copy_pattern_evidence"] = [ev(x) for x in (b, m) if x]

        # 1. identitas sisi PC
        candidates = []
        if born is not None:
            for seg, rows in usn_by_seg.items():
                named = [r for r in rows if r["name"].lower() == name
                         and ("RENAME_NEW_NAME" in r["reason"] or "FILE_CREATE" in r["reason"])
                         and utc(r["time"]) <= born]
                if not named:
                    continue
                deleted_before = [r for r in rows if "FILE_DELETE" in r["reason"]
                                  and utc(r["time"]) < born]
                if deleted_before:
                    continue
                names_seen = []
                for r in rows:
                    if r["name"] not in names_seen:
                        names_seen.append(r["name"])
                last_named = max(utc(r["time"]) for r in named)
                deleted_after = [r for r in rows if "FILE_DELETE" in r["reason"]]
                candidates.append({
                    "pc_entity": seg, "earliest_name_seen": names_seen[0],
                    "names_seen": names_seen, "name_acquired_utc": last_named.isoformat(),
                    "created_on_pc_utc": next((r["time"] for r in rows
                                               if "FILE_CREATE" in r["reason"]), None),
                    "deleted_on_pc_utc": deleted_after[-1]["time"] if deleted_after else None,
                    "evidence": [ev(r) for r in named] + [ev(r) for r in deleted_after[-1:]],
                })
        if candidates:
            res["pc_identity_status"] = "pc_record_with_same_name_before_usb_creation"
        elif born is None:
            res["pc_identity_status"] = "unknown_no_usb_time"
        else:
            res["pc_identity_status"] = "no_pc_record_found"
        res["pc_candidates"] = candidates

        # 2. perangkat
        serial = (device_map.get(f["media_id"]) or {}).get("serial")
        res["device_serial_from_acquisition"] = serial
        conn = sorted(connect.get(serial, []), key=lambda r: utc(r["time"])) if serial else []
        conn_before = [r for r in conn if born is not None and utc(r["time"]) <= born]
        if f["media_id"] not in link_cache:
            link_cache[f["media_id"]] = image_links(f["media_id"])
        linked = link_cache[f["media_id"]]
        if not serial:
            res["device_status"] = "device_unresolved_no_acquisition_mapping"
        elif conn_before and linked:
            res["device_status"] = "connected_before_creation_and_image_linked"
        elif conn_before:
            res["device_status"] = "connected_before_creation"
        elif conn and born is None:
            res["device_status"] = "connected_but_usb_time_unknown"
        elif linked:
            res["device_status"] = "image_linked_no_connection_record"
        else:
            res["device_status"] = "device_unresolved"
        res["device_evidence"] = {"connection": [ev(r) for r in conn_before], "image_links": linked}

        # 3. arah
        if copy_pattern is False:
            res["direction"] = "not_a_copy_created_on_media"
        elif copy_pattern and candidates:
            res["direction"] = "pc_to_usb"
        else:
            res["direction"] = "direction_unknown"

        # 4. waktu
        if res["direction"] == "pc_to_usb":
            lows = []
            if conn_before:
                lows.append(("device_connected", utc(conn_before[-1]["time"])))
            lows.append(("pc_name_acquired",
                         max(utc(c["name_acquired_utc"]) for c in candidates)))
            basis, low = max(lows, key=lambda x: x[1])
            res["time_status"] = "bounded"
            res["time_interval_utc"] = [low.isoformat(), (born + FAT_TOL).isoformat()]
            res["time_lower_basis"] = basis
            res["time_width_seconds"] = (born + FAT_TOL - low).total_seconds()
        else:
            res["time_status"] = "time_unknown"
            res["time_interval_utc"] = None
        results.append(res)

    # urutan kejadian (dari bukti yang tersisa saja)
    leaked = [r for r in results if r["direction"] == "pc_to_usb"]
    segs = {r["pc_candidates"][0]["pc_entity"] for r in leaked if len(r["pc_candidates"]) == 1}
    rows = [x for s in segs for x in usn_by_seg[s]]
    def first(pred):
        t = [utc(x["time"]) for x in rows if pred(x)]
        return min(t).isoformat() if t else None
    def last(pred):
        t = [utc(x["time"]) for x in rows if pred(x)]
        return max(t).isoformat() if t else None
    serials = {r["device_serial_from_acquisition"] for r in leaked}
    conn_t = [utc(x["time"]) for s in serials for x in connect.get(s, [])]
    events = {
        "pc_ingest": first(lambda x: "FILE_CREATE" in x["reason"]),
        "pc_rename": first(lambda x: "RENAME_NEW_NAME" in x["reason"]),
        "device_connect": min(conn_t).isoformat() if conn_t else None,
        "usb_copy": min(utc(r["time_interval_utc"][1]) - FAT_TOL for r in leaked).isoformat() if leaked else None,
        "pc_delete": last(lambda x: "FILE_DELETE" in x["reason"]),
    }
    mapping = []
    for media, info in device_map.items():
        serial = info.get("serial")
        conn = sorted(connect.get(serial, []), key=lambda r: utc(r["time"]))
        linked = link_cache.get(media) or image_links(media)
        mapping.append({
            "image_id": media, "image": info.get("image"),
            "serial_from_acquisition": serial, "acquisition_status": info.get("status"),
            "pc_connection_records": [ev(r) for r in conn],
            "drive_letters_seen_in_links": sorted({l["path"][:2].upper() for l in linked}),
            "image_links": linked,
        })
    return {"method": "artifact_correlation_v1", "device_mapping": mapping,
            "files": results, "event_times_utc": events}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inputs", nargs="+", default=[r"D:\RM\data\normalized\usb02_complete.json",
                                                   r"D:\RM\data\normalized\events.json"])
    p.add_argument("--device-map", default=r"D:\RM\data\normalized\device_map.json")
    p.add_argument("--device-inventory", default=r"D:\RM\data\normalized\device_inventory.json")
    p.add_argument("--out", default=r"D:\RM\data\results\correlated.json")
    a = p.parse_args()
    device_map = json.loads(Path(a.device_map).read_text(encoding="utf-8"))
    report = correlate(read_records(a.inputs), device_map)
    inv = Path(a.device_inventory)
    if inv.is_file():
        registry = json.loads(inv.read_text(encoding="utf-8")).get("registry_usbstor", [])
        for row in report["device_mapping"]:
            row["registry_usbstor"] = [d for d in registry
                                       if d["serial"] == row["serial_from_acquisition"]]
    write_json(a.out, report)
    count = defaultdict(int)
    for r in report["files"]:
        count[r["direction"]] += 1
    print("File USB dinilai :", len(report["files"]))
    for k, v in sorted(count.items()):
        print(f"  {k:32s}: {v}")
    for row in report["device_mapping"]:
        print("Pemetaan perangkat:", row["image_id"], "->", row["serial_from_acquisition"],
              "| koneksi PC:", [c["time"] for c in row["pc_connection_records"]],
              "| huruf drive di tautan:", row["drive_letters_seen_in_links"])
    print("Urutan kejadian  :", report["event_times_utc"])
    print("Output           :", a.out)


if __name__ == "__main__":
    main()
