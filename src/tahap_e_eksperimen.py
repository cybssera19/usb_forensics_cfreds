"""TAHAP E (README dosen bagian 8 dan 9): eksperimen kehilangan bukti dan evaluasi.

1. Baseline (pada label yang sama):
   - nama file : file USB dianggap bocor dari PC jika namanya ada di ekspor PC
   - hash      : file USB dianggap bocor jika analyze() kode dosen menemukan pasangan
   - gabungan  : mesin korelasi tahap D
2. Ablation: satu kelompok bukti dihapus seluruhnya, lalu 10/30/50/70% root
   bukti dihapus acak dengan 30 seed tercatat. Memakai mask_records kode dosen.
   Setiap percobaan menghitung ulang SEMUA kesimpulan dari bukti yang tersisa.
3. Metrik per pertanyaan (label tahap C, dibaca hanya di sini):
   identitas (precision/recall file bocor), perangkat, arah, waktu, urutan.
   Precision tanpa prediksi = null. Penyebut recall tetap 17 target.

Pakai:
    python tahap_e_eksperimen.py
"""
import argparse
import csv
import json
import statistics
from itertools import combinations
from pathlib import Path, PureWindowsPath

from usb_forensics import analyze, mask_records, read_records, utc, write_json
from tahap_d_korelasi import correlate

GROUPS = ["content", "fs_usb", "usnjrnl", "jumplist", "lnk", "setupapi"]
FRACTIONS = [0.1, 0.3, 0.5, 0.7]


def ratio(a, b):
    return a / b if b else None


def evaluate(report, labels):
    targets, negatives = set(labels["targets"]), set(labels["negatives"])
    by_id = {r["usb_file_id"]: r for r in report["files"]}
    leaked = {k for k, r in by_id.items() if r["direction"] == "pc_to_usb"}
    tp, fp = len(leaked & targets), len(leaked & negatives)
    fn = len(targets - leaked)
    m = {"tp": tp, "fp": fp, "fn": fn, "precision": ratio(tp, tp + fp), "recall": tp / len(targets)}

    dev_ok = dev_wrong = dir_ok = dir_wrong = t_ok = t_bad = 0
    widths = []
    lo, hi = (utc(x) for x in labels["copy_window_utc"])
    for t in targets:
        r = by_id.get(t)
        if not r:
            continue
        if r["device_status"].startswith("connected_before_creation"):
            if r["device_serial_from_acquisition"] == labels["device_serial"]:
                dev_ok += 1
            else:
                dev_wrong += 1
        if r["direction"] == "pc_to_usb":
            dir_ok += 1
        elif r["direction"] == "not_a_copy_created_on_media":
            dir_wrong += 1
        if r["time_status"] == "bounded":
            a, b = (utc(x) for x in r["time_interval_utc"])
            widths.append(r["time_width_seconds"])
            if a <= hi and b >= lo:
                t_ok += 1
            else:
                t_bad += 1
    n = len(targets)
    m.update({
        "device_correct": dev_ok, "device_wrong": dev_wrong, "device_unknown": n - dev_ok - dev_wrong,
        "device_accuracy": dev_ok / n,
        "direction_correct": dir_ok, "direction_wrong": dir_wrong,
        "direction_unknown": n - dir_ok - dir_wrong, "direction_accuracy": dir_ok / n,
        "time_consistent": t_ok, "time_inconsistent": t_bad, "time_unknown": n - t_ok - t_bad,
        "time_coverage": (t_ok + t_bad) / n,
        "time_width_median_s": statistics.median(widths) if widths else None,
    })
    ev = report["event_times_utc"]
    order = labels["event_order"]
    good = bad = unk = 0
    for x, y in combinations(order, 2):  # label: x sebelum y
        if ev.get(x) is None or ev.get(y) is None:
            unk += 1
        elif utc(ev[x]) < utc(ev[y]):
            good += 1
        else:
            bad += 1
    m.update({"order_correct_pairs": good, "order_wrong_pairs": bad, "order_unknown_pairs": unk,
              "order_accuracy": good / (good + bad + unk)})
    return m


def baseline_metrics(predicted, labels):
    targets, negatives = set(labels["targets"]), set(labels["negatives"])
    tp, fp = len(predicted & targets), len(predicted & negatives)
    return {"predicted": len(predicted), "tp": tp, "fp": fp, "fn": len(targets - predicted),
            "precision": ratio(tp, tp + fp), "recall": tp / len(targets)}


def summarize(rows):
    keys = [k for k in rows[0] if isinstance(rows[0][k], (int, float)) and k != "seed"]
    out = {"runs": len(rows)}
    for k in keys:
        vals = [r[k] for r in rows if r[k] is not None]
        out[k] = {"mean": statistics.mean(vals), "min": min(vals), "max": max(vals),
                  "n_null": len(rows) - len(vals)} if vals else None
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--usb", default=r"D:\RM\data\normalized\usb02_complete.json")
    p.add_argument("--events", default=r"D:\RM\data\normalized\events.json")
    p.add_argument("--pc", default=r"D:\RM\data\normalized\pc.json")
    p.add_argument("--pc-export", default=r"D:\RM\data\exports\pc")
    p.add_argument("--device-map", default=r"D:\RM\data\normalized\device_map.json")
    p.add_argument("--labels", default=r"D:\RM\data\labels\case_labels.json")
    p.add_argument("--seeds", type=int, default=30)
    p.add_argument("--out-dir", default=r"D:\RM\data\results\eksperimen")
    a = p.parse_args()

    out = Path(a.out_dir)
    if out.exists() and any(out.iterdir()):
        raise SystemExit("Folder output sudah berisi file. Pakai --out-dir baru.")
    labels = json.loads(Path(a.labels).read_text(encoding="utf-8"))
    device_map = json.loads(Path(a.device_map).read_text(encoding="utf-8"))
    usb = read_records([a.usb])
    records = read_records([a.usb, a.events])

    # baseline
    pc_names = {n.lower() for _, _, fs in __import__("os").walk(a.pc_export) for n in fs}
    by_name = {r["id"] for r in usb if r["kind"] == "file"
               and PureWindowsPath(r["export_path"]).name.lower() in pc_names}
    hash_report = analyze(read_records([a.pc]) + usb)
    by_hash = {m["usb_file_id"] for m in hash_report["matches"]}
    full = correlate(records, device_map)
    write_json(out / "correlated_full.json", full)
    baselines = {
        "nama_file": baseline_metrics(by_name, labels),
        "hash_sha256": baseline_metrics(by_hash, labels),
        "gabungan_artefak": baseline_metrics(
            {r["usb_file_id"] for r in full["files"] if r["direction"] == "pc_to_usb"}, labels),
        "catatan": "Unit evaluasi = file di RM#2 (17 target, 24 negatif). "
                   "Baseline nama/hash tidak menilai arah atau waktu.",
    }
    write_json(out / "baselines.json", baselines)

    # ablation
    runs = [("acuan", None, 0.0, 0)]
    runs += [("tanpa_" + g, g, 0.0, 0) for g in GROUPS]
    runs += [("acak_%d%%" % round(f * 100), None, f, s) for f in FRACTIONS
             for s in range(1, a.seeds + 1)]
    rows = []
    roots_total = len({r["root_id"] for r in records})
    for name, group, frac, seed in runs:
        visible, removed = mask_records(records, fraction=frac, seed=seed, drop_group=group)
        report = correlate(visible, device_map)
        row = {"skenario": name, "drop_group": group or "", "fraction": frac, "seed": seed,
               "records_removed": len(removed), "records_total": len(records),
               "roots_total": roots_total}
        row.update(evaluate(report, labels))
        rows.append(row)
    with open(out / "experiments.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    summary = {}
    for name in dict.fromkeys(r["skenario"] for r in rows):
        summary[name] = summarize([r for r in rows if r["skenario"] == name])
    write_json(out / "experiments_summary.json", summary)

    print("Baseline (precision / recall file bocor):")
    for k in ("nama_file", "hash_sha256", "gabungan_artefak"):
        b = baselines[k]
        print(f"  {k:17s} prediksi={b['predicted']:2d} TP={b['tp']:2d} FP={b['fp']:2d} "
              f"precision={b['precision']} recall={b['recall']:.2f}")
    print("\nSkenario            recall  perangkat  arah   waktu_cakupan  urutan")
    for name, s in summary.items():
        g = lambda k: s[k]["mean"] if s.get(k) else float("nan")
        print(f"  {name:17s} {g('recall'):6.2f}  {g('device_accuracy'):8.2f}  "
              f"{g('direction_accuracy'):5.2f}  {g('time_coverage'):12.2f}  {g('order_accuracy'):6.2f}")
    print("\nOutput:", out)


if __name__ == "__main__":
    main()
