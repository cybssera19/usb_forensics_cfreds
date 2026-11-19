#!/usr/bin/env python3
"""Eksperimen kehilangan bukti untuk percobaan 2 (analyze_cfreds.py).

Logika skrip asli TIDAK diubah. Pembungkus ini hanya:
  1. Memuat semua record mentah (usn, shellbags, jumplist, lnk) sekali.
  2. Menghapus sebagian record (per kelompok artefak, atau acak p% dengan seed tercatat).
  3. Menjalankan langkah 1-3 analyze_cfreds.main() pada record yang tersisa
     (patch kecil: main() mengembalikan kandidat, bukan mencetak laporan).
  4. Menilai tiap operasi NIST persis seperti langkah 5 skrip asli
     (kandidat terdekat dalam +-15 menit), lalu mengelompokkan hasil:
       correct      kanal dan arah sesuai kunci jawaban
       inconclusive kandidat ada tetapi berlabel Inconclusive
       missed       tidak ada kandidat dalam +-15 menit
       wrong        label yakin tetapi kanal/arah salah
       borrowed     kandidat yang terpakai milik operasi lain (kandidat sendiri hilang)
Satuan kehilangan = satu record artefak mentah (satu baris JSONL), sama seperti
'root' di percobaan 1.

Pakai: python masking_path_b.py <folder_jsonl> <analyze_cfreds.py> <truth.json> <out_dir> [jumlah_seed=30]
"""
import csv, io, json, random, statistics, sys, types
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

data_dir, script, truth_path, out_dir = map(Path, sys.argv[1:5])
SEEDS = int(sys.argv[5]) if len(sys.argv) > 5 else 30  # jumlah seed per tingkat (default 30, sama dengan percobaan 1)
out_dir.mkdir(parents=True, exist_ok=True)

# ---- muat skrip asli dengan dua patch kecil ----------------------------------
src = script.read_text(encoding='utf-8')
p1_old = "    a = ap.parse_args(); d = Path(a.dir)"
p1_new = "    a = ap.parse_args(ARGV); d = Path(a.dir)"
p2_old = "    # ---------- 4. laporan ----------"
p2_new = "    return cands, {e[3] for e in ev}\n    # ---------- 4. laporan ----------"
p3_old = "def main():"
p3_new = "def main(ARGV=None):"
for o, n in ((p1_old, p1_new), (p2_old, p2_new), (p3_old, p3_new)):
    assert src.count(o) == 1, o
    src = src.replace(o, n)
mod = types.ModuleType('acf')
exec(compile(src, str(script), 'exec'), mod.__dict__)
orig_load = mod.load

FILES = {'usn': 'usn_filtered.jsonl', 'shellbag': 'shellbags.jsonl',
         'jumplist': 'jumplist.jsonl', 'lnk': 'lnk.jsonl'}
raw = {g: orig_load(data_dir / f) for g, f in FILES.items()}
roots = [(g, i) for g, rs in raw.items() for i in range(len(rs))]
N = len(roots)

truth = json.loads(truth_path.read_text(encoding='utf-8'))
EXPECT = {'usb_to_pc': 'USB->PC', 'pc_to_usb': 'PC->USB',
          'network_to_pc': 'network', 'pc_to_cd': 'CD'}


def category(label):
    if label.startswith('Inconclusive'):
        return 'inconclusive'
    for k in ('USB->PC', 'PC->USB'):
        if k in label:
            return k
    if 'network' in label:
        return 'network'
    if 'CD' in label:
        return 'CD'
    return label


def run(keep):
    """keep: set of (group, index) yang tetap ada."""
    cache = {FILES[g]: [r for i, r in enumerate(raw[g]) if (g, i) in keep] for g in FILES}
    mod.load = lambda path: cache[Path(path).name]
    with redirect_stdout(io.StringIO()):
        res = mod.main(['--dir', str(data_dir), '--truth', str(truth_path)])
    mod.load = orig_load
    cands, names = res if res else ([], set())
    # langkah 5 skrip asli: kandidat terdekat dalam 900 s
    match = {}
    for op in truth['operations']:
        t = datetime.strptime(op['local'][:16], '%Y-%m-%d %H:%M').replace(tzinfo=timezone.utc) + timedelta(hours=4)
        best = min(cands, key=lambda c: abs((c['t0'] - t).total_seconds()), default=None)
        match[op['id']] = best if best and abs((best['t0'] - t).total_seconds()) <= 900 else None
    # pemilik kandidat = operasi (di antara yang memakainya) yang waktunya paling dekat
    t_of = {op['id']: datetime.strptime(op['local'][:16], '%Y-%m-%d %H:%M').replace(tzinfo=timezone.utc)
            + timedelta(hours=4) for op in truth['operations']}
    out = {}
    for op in truth['operations']:
        c = match[op['id']]
        exp = EXPECT[op['direction']]
        if c is None:
            out[op['id']] = 'missed'; continue
        users = [o for o in t_of if match[o] is c]
        owner = min(users, key=lambda o: abs((c['t0'] - t_of[o]).total_seconds()))
        cat = category(c['label'])
        if cat == exp:
            out[op['id']] = 'correct'
        elif owner != op['id']:
            out[op['id']] = 'borrowed'   # kandidat sendiri hilang; yang terpakai milik operasi lain
        elif cat == 'inconclusive':
            out[op['id']] = 'inconclusive'
        else:
            out[op['id']] = 'wrong'
        if op['id'] == 'op1' and out['op1'] == 'correct':
            out['op1_strength'] = 'strong' if 'Strongly' in c['label'] else 'suspected'
    files = truth['operations'][4].get('files') or []
    out['op4_names'] = sum(f in names for f in files)
    return out


OPS = [op['id'] for op in truth['operations']]
OUTCOMES = ['correct', 'inconclusive', 'missed', 'wrong', 'borrowed']
rows = []
everything = set(roots)
rows.append({'scenario': 'reference', 'seed': 0, 'removed': 0, **run(everything)})
for g in FILES:
    keep = {r for r in roots if r[0] != g}
    rows.append({'scenario': 'without_' + g, 'seed': 0, 'removed': N - len(keep), **run(keep)})
for p in (0.1, 0.3, 0.5, 0.7):
    for s in range(1, SEEDS + 1):
        k = int(N * p)
        drop = set(random.Random(s).sample(roots, k))
        rows.append({'scenario': f'random_{round(p*100)}', 'seed': s, 'removed': k,
                     **run(everything - drop)})

with open(out_dir / 'path_b_experiments.csv', 'w', newline='', encoding='utf-8-sig') as f:
    cols = ['scenario', 'seed', 'removed'] + OPS + ['op1_strength', 'op4_names']
    w = csv.DictWriter(f, fieldnames=cols, extrasaction='ignore')
    w.writeheader(); w.writerows(rows)

summary = {'roots_total': N, 'roots_per_group': {g: len(r) for g, r in raw.items()}, 'scenarios': {}}
for sc in dict.fromkeys(r['scenario'] for r in rows):
    rs = [r for r in rows if r['scenario'] == sc]
    agg = {o: statistics.mean(sum(r[op] == o for op in OPS) for r in rs) for o in OUTCOMES}
    agg['runs'] = len(rs)
    agg['runs_with_any_wrong'] = sum(any(r[op] == 'wrong' for op in OPS) for r in rs)
    agg['per_op_correct_rate'] = {op: sum(r[op] == 'correct' for r in rs) / len(rs) for op in OPS}
    agg['per_op_wrong_rate'] = {op: sum(r[op] == 'wrong' for r in rs) / len(rs) for op in OPS}
    agg['op4_names_mean'] = statistics.mean(r['op4_names'] for r in rs)
    summary['scenarios'][sc] = agg
(out_dir / 'path_b_summary.json').write_text(json.dumps(summary, indent=1), encoding='utf-8')

print(f'Record mentah: {N}  ', summary['roots_per_group'])
print(f"{'skenario':16s} {'benar':>6s} {'inconcl':>8s} {'hilang':>7s} {'salah':>6s} {'pinjam':>7s} {'run salah':>10s}")
for sc, a in summary['scenarios'].items():
    print(f"{sc:16s} {a['correct']:6.2f} {a['inconclusive']:8.2f} {a['missed']:7.2f} {a['wrong']:6.2f} "
          f"{a['borrowed']:7.2f} {a['runs_with_any_wrong']:>4d}/{a['runs']}")
print('\nPer operasi (tingkat benar | tingkat salah):')
for sc, a in summary['scenarios'].items():
    print(f"{sc:16s} " + '  '.join(f"{op}:{a['per_op_correct_rate'][op]:.2f}|{a['per_op_wrong_rate'][op]:.2f}" for op in OPS))
