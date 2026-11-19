#!/usr/bin/env python3
"""Tahap 2 (CFReDS): gabungkan artefak PC -> kandidat operasi -> bandingkan dengan ground truth NIST.
Masukan (JSON Lines hasil Dissect, boleh terpotong baris): usn_filtered.jsonl, shellbags.jsonl, jumplist.jsonl,
opsional lnk.jsonl. Ground truth hanya dipakai di langkah evaluasi, bukan untuk membuat label.
Stdlib saja. Jalankan:  py analyze_cfreds.py --dir D:\\RM --truth truth_cfreds.json
"""
import argparse, json, re, sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

def P(s):
    return datetime.fromisoformat(s) if s else None

def load(path):
    """Baca JSONL; sambung baris yang terpotong oleh Out-File/Select-String."""
    recs, cur = [], ''
    for l in Path(path).read_text(encoding='utf-8-sig', errors='replace').split('\n'):
        l = l.rstrip('\r')
        if l.startswith('{"'):
            if cur: recs.append(cur)
            cur = l
        else:
            cur += l
    if cur: recs.append(cur)
    out = []
    for r in recs:
        try:
            j = json.loads(r)
            if j.get('_type') == 'record': out.append(j)
        except Exception:
            pass
    return out

def base(p): return re.split(r'[\\/]', str(p))[-1]
def loc(path):
    p = str(path)
    if re.match(r'^(My Computer\\)?[A-Z]:\\?', p) and not re.match(r'^(My Computer\\)?[Cc]:', p):
        if 'CDBURN' in p or p.startswith('My Computer\\D:\\de') or re.search(r'Burn', p): return 'cd'
        if re.match(r'^(My Computer\\)?V:', p): return 'network'
        return 'removable'
    if p.startswith('Network') or p.startswith('\\\\'): return 'network'
    return 'local'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', required=True); ap.add_argument('--truth', required=True)
    ap.add_argument('--gap', type=int, default=180, help='detik antar file dalam satu kelompok salinan')
    ap.add_argument('--drop', default='', help='buang artefak (ablation), mis. usn,shellbag,jumplist,lnk')
    a = ap.parse_args(); d = Path(a.dir)

    # ---------- 1. normalisasi ----------
    ev = []   # (utc, source, kind, name, path, extra)
    usn = load(d / 'usn_filtered.jsonl')
    by_path = defaultdict(list)
    for r in usn: by_path[r['path']].append(r)
    for path, rs in by_path.items():
        rs.sort(key=lambda r: r['ts'])
        low = path.lower()
        reasons = '|'.join(r['reason'] for r in rs)
        t0 = P(rs[0]['ts'])
        if '\\recent\\' in low or low.endswith('.lnk'): continue
        if '\\burn\\burn\\' in low:
            ev.append((t0, 'usn', 'cd_stage', base(path), path, {})); continue
        if 'FILE_CREATE' in reasons and 'DATA_OVERWRITE' in reasons:
            ev.append((t0, 'usn', 'copy_signature', base(path), path, {}))
    for r in load(d / 'shellbags.jsonl'):
        p = str(r['path'])
        if p.startswith('S data'): ev.append((P(r['regf_mtime']), 'shellbag', 'pc_tree', base(p), p, {}))
        elif loc(p) != 'local' or p.startswith('My Computer\\E:'):
            ev.append((P(r['regf_mtime']), 'shellbag', 'dir_' + loc(p), base(p), p, {}))
    for r in load(d / 'jumplist.jsonl'):
        p = r.get('local_base_path') or ''
        if re.match(r'^[D-Z]:\\', p) or r.get('lnk_net_name'):
            suffix = r.get('common_path_suffix') or ''
            full = p or (r['lnk_net_name'] + '\\' + suffix)
            ev.append((None, 'jumplist', 'open_' + loc(p or '\\\\'), base(full), full, {'time_unreliable': True}))
    lnkf = d / 'lnk.jsonl'
    if lnkf.exists():
        for r in load(lnkf):
            p = r.get('local_base_path') or ''
            if p and not p.upper().startswith('C:'):
                ev.append((P(r['lnk_mtime']), 'lnk', 'open_' + loc(p), base(p), p, {}))
    extra = d / 'lnk_paste.json'   # LNK yang ditempel manual (uji)
    if extra.exists():
        for r in json.loads(extra.read_text()):
            ev.append((P(r['t']), 'lnk', 'open_' + loc(r['p']), base(r['p']), r['p'], {}))

    # Huruf drive yang terbukti CD (ShellBag <CDBURN> / folder burn) -> semua jejak di huruf itu = CD, bukan USB.
    cd_letters = {m.group(1) for e in ev if e[2] == 'dir_cd'
                  for m in [re.match(r'^(?:My Computer\\)?([A-Z]):', str(e[4]))] if m}
    ev = [(t, s_, k.replace('_removable', '_cd') if k.endswith('_removable') and
           (re.match(r'^(?:My Computer\\)?([A-Z]):', str(p)) or [None, None])[1] in cd_letters else k, n, p, x)
          for (t, s_, k, n, p, x) in ev]

    drop = {x.strip() for x in a.drop.split(',') if x.strip()}
    if drop:
        ev = [e for e in ev if e[1] not in drop]
        print(f'(ablation: tanpa {", ".join(sorted(drop))})')

    # ---------- 2. kelompok salinan (waktu) ----------
    sig = sorted([e for e in ev if e[2] == 'copy_signature'], key=lambda e: e[0])
    groups, cur = [], []
    for e in sig:
        if cur and (e[0] - cur[-1][0]).total_seconds() > a.gap:
            groups.append(cur); cur = []
        cur.append(e)
    if cur: groups.append(cur)

    # ---------- 3. aturan label ----------
    W = timedelta(minutes=10)
    def near(kinds, t0, t1, names=None):
        out = []
        for e in ev:
            if e[2] not in kinds or e[0] is None: continue
            if not (t0 - W <= e[0] <= t1 + W): continue
            if names is not None and e[3] not in names: continue
            out.append(e)
        return out
    cands = []
    for g in groups:
        t0, t1 = g[0][0], g[-1][0]
        names = {e[3] for e in g}
        net = [e for e in ev if e[2] == 'open_network' and e[3] in names]
        lnk_usb = [e for e in ev if e[2] == 'open_removable' and e[3] in names and e[0]
                   and t0 - timedelta(minutes=30) <= e[0] <= t1]
        sb_usb = near({'dir_removable'}, t0, t1)
        cd = near({'cd_stage', 'dir_cd'}, t0, t1)
        if cd and not net and not lnk_usb:
            lab, why = 'Bukan USB (penyimpanan CD)', 'folder Burn di USN'
        elif net and not lnk_usb:
            lab, why = 'Bukan USB (network drive)', f'{len(net)} file tertaut ke \\\\10.11.11.128'
        elif lnk_usb:
            lab, why = 'Copy Strongly Supported (USB->PC)', f'LNK/JumpList ke drive lepas sebelum salinan ({len(lnk_usb)} file)'
        elif sb_usb:
            lab, why = 'Copy Suspected (USB->PC)', 'pola salinan di C: + ShellBag drive lepas di sekitar waktu itu'
        else:
            lab, why = 'Inconclusive', 'pola salinan tanpa sumber yang jelas'
        cands.append({'t0': t0, 't1': t1, 'files': sorted(names), 'label': lab, 'why': why})

    # PC -> USB: pohon folder di drive lepas yang meniru folder sumber di PC.
    # Dikelompokkan per folder teratas di drive (mis. E:\RM#1 vs E:\Secret Project Data), karena
    # huruf drive yang sama bisa dipakai flashdisk berbeda. Arah ditentukan dari urutan waktu.
    pc_tree = [e for e in ev if e[2] == 'pc_tree' and e[0]]
    pc_dirs = {e[3].lower() for e in pc_tree}
    pc_first = min((e[0] for e in pc_tree), default=None)
    tops = defaultdict(list)
    for e in ev:
        if e[2] != 'dir_removable' or not e[0]: continue
        parts = str(e[4]).split('\\')
        if parts[0] == 'My Computer': parts = parts[1:]
        if len(parts) >= 2: tops[parts[0] + '\\' + parts[1]].append(e)
    for top, es in tops.items():
        match = {e[3].lower() for e in es} & pc_dirs
        if len(match) < 3: continue
        t0, t1 = min(e[0] for e in es), max(e[0] for e in es)
        if pc_first and pc_first < t0:
            lab = 'Copy Suspected (PC->USB)'
        else:
            lab = 'Inconclusive (arah tidak jelas)'
        fn = sorted({e[3] for e in ev if e[2] in ('open_removable', 'dir_removable') and '.' in e[3]
                     and str(e[4]).replace('My Computer\\', '').startswith(top)})
        cands.append({'t0': t0, 't1': t1, 'files': fn, 'label': lab,
                      'why': f'{len(match)} nama folder di {top} sama dengan folder PC; nama file tercatat: {len(fn)}'})

    # ---------- 4. laporan ----------
    print('=== KANDIDAT OPERASI (waktu UTC) ===')
    for c in sorted(cands, key=lambda c: c['t0']):
        print(f"{c['t0']:%Y-%m-%d %H:%M} - {c['t1']:%H:%M} | {c['label']} | {len(c['files'])} file | {c['why']}")

    # ---------- 5. evaluasi terhadap ground truth ----------
    truth = json.loads(Path(a.truth).read_text(encoding='utf-8'))
    all_names = {e[3] for e in ev}
    print('\n=== EVALUASI (ground truth NIST) ===')
    for op in truth['operations']:
        t = datetime.strptime(op['local'][:16], '%Y-%m-%d %H:%M').replace(tzinfo=timezone.utc) + timedelta(hours=4)
        best = min(cands, key=lambda c: abs((c['t0'] - t).total_seconds()), default=None)
        hit = [best] if best and abs((best['t0'] - t).total_seconds()) <= 900 else []
        files = op.get('files')
        rec = ''
        if files:
            found = [f for f in files if f in all_names]
            rec = f" | nama file ditemukan {len(found)}/{len(files)} ({100*len(found)//len(files)}%)"
        print(f"{op['id']} {op['direction']:<14} {op['local']} | terdeteksi: {hit[0]['label'] if hit else 'TIDAK'}{rec}")

if __name__ == '__main__':
    main()
