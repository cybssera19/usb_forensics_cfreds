"""R&D prototipe: alat forensik USB lokal (Flask).

Yang diuji di prototipe ini (bagian paling berisiko dari rancangan):
  1. Pemeriksa lingkungan (alat ada/tidak, versi) -> hijau/merah
  2. Tahap berjalan di LATAR BELAKANG, log langsung, tahan browser ditutup
  3. Status: belum / jalan / selesai / gagal / TERPUTUS (proses mati di tengah jalan)
  4. Lencana lulus/gagal dari nilai acuan
  5. Output program ditulis ke file APA ADANYA (tanpa re-encode shell), path berspasi aman
  6. Cegah laptop tidur selama tahap jalan (Windows)
  7. Tidak pernah menimpa: tiap eksekusi masuk folder run-<waktu> sendiri

Jalankan:  python -m pip install flask   lalu   python app.py   lalu buka http://127.0.0.1:5000
Hanya bisa diakses dari komputer ini (127.0.0.1). Tidak ada data yang diunggah.
"""
import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

from flask import Flask, jsonify, request

BASE = Path(__file__).resolve().parent
CONFIG_FILE = BASE / "config.json"

DEFAULT_CONFIG = {
    "tsk_bin": r"C:\Users\Acer\Downloads\Tools foren\sleuthkit-4.15.0-win32\bin",
    "img_pc": r"D:\RM FIX\rerun4_out\extract\cfreds_2015_data_leakage_pc.7z\cfreds_2015_data_leakage_pc.dd",
    "img_rm2": r"D:\RM FIX\rerun4_out\extract\cfreds_2015_data_leakage_rm#2\cfreds_2015_data_leakage_rm#2.dd",
    "seven_zip": r"C:\Program Files\7-Zip\7z.exe",
    "dissect_venv": r"D:\RM FIX\usb-forensics-starter\usb-forensics-starter\.venv311-ulang",
    "out_root": str(BASE / "out"),
}

app = Flask(__name__)
JOBS = {}  # stage_id -> Thread yang hidup di proses ini
LOCK = threading.Lock()


# ----------------------------------------------------------------- konfigurasi
def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
    return cfg


def save_config(new):
    cfg = load_config()
    for k in DEFAULT_CONFIG:
        if k in new and isinstance(new[k], str):
            cfg[k] = new[k].strip()
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    return cfg


def exe(folder, name):
    """Cari program di folder; terima 'mmls.exe' (Windows) maupun 'mmls' (uji di Linux)."""
    for cand in (name + ".exe", name):
        p = Path(folder) / cand
        if p.is_file():
            return str(p)
    return None


# ----------------------------------------------------------------- cek lingkungan
def run_quiet(args, timeout=20):
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout)
        out = (r.stdout + r.stderr).decode("utf-8", "replace").strip()
        return r.returncode, out
    except Exception as e:  # noqa: BLE001
        return -1, str(e)


def check_env(cfg):
    rows = []

    def add(nama, ok, detail):
        rows.append({"nama": nama, "ok": bool(ok), "detail": detail})

    add("Python", True, sys.version.split()[0])
    m = exe(cfg["tsk_bin"], "mmls")
    if m:
        _, v = run_quiet([m, "-V"])
        add("Sleuth Kit (mmls)", "Sleuth Kit" in v, v.splitlines()[0] if v else "tanpa output")
    else:
        add("Sleuth Kit (mmls)", False, "tidak ditemukan di " + cfg["tsk_bin"])
    for key, label in (("img_pc", "Image PC"), ("img_rm2", "Image RM#2")):
        p = Path(cfg[key])
        add(label, p.is_file(), f"{p.stat().st_size:,} byte" if p.is_file() else "tidak ada: " + cfg[key])
    sz = Path(cfg["seven_zip"])
    add("7-Zip", sz.is_file(), cfg["seven_zip"] if sz.is_file() else "tidak ada: " + cfg["seven_zip"])
    tq = exe(Path(cfg["dissect_venv"]) / "Scripts", "target-query") or exe(Path(cfg["dissect_venv"]) / "bin", "target-query")
    if tq:
        _, v = run_quiet([tq, "--version"])
        add("Dissect (target-query)", "dissect" in v.lower(), v.splitlines()[0] if v else "tanpa output")
    else:
        add("Dissect (target-query)", False, "venv tidak ditemukan: " + cfg["dissect_venv"])
    free = shutil.disk_usage(cfg["out_root"] if Path(cfg["out_root"]).exists() else BASE).free / 1024 ** 3
    add("Ruang disk output", free > 30, f"{free:,.0f} GB kosong (perlu > 30 GB untuk run penuh)")
    return rows


# ----------------------------------------------------------------- tahap
def stage_mmls_commands(cfg, outdir):
    m = exe(cfg["tsk_bin"], "mmls")
    if not m:
        raise RuntimeError("mmls tidak ditemukan; periksa Pengaturan")
    return [("pc_mmls.txt", [m, cfg["img_pc"]]), ("rm2_mmls.txt", [m, cfg["img_rm2"]])]


def stage_mmls_checks(outdir):
    def has(fname, *pats):
        p = Path(outdir) / fname
        if not p.is_file():
            return False
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        return any(all(re.search(x, ln) for x in pats) for ln in lines)

    return [
        {"item": "Offset NTFS PC", "acuan": "206848", "ok": has("pc_mmls.txt", r"\b0*206848\b", "NTFS")},
        {"item": "Offset FAT32 RM#2", "acuan": "128", "ok": has("rm2_mmls.txt", r"\b0*128\b", "FAT32")},
    ]


STAGES = [{
    "id": "03_mmls",
    "nama": "03 - Tabel partisi (mmls)",
    "perkiraan": "detik",
    "butuh": ["tsk_bin", "img_pc", "img_rm2"],
    "commands": stage_mmls_commands,
    "checks": stage_mmls_checks,
}]
STAGE_BY_ID = {s["id"]: s for s in STAGES}


# ----------------------------------------------------------------- status & pelari
def sdir(cfg, sid):
    d = Path(cfg["out_root"]) / "stages" / sid
    d.mkdir(parents=True, exist_ok=True)
    return d


def read_status(cfg, sid):
    f = sdir(cfg, sid) / "status.json"
    if not f.exists():
        return {"status": "belum"}
    st = json.loads(f.read_text(encoding="utf-8"))
    # proses yang tercatat 'jalan' tapi tidak ada thread hidup = TERPUTUS (jendela ditutup, laptop tidur, crash)
    if st.get("status") == "jalan":
        t = JOBS.get(sid)
        if not (t and t.is_alive()):
            st["status"] = "terputus"
    return st


def write_status(cfg, sid, **kw):
    f = sdir(cfg, sid) / "status.json"
    st = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
    st.update(kw)
    f.write_text(json.dumps(st, indent=2, ensure_ascii=False), encoding="utf-8")


def keep_awake(on):
    if os.name == "nt":
        ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001
        ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if on else 0))


def worker(cfg, sid, rundir):
    stage = STAGE_BY_ID[sid]
    log = rundir / "log.txt"
    keep_awake(True)
    try:
        with log.open("a", encoding="utf-8") as lg:
            def say(msg):
                lg.write(msg + "\n")
                lg.flush()

            for fname, args in stage["commands"](cfg, rundir):
                say(">> " + " ".join(f'"{a}"' if " " in a else a for a in args) + "  > " + fname)
                with (rundir / fname).open("wb") as out, (rundir / (fname + ".stderr.txt")).open("wb") as err:
                    r = subprocess.run(args, stdout=out, stderr=err)  # byte apa adanya
                say(f"   exit code {r.returncode}, {(rundir / fname).stat().st_size:,} byte")
                if r.returncode != 0:
                    write_status(cfg, sid, status="gagal", selesai=time.strftime("%H:%M:%S"),
                                 alasan=f"{Path(args[0]).name} exit code {r.returncode}")
                    return
            checks = stage["checks"](rundir)
            ok = all(c["ok"] for c in checks)
            say("Cek acuan: " + ", ".join(f"{c['item']}={'LULUS' if c['ok'] else 'GAGAL'}" for c in checks))
            write_status(cfg, sid, status="selesai" if ok else "gagal", checks=checks,
                         selesai=time.strftime("%H:%M:%S"), alasan="" if ok else "nilai acuan tidak cocok")
    except Exception as e:  # noqa: BLE001
        write_status(cfg, sid, status="gagal", alasan=str(e), selesai=time.strftime("%H:%M:%S"))
    finally:
        keep_awake(False)


def start_stage(sid):
    cfg = load_config()
    stage = STAGE_BY_ID[sid]
    with LOCK:
        t = JOBS.get(sid)
        if t and t.is_alive():
            return {"error": "tahap ini masih berjalan"}, 409
        for key in stage["butuh"]:
            p = Path(cfg[key])
            if not (p.is_file() or p.is_dir()):
                return {"error": f"prasyarat belum terpenuhi: {key} -> {cfg[key]}"}, 400
        stem = sdir(cfg, sid) / ("run-" + time.strftime("%Y%m%d-%H%M%S"))
        rundir, n = stem, 1
        while rundir.exists():  # dua klik dalam detik yang sama -> beri akhiran, jangan bentrok/menimpa
            n += 1
            rundir = Path(f"{stem}-{n}")
        rundir.mkdir(parents=True)
        write_status(cfg, sid, status="jalan", mulai=time.strftime("%H:%M:%S"), rundir=str(rundir),
                     checks=[], alasan="")
        t = threading.Thread(target=worker, args=(cfg, sid, rundir), daemon=False)
        JOBS[sid] = t
        t.start()
    return {"ok": True, "rundir": str(rundir)}, 200


# ----------------------------------------------------------------- API
@app.get("/api/config")
def api_config():
    return jsonify(load_config())


@app.post("/api/config")
def api_config_save():
    return jsonify(save_config(request.get_json(force=True)))


@app.get("/api/env")
def api_env():
    return jsonify(check_env(load_config()))


@app.get("/api/stages")
def api_stages():
    cfg = load_config()
    return jsonify([{"id": s["id"], "nama": s["nama"], "perkiraan": s["perkiraan"], **read_status(cfg, s["id"])}
                    for s in STAGES])


@app.post("/api/run/<sid>")
def api_run(sid):
    if sid not in STAGE_BY_ID:
        return {"error": "tahap tidak dikenal"}, 404
    body, code = start_stage(sid)
    return jsonify(body), code


@app.get("/api/log/<sid>")
def api_log(sid):
    cfg = load_config()
    st = read_status(cfg, sid)
    log = Path(st["rundir"]) / "log.txt" if st.get("rundir") else None
    text = log.read_text(encoding="utf-8", errors="replace") if log and log.exists() else ""
    return jsonify({"status": st.get("status"), "log": text[-6000:]})


PAGE = """<!doctype html><meta charset="utf-8"><title>Prototipe alat forensik USB</title>
<style>
body{font:15px system-ui,sans-serif;margin:24px;max-width:980px;color:#222}
h1{font-size:20px} h2{font-size:16px;margin-top:28px}
table{border-collapse:collapse;width:100%} td,th{border-bottom:1px solid #ddd;padding:6px 8px;text-align:left}
.ok{color:#0a7a2f;font-weight:600}.bad{color:#b3261e;font-weight:600}.warn{color:#9a6700;font-weight:600}
input{width:100%;padding:5px} button{padding:6px 14px;cursor:pointer}
pre{background:#111;color:#ddd;padding:10px;max-height:260px;overflow:auto;white-space:pre-wrap}
.card{border:1px solid #ccc;border-radius:8px;padding:12px;margin:10px 0}
</style>
<h1>Prototipe alat forensik USB (R&amp;D)</h1>
<p>Lokal, hanya di komputer ini. Menguji: cek lingkungan, tahap di latar belakang, status terputus, lencana acuan.</p>
<h2>1. Pengaturan</h2><table id="cfg"></table><button onclick="saveCfg()">Simpan</button>
<h2>2. Cek lingkungan</h2><button onclick="loadEnv()">Periksa</button><table id="env"></table>
<h2>3. Tahap</h2><div id="stages"></div>
<script>
const $=id=>document.getElementById(id);
async function j(u,o){const r=await fetch(u,o);return r.json()}
async function loadCfg(){const c=await j('/api/config');
 $('cfg').innerHTML=Object.entries(c).map(([k,v])=>`<tr><td>${k}</td><td><input id="c_${k}" value="${v.replace(/"/g,'&quot;')}"></td></tr>`).join('')}
async function saveCfg(){const b={};document.querySelectorAll('[id^=c_]').forEach(e=>b[e.id.slice(2)]=e.value);
 await j('/api/config',{method:'POST',body:JSON.stringify(b)});loadEnv();loadStages()}
async function loadEnv(){$('env').innerHTML='<tr><td>memeriksa...</td></tr>';const r=await j('/api/env');
 $('env').innerHTML=r.map(x=>`<tr><td>${x.nama}</td><td class="${x.ok?'ok':'bad'}">${x.ok?'OK':'MASALAH'}</td><td>${x.detail}</td></tr>`).join('')}
async function run(id){const r=await j('/api/run/'+id,{method:'POST'});if(r.error)alert(r.error);loadStages()}
async function loadStages(){const s=await j('/api/stages');let h='';
 for(const x of s){const cls={selesai:'ok',gagal:'bad',terputus:'warn',jalan:'warn'}[x.status]||'';
  const chk=(x.checks||[]).map(c=>`<div class="${c.ok?'ok':'bad'}">${c.ok?'LULUS':'GAGAL'} - ${c.item} (acuan ${c.acuan})</div>`).join('');
  const lg=(await j('/api/log/'+x.id)).log;
  h+=`<div class="card"><b>${x.nama}</b> <span class="${cls}">[${x.status}]</span> <small>perkiraan ${x.perkiraan}</small>
  <button onclick="run('${x.id}')" ${x.status=='jalan'?'disabled':''}>Jalankan</button>${x.alasan?`<div class="bad">${x.alasan}</div>`:''}${chk}<pre>${lg.replace(/</g,'&lt;')}</pre></div>`}
 $('stages').innerHTML=h}
loadCfg();loadEnv();loadStages();setInterval(loadStages,2000);
</script>"""


@app.get("/")
def index():
    return PAGE


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
