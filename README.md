# Rekonstruksi Perpindahan Dokumen ke USB melalui Korelasi Artefak Windows dan Evaluasi Kehilangan Bukti

Kode dan catatan reproduksi untuk dua percobaan pada dataset **NIST CFReDS Data Leakage Case**
(<https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html>).

- **Percobaan 1** (inti): artefak PC (`$UsnJrnl`, Jump List, LNK, `setupapi.dev.log`) dikorelasikan dengan metadata
  flashdisk RM#2 untuk menentukan arah penyalinan dokumen, lalu dievaluasi dengan penghilangan bukti (ablation).
- **Percobaan 2** (pendukung): analisis sisi PC saja dan eksperimen penghilangan bukti (masking) 30 dan 1000 seed.

> Repositori ini **tidak berisi data NIST** (image disk 20 GB dan 4 GB). Unduh sendiri dari NIST dan verifikasi hash
> arsipnya (lihat [Data](#data)).

## Struktur

| Folder | Isi |
|---|---|
| `src/` | Kode Percobaan 1. Berkas bertanda **(dosen)** adalah kode dosen dan **tidak diubah** |
| `percobaan2/` | Kode, masukan Dissect, kunci jawaban, dan hasil Percobaan 2 |
| `rerun/` | Runbook PowerShell 00 sampai 11 + `verify.ps1` untuk mengulang percobaan |
| `docs/` | `COMMANDS_formal.md` (catatan command dan sumbernya), `PANDUAN_JALANKAN.txt`, README dosen |
| `results/percobaan1/` | Hasil acuan Percobaan 1 (sumber angka di paper) |
| `labels/` | Label dari kunci jawaban NIST untuk evaluasi |
| `tools/web_prototype/` | Prototipe R&D antarmuka web lokal (belum final) |
| `requirements-dissect.txt` | Paket venv Dissect (Python 3.11) |

Berkas `src/`:

| Berkas | Peran |
|---|---|
| `usb_forensics.py` (dosen) | Mesin inventaris, pencocokan hash, korelasi |
| `extract_pc_artifacts.py` (dosen) | Ekspor artefak Dissect (`target-query ... -j`) |
| `demo.py`, `test_usb_forensics.py` (dosen) | Demo sintetis dan uji unit (15 tes) |
| `scan_pc_filtered.py` | Hash file PC yang ukurannya sama dengan file USB02 |
| `make_rm2_labels.py` | Label sisi RM#2 dari kunci jawaban NIST |
| `body2csv.py` | Body file `fls` menjadi timeline CSV |
| `tahap_a_tandai_utuh.py` | Tahap A: tandai file USB yang utuh (cocok dengan seed) |
| `tahap_b_adapter.py` | Tahap B: normalisasi artefak menjadi record bukti |
| `tahap_c_label_kasus.py` | Tahap C: label kasus dan pemetaan perangkat |
| `tahap_d_korelasi.py` | Tahap D: korelasi arah, waktu, dan perangkat |
| `tahap_e_eksperimen.py` | Tahap E: baseline, ablation, dan evaluasi |

## Kebutuhan

- Python 3.13 untuk semua skrip `src/` (hanya pustaka standar). Dissect membutuhkan **Python 3.11**
  (`pip install -r requirements-dissect.txt`). Python 3.14 gagal mengimpor `dissect.target`.
- The Sleuth Kit 4.14 atau 4.15 (`mmls`, `tsk_recover`, `fls`), 7-Zip atau WinRAR, Windows PowerShell 5.1.

## Data

Unduh arsip dari halaman NIST di atas: `cfreds_2015_data_leakage_pc.7z.001-.003`, `cfreds_2015_data_leakage_rm#2.7z`,
`cfreds_2015_data_leakage_seed_files.7z`. Bandingkan SHA-1 dengan
<https://cfreds-archive.nist.gov/data_leakage_case/hash_values.html>. Hash image hasil ekstraksi yang dipakai
(NIST tidak mempublikasikan hash `.dd`):

| Image | SHA-256 |
|---|---|
| `cfreds_2015_data_leakage_pc.dd` | `026C143638295DB1FBFA598C5B35BCAC4860BA73EC5DA1CC87B67AFD598BE4E2` |
| `cfreds_2015_data_leakage_rm#2.dd` | `D930AFA23F8905E88A28041786EDBE3791B5BF41B01468027EE27A19CD59D407` |

Offset partisi (`mmls`): PC NTFS **206848**, RM#2 FAT32 **128**.

## Menjalankan Percobaan 1

Semua skrip memiliki jalur bawaan yang menunjuk ke `D:\RM\data\...`. **Selalu isi argumen jalur secara eksplisit**
agar tidak membaca atau menulis ke lokasi yang tidak dimaksud. Ganti `<...>` dengan jalur Anda.

```powershell
# 1. Ekspor file (Sleuth Kit)
tsk_recover -e -o 128    "<rm#2.dd>" "<EXPORT>\usb02"
tsk_recover -e -o 206848 "<pc.dd>"   "<EXPORT>\pc"

# 2. Artefak Dissect (aktifkan venv Python 3.11 yang berisi Dissect; wajib via skrip ini karena memakai -j)
python src\extract_pc_artifacts.py --image "<pc.dd>" --out "<OUT>\artifacts\pc"

# 3. Body file FAT (tulis lewat cmd agar byte tidak diubah PowerShell)
cmd /c 'fls -r -m "USB02/" -z UTC0 -o 128 "<rm#2.dd>" > "<OUT>\metadata\usb02_body.txt"'

# 4. Inventaris dan tahap A sampai E (cukup Python biasa, tanpa venv)
python src\usb_forensics.py scan --folder "<EXPORT>\usb02" --media USB02 --out "<OUT>\normalized\usb02.json"
python src\scan_pc_filtered.py --pc-export "<EXPORT>\pc" --usb "<OUT>\normalized\usb02.json" --out "<OUT>\normalized\pc.json" --stats "<OUT>\normalized\pc_filter_stats.json"
python src\make_rm2_labels.py        # jalur DATA di dalam berkas harus disesuaikan (lihat catatan di bawah)
python src\tahap_a_tandai_utuh.py --usb "<OUT>\normalized\usb02.json" --seed "<SEED>" --out "<OUT>\normalized\usb02_complete.json" --check "<OUT>\normalized\usb02_complete_check.json"
python src\tahap_b_adapter.py --usb-inventory "<OUT>\normalized\usb02_complete.json" --fat-body "<OUT>\metadata\usb02_body.txt" --fat-utc-offset -4 --usn "<OUT>\artifacts\pc\artifact-3.jsonl" --jumplist "<OUT>\artifacts\pc\artifact-1.jsonl" --lnk "<OUT>\artifacts\pc\artifact-2.jsonl" --usb-registry "<OUT>\artifacts\pc\artifact-0.jsonl" --setupapi "<EXPORT>\pc\Windows\inf\setupapi.dev.log" --setupapi-utc-offset -4 --out-dir "<OUT>\normalized"
python src\tahap_c_label_kasus.py --serial-verified --rm2-labels "<OUT>\labels\rm2_labels.json" --device-map "<OUT>\normalized\device_map.json" --out "<OUT>\labels\case_labels.json"
python src\tahap_d_korelasi.py --inputs "<OUT>\normalized\usb02_complete.json" "<OUT>\normalized\events.json" --device-map "<OUT>\normalized\device_map.json" --device-inventory "<OUT>\normalized\device_inventory.json" --out "<OUT>\results\correlated.json"
python src\tahap_e_eksperimen.py --usb "<OUT>\normalized\usb02_complete.json" --events "<OUT>\normalized\events.json" --pc "<OUT>\normalized\pc.json" --pc-export "<EXPORT>\pc" --device-map "<OUT>\normalized\device_map.json" --labels "<OUT>\labels\case_labels.json" --out-dir "<OUT>\hasil_e"
```

Catatan:
- `make_rm2_labels.py` tidak memiliki argparse; ubah baris `DATA = Path(r"...")` ke folder data Anda sebelum dijalankan.
- `--out` Dissect harus folder yang **belum ada**; `--out-dir` tahap E harus **belum ada atau kosong**.
- Langkah 3 memakai `cmd /c` agar byte keluaran tidak diubah PowerShell. Pakai jalur **tanpa spasi** untuk langkah ini
  (cara yang sama dipakai pada run acuan, `rerun/08_fls_timeline.ps1`).
- Peringatan Dissect pada `stderr` (parse USBSTOR, LNK) juga muncul pada run acuan dan tidak menghentikan proses.
- `tsk_recover` pada image PC melaporkan 80.927 file; 4 file cache Internet Explorer gagal ditulis karena path lebih dari
  260 karakter. Ini batasan yang dicatat pada `docs/COMMANDS_formal.md`.

### Nilai yang diharapkan

| Tahap | Nilai |
|---|---|
| Ekspor | RM#2: 41 file; PC: 80.778 file di disk |
| Scan PC | 80778 file, 41 ukuran unik, 51 di-hash |
| A | 17 file ditandai utuh dari 41 |
| B | fs_usb 82, usnjrnl 412, jumplist 2, lnk 2, setupapi 2 |
| C | 17 target, 24 negatif; serial `4C530012550531106501` |
| D | 17 file `pc_to_usb` |
| E | Baseline: nama file dan hash precision 0.0; gabungan artefak precision 1.0 dan recall 1.0 |

Hasil acuan ada di `results/percobaan1/` (`experiments_summary.json`, `baselines.json`).

## Menjalankan Percobaan 2

Lihat `percobaan2/` dan `rerun/11_percobaan2.ps1`. Masukan Dissect Percobaan 2 dibuat pada Python 3.12 di akun lab
lain; perintah persisnya tidak terekam, sehingga bagian itu hanya dapat direkonstruksi (lihat `docs/COMMANDS_formal.md`
bagian 8).

## Status reproduksi

Hasil akhir Percobaan 1 telah direproduksi **identik byte per byte** pada dua pengulangan terpisah dengan jalur
eksplisit: (1) `experiments_summary.json` dan `baselines.json` dengan ekspor `tsk_recover` baru, dan
(2) `experiments_summary.json`, `baselines.json`, dan `correlated_full.json` dengan artefak Dissect baru
(`extract_pc_artifacts.py`, `-j`). Pada masing-masing pengulangan itu sebagian masukan perantara dari run
sebelumnya dipakai ulang. Pengulangan **penuh dari arsip NIST dalam satu rangkaian** (ekstraksi ulang,
`tsk_recover`, `fls`, Dissect, tahap A sampai E) sedang diverifikasi; hasilnya akan ditambahkan di sini.
Batasan yang diketahui ada di `docs/COMMANDS_formal.md` bagian 8.

## Catatan penggunaan `rerun/`

Skrip `rerun/*.ps1` ditulis untuk susunan folder `D:\RM` dan keluaran `D:\RM_rerun`. Jika folder Anda berbeda, ubah
konstanta di `rerun/_common.ps1` dan baris `Start-Transcript` pada tiap skrip. Skrip hanya membaca data asli dan
menolak menimpa keluaran yang sudah ada.

## Atribusi dan lisensi

Lihat [NOTICE.md](NOTICE.md).
