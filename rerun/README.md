# Runbook rerun

Dokumentasi lengkap (sumber setiap command, input/output, hasil acuan): `D:\RM\docs\COMMANDS.md`.

- Skrip hanya MEMBACA `D:\RM` dan menulis ke `D:\RM_rerun\` (subfolder `data\` meniru `D:\RM\data\`).
- Tiap skrip membuat transcript `D:\RM_rerun\logs\<nama>.log`.
- Skrip yang path-nya hardcoded (`make_rm2_labels.py`, `scan_pc_filtered.py`) dijalankan sebagai salinan di
  `D:\RM_rerun\kode_salinan\`. File aslinya tidak diubah. Kode dosen tidak disalin dan tidak diubah.

Urutan (PowerShell biasa, bukan venv):

    cd D:\RM\rerun
    powershell -ExecutionPolicy Bypass -File .\00_env.ps1
    powershell -ExecutionPolicy Bypass -File .\01_hash.ps1          # lama
    powershell -ExecutionPolicy Bypass -File .\02_extract.ps1       # opsional, lama, +25 GB
    powershell -ExecutionPolicy Bypass -File .\03_mmls.ps1
    powershell -ExecutionPolicy Bypass -File .\04_tsk_recover.ps1   # lama, +21 GB
    powershell -ExecutionPolicy Bypass -File .\05_uji_dosen.ps1
    powershell -ExecutionPolicy Bypass -File .\06_tahap_a_labels.ps1
    powershell -ExecutionPolicy Bypass -File .\07_scan_pc_analyze.ps1
    powershell -ExecutionPolicy Bypass -File .\08_fls_timeline.ps1
    powershell -ExecutionPolicy Bypass -File .\09_dissect.ps1
    powershell -ExecutionPolicy Bypass -File .\10_tahap_bcde.ps1    # -Seeds1000 opsional
    powershell -ExecutionPolicy Bypass -File .\11_percobaan2.ps1    # -Lewati1000 opsional
    powershell -ExecutionPolicy Bypass -File .\verify.ps1

Mau ulang satu tahap: hapus/ganti nama folder output tahap itu di `D:\RM_rerun` (skrip menolak menimpa output).
