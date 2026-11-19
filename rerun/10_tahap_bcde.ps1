# 10_tahap_bcde.ps1 - TAHAP 10: adapter (B) -> label kasus (C) -> korelasi (D) -> eksperimen (E)
# Panduan Teknis poin 5-6 (B, D), poin 8 (C: label hanya untuk evaluasi), poin 7-9 (E: ablation, evaluasi, baseline)
# README dosen bagian 6-7 (B), 7 dan 9 (C), 7 (D), 8 dan 9 (E)
# Interpreter: Python 3.14 (tidak perlu venv; tahap_* hanya stdlib + usb_forensics)
# Folder kerja: D:\RM\usb-forensics-starter\usb-forensics-starter
# Sumber: history baris 561-583 dan PANDUAN_JALANKAN.txt. Argumen --xxx eksplisit diambil dari argparse:
#   tahap_b_adapter.py baris 217-229, tahap_c_label_kasus.py baris 25-32,
#   tahap_d_korelasi.py baris 217-223, tahap_e_eksperimen.py baris 109-118.
#   Aslinya dijalankan TANPA argumen (pakai default D:\RM\data\...). Di sini semua path diarahkan ke D:\RM_rerun\data.
# CATATAN PATCH: tahap_b_adapter.py dan tahap_d_korelasi.py diubah di tempat pada 22 Okt (history 564 dan 577,
#   -replace ... | Set-Content). File yang ada sekarang SUDAH berisi patch itu, dan output final di D:\RM\data
#   dibuat setelah patch (history 566, 579, 580). Run pertama tahap_b (history 562) dan tahap_d (568) = sebelum patch.
# Input (default dari rerun; -InputAsli = baca upstream dari D:\RM\data, read-only, untuk uji tahap 10 saja):
#   normalized\usb02_complete.json, metadata\usb02_body.txt, artifacts\pc-run2\artifact-0..3.jsonl,
#   exports\pc\Windows\inf\setupapi.dev.log, labels\rm2_labels.json, normalized\pc.json, exports\pc
# Output: D:\RM_rerun\data\normalized\events.json, events_report.json, device_inventory.json, device_map.json
#         D:\RM_rerun\data\labels\case_labels.json
#         D:\RM_rerun\data\results\correlated.json, kandidat.txt
#         D:\RM_rerun\data\results\eksperimen\baselines.json, experiments.csv, experiments_summary.json, correlated_full.json
#         (opsional -Seeds1000) D:\RM_rerun\data\results\eksperimen_1000\
# Waktu : B 2-5 menit (USN 189 MB dibaca dua kali), C/D detik, E +- 1 menit (30 seed); 1000 seed belum pernah
#         diukur (perkiraan kasar x33 dari 30 seed).
# Acuan : B: fs_usb 82/41 root, usnjrnl 412, jumplist 2, lnk 2 (1 root), setupapi 2; total root 499 (6 kelompok
#            termasuk "content" dari usb02_complete). C: serial 4C530012550531106501.
#         D: pc_to_usb 17/17, interval 56-107 s (median 73 s), landscape.png 2 kandidat.
#         E: 127 run; fp/device_wrong/direction_wrong/time_inconsistent = 0 di semua skenario.
param([switch]$InputAsli, [switch]$Seeds1000)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force 'D:\RM_rerun\logs' | Out-Null
Start-Transcript -Path 'D:\RM_rerun\logs\10_tahap_bcde.log' -Append
try {
    . "$PSScriptRoot\_common.ps1"
    Assert-Python314
    $src  = if ($InputAsli) { $RMData } else { $RRData }    # sumber upstream
    $norm = Join-Path $RRData 'normalized'
    $lab  = Join-Path $RRData 'labels'
    $res  = Join-Path $RRData 'results'
    Write-Host "Input upstream dibaca dari: $src"

    $in = @{
        usb      = Join-Path $src 'normalized\usb02_complete.json'
        fatbody  = Join-Path $src 'metadata\usb02_body.txt'
        usn      = Join-Path $src 'artifacts\pc-run2\artifact-3.jsonl'
        jumplist = Join-Path $src 'artifacts\pc-run2\artifact-1.jsonl'
        lnk      = Join-Path $src 'artifacts\pc-run2\artifact-2.jsonl'
        usbreg   = Join-Path $src 'artifacts\pc-run2\artifact-0.jsonl'
        setupapi = Join-Path $src 'exports\pc\Windows\inf\setupapi.dev.log'
        rm2lab   = Join-Path $src 'labels\rm2_labels.json'
        pc       = Join-Path $src 'normalized\pc.json'
        pcexp    = Join-Path $src 'exports\pc'
    }
    foreach ($k in $in.Keys) { if ($k -eq 'pcexp') { Assert-Dir $in[$k] } else { Assert-File $in[$k] } }
    foreach ($f in 'events.json', 'device_map.json') { if (Test-Path (Join-Path $norm $f)) { throw "Sudah ada: $norm\$f" } }
    New-Item -ItemType Directory -Force $norm, $lab, $res | Out-Null

    Push-Location $Starter
    try {
        Write-Judul "TAHAP B - tahap_b_adapter.py  (2-5 menit)"
        Invoke-Native $Py314 @('tahap_b_adapter.py',
            '--usb-inventory', $in.usb,
            '--fat-body',      $in.fatbody,
            '--usn',           $in.usn,
            '--jumplist',      $in.jumplist,
            '--lnk',           $in.lnk,
            '--usb-registry',  $in.usbreg,
            '--setupapi',      $in.setupapi,
            '--out-dir',       $norm) | Out-Null

        Write-Judul "TAHAP C - tahap_c_label_kasus.py --serial-verified"
        # history 567. Serial sudah dicocokkan dengan dokumen NIST sebelum run asli.
        Invoke-Native $Py314 @('tahap_c_label_kasus.py',
            '--rm2-labels', $in.rm2lab,
            '--serial-verified',
            '--device-map', (Join-Path $norm 'device_map.json'),
            '--out',        (Join-Path $lab 'case_labels.json')) | Out-Null

        Write-Judul "TAHAP D - tahap_d_korelasi.py"
        # history 579 (run setelah patch 577)
        $corr = Join-Path $res 'correlated.json'
        Invoke-Native $Py314 @('tahap_d_korelasi.py',
            '--inputs', $in.usb, (Join-Path $norm 'events.json'),
            '--device-map',       (Join-Path $norm 'device_map.json'),
            '--device-inventory', (Join-Path $norm 'device_inventory.json'),
            '--out', $corr) | Out-Null

        Write-Judul "TAHAP E - tahap_e_eksperimen.py (30 seed)"
        # history 580
        Invoke-Native $Py314 @('tahap_e_eksperimen.py',
            '--usb',        $in.usb,
            '--events',     (Join-Path $norm 'events.json'),
            '--pc',         $in.pc,
            '--pc-export',  $in.pcexp,
            '--device-map', (Join-Path $norm 'device_map.json'),
            '--labels',     (Join-Path $lab 'case_labels.json'),
            '--seeds',      '30',
            '--out-dir',    (Join-Path $res 'eksperimen')) | Out-Null

        if ($Seeds1000) {
            Write-Judul "TAHAP E - 1000 seed (opsional; dari 00_BACA_DULU.md, belum ada hasil asli pembanding)"
            Invoke-Native $Py314 @('tahap_e_eksperimen.py',
                '--usb', $in.usb, '--events', (Join-Path $norm 'events.json'), '--pc', $in.pc,
                '--pc-export', $in.pcexp, '--device-map', (Join-Path $norm 'device_map.json'),
                '--labels', (Join-Path $lab 'case_labels.json'),
                '--seeds', '1000', '--out-dir', (Join-Path $res 'eksperimen_1000')) | Out-Null
        }
    } finally { Pop-Location }

    Write-Judul "Kandidat file PC per file bocor (history 569-576)"
    $r = Get-Content $corr -Raw -Encoding UTF8 | ConvertFrom-Json
    $r.files | Where-Object direction -eq 'pc_to_usb' | ForEach-Object {
        $f = $_
        $f.pc_candidates | ForEach-Object {
            [pscustomobject]@{ file = ($f.usb_path -split '/')[-1]; kandidat = $_.pc_entity; nama_asal = $_.earliest_name_seen; dibuat_pc = $_.created_on_pc_utc; dihapus_pc = $_.deleted_on_pc_utc }
        }
    } | Format-Table -AutoSize | Out-File (Join-Path $res 'kandidat.txt') -Width 300
    Get-Content (Join-Path $res 'kandidat.txt') | Write-Host

    Write-Judul "landscape.png (history 581-582)"
    ($r.files | Where-Object usb_path -like '*landscape*').pc_candidates |
        Select-Object pc_entity, names_seen, name_acquired_utc | Format-List | Out-String | Write-Host

    Write-Judul "Cek kesalahan di experiments_summary.json (history 583)"
    Get-Content (Join-Path $res 'eksperimen\experiments_summary.json') |
        Select-String '"fp"|"device_wrong"|"direction_wrong"|"time_inconsistent"' -Context 0, 1 |
        Out-String -Width 200 | Write-Host
    Write-Host "`nSELESAI 10. Jalankan verify.ps1 untuk tabel SAMA/BEDA."
} finally {
    Stop-Transcript
}
