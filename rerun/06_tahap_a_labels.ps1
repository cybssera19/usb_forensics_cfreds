# 06_tahap_a_labels.ps1 - TAHAP 6: label RM#2 (make_rm2_labels.py) + inventaris USB02 + tahap A (tandai utuh)
# Panduan Teknis poin 3 ("tandai file yang utuh") dan poin 8 (label untuk evaluasi); README dosen bagian 5
# Interpreter: Python 3.14
# URUTAN ASLI: make_rm2_labels.py (20 Okt) -> usb_forensics.py scan USB02 (21 Okt) -> tahap_a (22 Okt).
#   tahap_a butuh usb02.json, jadi scan USB02 dijalankan di skrip ini (bukan di 07).
# Input : D:\RM_rerun\data\exports\usb02 (tahap 4), seed files asli
# Output: D:\RM_rerun\data\labels\rm2_labels.json
#         D:\RM_rerun\data\normalized\usb02.json, usb02_complete.json, usb02_complete_check.json
# Sumber:
#   make_rm2_labels.py : history baris 478-479 (cd D:\RM\data\labels ; python make_rm2_labels.py)
#   scan USB02         : history baris 488 (python usb_forensics.py scan --folder ...usb02 --media USB02 --out ...usb02.json)
#   tahap A            : history baris 561 (python tahap_a_tandai_utuh.py) + argparse tahap_a_tandai_utuh.py baris 25-28
# make_rm2_labels.py punya path hardcoded (baris 15: DATA = Path(r"D:\RM\data")) dan tidak punya argparse.
#   [REKONSTRUKSI] yang dijalankan = salinan di D:\RM_rerun\kode_salinan dengan baris 15 diganti ke D:\RM_rerun\data.
# Acuan : rm2_labels Target 17 / 17, negatif 24; tahap A "Ditandai complete : 17" dari 41 file

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force 'D:\RM_rerun\logs' | Out-Null
Start-Transcript -Path 'D:\RM_rerun\logs\06_tahap_a_labels.log' -Append
try {
    . "$PSScriptRoot\_common.ps1"
    Assert-Python314
    $usbExp = Join-Path $RRData 'exports\usb02'
    Assert-Dir $usbExp
    Assert-Dir $SeedDir
    $labels = Join-Path $RRData 'labels'
    $norm   = Join-Path $RRData 'normalized'
    New-Item -ItemType Directory -Force $labels, $norm | Out-Null

    Write-Judul "make_rm2_labels.py (salinan, path -> D:\RM_rerun\data)"
    Assert-EmptyOrMissing (Join-Path $labels 'rm2_labels.json')
    $mk = New-SalinanSkrip -Source (Join-Path $RMData 'labels\make_rm2_labels.py') -Replacements @(
        , @('DATA = Path(r"D:\RM\data")', 'DATA = Path(r"D:\RM_rerun\data")')
    )
    Push-Location $labels
    try { Invoke-Native $Py314 @($mk) | Out-Null } finally { Pop-Location }

    Push-Location $Starter
    try {
        Write-Judul "usb_forensics.py scan USB02 (kode dosen, tanpa --complete)"
        $usbJson = Join-Path $norm 'usb02.json'
        if (Test-Path $usbJson) { throw "Sudah ada: $usbJson" }
        Invoke-Native $Py314 @('usb_forensics.py', 'scan', '--folder', $usbExp, '--media', 'USB02', '--out', $usbJson) | Out-Null

        Write-Judul "tahap_a_tandai_utuh.py"
        Invoke-Native $Py314 @('tahap_a_tandai_utuh.py',
            '--usb',   $usbJson,
            '--seed',  $SeedDir,
            '--out',   (Join-Path $norm 'usb02_complete.json'),
            '--check', (Join-Path $norm 'usb02_complete_check.json')) | Out-Null
    } finally {
        Pop-Location
    }
    Write-Host "`nSELESAI 06. Harapan: 'Target : 17 / 17' dan 'Ditandai complete : 17'."
} finally {
    Stop-Transcript
}
