# 07_scan_pc_analyze.ps1 - TAHAP 7: inventaris PC (scan_pc_filtered.py) + pencocokan hash PC<->RM#2 (analyze)
# Panduan Teknis poin 4 ("Cocokkan dokumen berdasarkan isinya"); poin 9 (baseline hash)
# Interpreter: Python 3.14
# Input : D:\RM_rerun\data\exports\pc (tahap 4), D:\RM_rerun\data\normalized\usb02.json (tahap 6)
# Output: D:\RM_rerun\data\normalized\pc.json, pc_filter_stats.json
#         D:\RM_rerun\data\results\matches_pc_usb02.json, matches_summary.txt
# Sumber:
#   scan_pc_filtered.py : history baris 489-494 (dipindah dari Downloads, diedit di notepad, python scan_pc_filtered.py)
#   analyze             : history baris 495 (python usb_forensics.py analyze --inputs ...pc.json ...usb02.json --out ...matches_pc_usb02.json)
#   ringkasan           : history baris 499-501
# scan_pc_filtered.py path-nya hardcoded (baris 9-12) dan baris 1-nya sekarang "//untuk mengekstrak ..."
#   -> SyntaxError kalau dijalankan apa adanya (dicek dengan ast.parse, 18 Nov 2026).
#   [REKONSTRUKSI] yang dijalankan = salinan di D:\RM_rerun\kode_salinan: baris 1 dibuang, 4 path diganti
#   ke D:\RM_rerun\data. Isi logika tidak diubah. PYTHONPATH diarahkan ke folder kode dosen (import usb_forensics).
# Catatan sejarah: scan PC penuh (history 483, 484 dengan --complete pada \Users, 486) pernah dicoba,
#   lalu pc.json-nya ditimpa scan_pc_filtered.py. Tidak diulang di sini.
# Acuan : Total file PC 80778, ukuran unik USB02 41, file PC di-hash 51; analyze: 3 pasangan, semuanya desktop.ini

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force 'D:\RM_rerun\logs' | Out-Null
Start-Transcript -Path 'D:\RM_rerun\logs\07_scan_pc_analyze.log' -Append
try {
    . "$PSScriptRoot\_common.ps1"
    Assert-Python314
    $norm = Join-Path $RRData 'normalized'
    $res  = Join-Path $RRData 'results'
    Assert-Dir (Join-Path $RRData 'exports\pc')
    Assert-File (Join-Path $norm 'usb02.json')
    if (Test-Path (Join-Path $norm 'pc.json')) { throw "Sudah ada: $norm\pc.json" }
    New-Item -ItemType Directory -Force $res | Out-Null

    Write-Judul "scan_pc_filtered.py (salinan)"
    $sp = New-SalinanSkrip -Source (Join-Path $Starter 'scan_pc_filtered.py') -DropFirstLineIfSlashComment -Replacements @(
        @('PC_EXPORT = Path(r"D:\RM\data\exports\pc")',               'PC_EXPORT = Path(r"D:\RM_rerun\data\exports\pc")'),
        @('USB_JSON = Path(r"D:\RM\data\normalized\usb02.json")',      'USB_JSON = Path(r"D:\RM_rerun\data\normalized\usb02.json")'),
        @('OUT = Path(r"D:\RM\data\normalized\pc.json")',              'OUT = Path(r"D:\RM_rerun\data\normalized\pc.json")'),
        @('STATS = Path(r"D:\RM\data\normalized\pc_filter_stats.json")', 'STATS = Path(r"D:\RM_rerun\data\normalized\pc_filter_stats.json")')
    )
    $oldPP = $env:PYTHONPATH
    $env:PYTHONPATH = $Starter
    try { Invoke-Native $Py314 @($sp) | Out-Null } finally { $env:PYTHONPATH = $oldPP }

    Write-Judul "usb_forensics.py analyze (kode dosen)"
    $m = Join-Path $res 'matches_pc_usb02.json'
    Push-Location $Starter
    try {
        Invoke-Native $Py314 @('usb_forensics.py', 'analyze', '--inputs', (Join-Path $norm 'pc.json'), (Join-Path $norm 'usb02.json'), '--out', $m) | Out-Null
    } finally { Pop-Location }

    # history 499-501
    $r = Get-Content $m -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-Host ("Jumlah pasangan: " + $r.matches.Count + "   (acuan: 3, semuanya desktop.ini)")
    $r.matches | Select-Object pc_path, usb_path | Format-Table -AutoSize -Wrap |
        Out-File (Join-Path $res 'matches_summary.txt') -Width 300
    Get-Content (Join-Path $res 'matches_summary.txt') | Write-Host
    Write-Host "`nSELESAI 07."
} finally {
    Stop-Transcript
}
