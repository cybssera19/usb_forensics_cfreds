# 09_dissect.ps1 - TAHAP 9: artefak PC dengan Dissect (pc-run2) + potongan USN + setupapi
# Panduan Teknis poin 5 ("Salah satu alat berbasis Python adalah Dissect ... target-query -l / -f usb -j")
# Interpreter: venv .venv311 (Python 3.11.9, dissect.target 3.25.1). JANGAN Python 3.14 (pc-run1 gagal).
# Folder kerja: D:\RM\usb-forensics-starter\usb-forensics-starter (extract_pc_artifacts.py import usb_forensics)
# Input : image PC asli (read-only)
# Output: D:\RM_rerun\data\artifacts\pc-run2\ (version, plugins, artifact-0..4 .jsonl/.stderr.txt, manifest.json)
#         D:\RM_rerun\data\artifacts\pc-run2\usn_0935_1015.jsonl
# Sumber:
#   history 541-549 : py -3.11 -m venv .venv311 ; Activate.ps1 ; pip install dissect ; pip freeze > environment.txt ;
#                     target-query --version ;
#                     python extract_pc_artifacts.py --image "<pc.dd>" --out D:\RM\data\artifacts\pc-run2 --plugins usb jumplist lnk usnjrnl evtx
#   manifest.json pc-run2 : 7 command target-query yang dijalankan wrapper (semua returncode 0)
#   history 552-553 : Select-String artifact-3.jsonl -Pattern '2015-03-24T(13:[3-5]\d|14:[01]\d)' ... > usn_0935_1015.jsonl
#   setupapi.dev.log : TIDAK dari Dissect. tahap_b membaca salinan hasil tsk_recover (exports\pc\Windows\inf\).
# Waktu : +- 5 menit (manifest pc-run2: version 11:22:31 -> evtx selesai 11:26:35; sebelumnya SHA-256 image 20 GB).
#         usnjrnl = 189 MB JSONL, paling lama (+- 2 menit).
# Percobaan gagal pc-run1 (Python 3.14 .venv, semua returncode 1, output 0 byte) TIDAK diulang.
param([string]$Venv = 'D:\RM\usb-forensics-starter\usb-forensics-starter\.venv311')

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force 'D:\RM_rerun\logs' | Out-Null
Start-Transcript -Path 'D:\RM_rerun\logs\09_dissect.log' -Append
try {
    . "$PSScriptRoot\_common.ps1"
    Assert-File $ImgPC
    $act = Join-Path $Venv 'Scripts\Activate.ps1'
    Assert-File $act
    Assert-File (Join-Path $Starter 'extract_pc_artifacts.py')
    $out = Join-Path $RRData 'artifacts\pc-run2'
    Assert-OutputPath $out
    if (Test-Path $out) { throw "Sudah ada: $out (extract_pc_artifacts.py memakai mkdir exist_ok=False)" }
    New-Item -ItemType Directory -Force (Split-Path $out) | Out-Null

    # history 543-544
    Set-ExecutionPolicy -Scope Process Bypass -Force
    . $act
    try {
        $v = (& python --version 2>&1 | Out-String).Trim()
        Write-Host "venv python: $v (acuan Python 3.11.9)"
        if ($v -notmatch '^Python 3\.11') { throw "Interpreter venv bukan 3.11: $v" }
        Invoke-Native 'target-query' @('--version') | Out-Null

        Push-Location $Starter
        try {
            Write-Judul "extract_pc_artifacts.py  -- +- 5 menit"
            $t0 = Get-Date
            Invoke-Native 'python' @('extract_pc_artifacts.py', '--image', $ImgPC, '--out', $out,
                '--plugins', 'usb', 'jumplist', 'lnk', 'usnjrnl', 'evtx') | Out-Null
            Write-Host ("Selesai dalam {0:N1} menit" -f ((Get-Date) - $t0).TotalMinutes)
        } finally { Pop-Location }
    } finally {
        if (Get-Command deactivate -ErrorAction SilentlyContinue) { deactivate }
    }

    # history 550-551
    (Get-Content (Join-Path $out 'manifest.json') -Raw | ConvertFrom-Json).runs |
        Format-Table returncode, status, output -AutoSize | Out-String -Width 250 | Write-Host
    Get-ChildItem $out | Format-Table Name, Length -AutoSize | Out-String | Write-Host

    Write-Judul "Potongan USN 13:30-14:19 UTC (history 553)"
    Push-Location $out
    try {
        Select-String -Path artifact-3.jsonl -Pattern '2015-03-24T(13:[3-5]\d|14:[01]\d)' | ForEach-Object { $_.Line } |
            Out-File usn_0935_1015.jsonl -Encoding utf8
        Get-Item usn_0935_1015.jsonl | Format-Table Name, Length | Out-String | Write-Host
    } finally { Pop-Location }

    Write-Judul "setupapi.dev.log (dari ekspor tsk_recover, bukan Dissect)"
    $sa = Join-Path $RRData 'exports\pc\Windows\inf\setupapi.dev.log'
    if (Test-Path $sa) {
        $h = (Get-FileHash $sa -Algorithm SHA256).Hash
        $acuan = '0588540A90EC22FD8F2118AFDBAF7FE05C783E040C396422FE715ECC683665EB'
        Write-Host "SHA-256 $h  -> $(if ($h -eq $acuan) {'SAMA dengan ekspor asli dan input percobaan 2'} else {'BEDA'})"
    } else { Write-Warning "Belum ada $sa (jalankan 04 dulu)" }
    Write-Host "`nSELESAI 09. Output: $out"
} finally {
    Stop-Transcript
}
