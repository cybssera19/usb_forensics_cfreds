# 00_env.ps1 - TAHAP 0: catat lingkungan (Panduan Teknis poin 3: "catat versi alat")
# Interpreter: Python 3.14 (C:\Python314), venv Dissect .venv311 (Python 3.11), Sleuth Kit 4.14.0
# Output: D:\RM_rerun\env\*.txt
# Opsional: -BuatVenvBaru  -> buat venv Dissect baru di D:\RM_rerun\venv311 dari environment.txt
#           [REKONSTRUKSI] aslinya: py -3.11 -m venv .venv311 ; python -m pip install dissect (tanpa pin versi)
param([switch]$BuatVenvBaru)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force 'D:\RM_rerun\logs' | Out-Null
Start-Transcript -Path 'D:\RM_rerun\logs\00_env.log' -Append
try {
    . "$PSScriptRoot\_common.ps1"
    $out = Join-Path $RR 'env'
    New-Item -ItemType Directory -Force $out | Out-Null

    Write-Judul "TODO 1: versi persis Python (harus $Py314Ver)"
    # sumber: history PowerShell baris 538 (python --version), manifest.txt bagian 1
    $v = (& python --version 2>&1 | Out-String).Trim()
    Write-Host "python --version (PATH) : $v"
    $v2 = (& $Py314 --version 2>&1 | Out-String).Trim()
    Write-Host "$Py314 --version : $v2"
    if ($v -ne $Py314Ver) { Write-Warning "python di PATH bukan $Py314Ver" } else { Write-Host "OK: sama dengan manifest.txt" }
    "$v`r`n$v2" | Out-File (Join-Path $out 'python_version.txt') -Encoding utf8

    Write-Judul "Daftar interpreter (py -0p)"
    # sumber: history baris 540 (py -0)
    Invoke-Native 'py' @('-0p') | Out-File (Join-Path $out 'py_0p.txt') -Encoding utf8
    $daftar = Get-Content (Join-Path $out 'py_0p.txt') -Raw
    if ($daftar -notmatch '3\.12') {
        Write-Warning "Python 3.12 tidak terpasang di akun ini. Percobaan 2 (Dissect 3.12) aslinya jalan di akun labsUSB."
    }

    Write-Judul "venv Dissect (.venv311)"
    $vpy = Join-Path $Venv311 'Scripts\python.exe'
    $tq  = Join-Path $Venv311 'Scripts\target-query.exe'
    Assert-File $vpy
    Assert-File $tq
    Invoke-Native $vpy @('--version') | Out-File (Join-Path $out 'venv311_python_version.txt') -Encoding utf8
    # sumber: manifest.json pc-run2 run[0] (target-query --version) -> "dissect.target version 3.25.1"
    $tqv = Invoke-Native $tq @('--version')
    $tqv | Out-File (Join-Path $out 'target_query_version.txt') -Encoding utf8
    if (($tqv -join ' ') -notmatch '3\.25\.1') { Write-Warning "dissect.target bukan 3.25.1" }
    # sumber: history baris 547 (python -m pip freeze > environment.txt). Di sini ke folder rerun, bukan ke folder kode.
    Invoke-Native $vpy @('-m','pip','freeze') | Out-File (Join-Path $out 'pip_freeze_venv311.txt') -Encoding utf8
    Write-Host "Bandingkan dengan: $Starter\environment.txt (UTF-16, hasil 'pip freeze >' di PS 5.1)"

    Write-Judul "pip freeze Python 3.14 (kode dosen + tahap_* hanya pakai stdlib)"
    Invoke-Native $Py314 @('-m','pip','freeze') | Out-File (Join-Path $out 'pip_freeze_py314.txt') -Encoding utf8

    Write-Judul "Sleuth Kit"
    # sumber: history baris 431 ($env:Path += ";D:\tools\sleuthkit-4.14.0-win32\bin")
    Invoke-Native (Join-Path $TskBin 'mmls.exe') @('-V') | Out-File (Join-Path $out 'sleuthkit_version.txt') -Encoding utf8

    Write-Judul "Pengekstrak arsip (WinRAR 7.13 dipakai lewat GUI; 7-Zip 25.01 tersedia)"
    # sumber: history baris 420 (Get-ItemProperty ... Uninstall\* | DisplayName -match WinRAR|7-Zip|...)
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match "WinRAR|7-Zip|Autopsy|FTK|Python" } |
        Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize | Out-String -Width 200 |
        Tee-Object -FilePath (Join-Path $out 'installed_tools.txt') | Write-Host

    if ($BuatVenvBaru) {
        Write-Judul "[REKONSTRUKSI] venv Dissect baru dari environment.txt"
        $nv = Join-Path $RR 'venv311'
        Assert-EmptyOrMissing $nv
        Invoke-Native 'py' @('-3.11','-m','venv',$nv) | Out-Null
        Invoke-Native (Join-Path $nv 'Scripts\python.exe') @('-m','pip','install','-r',(Join-Path $Starter 'environment.txt')) | Out-Null
        Invoke-Native (Join-Path $nv 'Scripts\target-query.exe') @('--version') | Out-Null
        Write-Host "venv baru: $nv  (09_dissect.ps1 tetap memakai .venv311 asli kecuali diberi -Venv)"
    }
    Write-Host "`nSELESAI 00_env. Output: $out"
} finally {
    Stop-Transcript
}
