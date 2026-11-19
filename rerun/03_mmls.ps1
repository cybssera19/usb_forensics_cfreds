# 03_mmls.ps1 - TAHAP 3: tabel partisi (mmls)
# Panduan Teknis poin 3 ("Bila perlu memilih partisi, tentukan offset dari image yang diperiksa")
# Interpreter: Sleuth Kit 4.14.0 (D:\tools\sleuthkit-4.14.0-win32\bin)
# Input : image PC dan RM#2 asli (hanya dibaca)
# Output: D:\RM_rerun\mmls\pc_mmls.txt, rm2_mmls.txt
# Sumber: history baris 431-433 ($env:Path += ...; mmls "<image>")
# Acuan : PC NTFS C: mulai sektor 206848; RM#2 FAT32 mulai sektor 128 (manifest.txt bagian 4)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force 'D:\RM_rerun\logs' | Out-Null
Start-Transcript -Path 'D:\RM_rerun\logs\03_mmls.log' -Append
try {
    . "$PSScriptRoot\_common.ps1"
    Assert-File $ImgPC
    Assert-File $ImgRM2
    Assert-File (Join-Path $TskBin 'mmls.exe')
    $env:Path += ";$TskBin"
    $out = Join-Path $RR 'mmls'
    New-Item -ItemType Directory -Force $out | Out-Null

    Write-Judul "mmls PC"
    $pc = Invoke-Native 'mmls' @($ImgPC)
    $pc | Out-File (Join-Path $out 'pc_mmls.txt') -Encoding utf8
    Write-Judul "mmls RM#2"
    $rm = Invoke-Native 'mmls' @($ImgRM2)
    $rm | Out-File (Join-Path $out 'rm2_mmls.txt') -Encoding utf8

    $okPC = [bool]($pc | Where-Object { $_ -match '\b0*206848\b' -and $_ -match 'NTFS' })
    $okRM = [bool]($rm | Where-Object { $_ -match '\b0*128\b' -and $_ -match 'FAT32' })
    Write-Host "PC   offset 206848 (NTFS) : $(if ($okPC) {'SAMA'} else {'BEDA'})"
    Write-Host "RM#2 offset 128 (FAT32)   : $(if ($okRM) {'SAMA'} else {'BEDA'})"
    Write-Host "`nSELESAI 03_mmls. Output: $out"
} finally {
    Stop-Transcript
}
