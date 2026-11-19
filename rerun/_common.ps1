# _common.ps1 - konstanta dan fungsi bersama runbook rerun.
# Di-dot-source oleh setiap skrip tahap:  . "$PSScriptRoot\_common.ps1"
# File ini sengaja ASCII saja (Windows PowerShell 5.1 membaca .ps1 tanpa BOM sebagai ANSI).
#
# PRINSIP
# - Image, folder data asli, dan skrip asli di D:\RM HANYA DIBACA.
# - Semua output ditulis ke D:\RM_rerun\ (subfolder data\ meniru D:\RM\data\).
# - Skrip tambahan yang path-nya hardcoded ke D:\RM\data (make_rm2_labels.py,
#   scan_pc_filtered.py) TIDAK diubah; yang dijalankan adalah SALINAN di
#   D:\RM_rerun\kode_salinan\ dengan path diganti (lihat New-SalinanSkrip).

$RM        = 'D:\RM'
$RR        = 'D:\RM_rerun'
$RRData    = 'D:\RM_rerun\data'
$RMData    = 'D:\RM\data'
$Starter   = 'D:\RM\usb-forensics-starter\usb-forensics-starter'
$Venv311   = 'D:\RM\usb-forensics-starter\usb-forensics-starter\.venv311'
$TskBin    = 'D:\tools\sleuthkit-4.14.0-win32\bin'
$ImgPC     = 'D:\RM\cfreds_2015_data_leakage_pc.7z\cfreds_2015_data_leakage_pc.dd'
$ImgRM2    = 'D:\RM\cfreds_2015_data_leakage_rm#2\cfreds_2015_data_leakage_rm#2.dd'
$SeedDir   = 'D:\RM\cfreds_2015_data_leakage_seed_files'
$Unduhan   = 'D:\RM\02_unduhan_asli'
$P2        = 'D:\RM\04_percobaan2_host_only'
$RRP2      = 'D:\RM_rerun\percobaan2'
$KodeSalin = 'D:\RM_rerun\kode_salinan'
$Py314     = 'C:\Python314\python.exe'          # dari: py -0p  (-V:3.14 * C:\Python314\python.exe)
$Py314Ver  = 'Python 3.14.4'                    # dari: manifest.txt bagian 1 dan bagian 7

# Jangan tulis __pycache__ ke folder kode asli saat menjalankan skrip dari sana.
$env:PYTHONDONTWRITEBYTECODE = '1'
# Output Python ke konsol/transcript sebagai UTF-8 (nama file NIST ada yang non-ASCII).
$env:PYTHONIOENCODING = 'utf-8'

function Assert-File([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Prasyarat tidak ada (file): $Path" }
}

function Assert-Dir([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Prasyarat tidak ada (folder): $Path" }
}

# Folder output harus belum ada atau kosong, supaya hasil rerun tidak tercampur.
function Assert-EmptyOrMissing([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        $isi = Get-ChildItem -LiteralPath $Path -Force | Select-Object -First 1
        if ($isi) { throw "Folder output sudah berisi file: $Path  (hapus/ganti nama dulu kalau mau ulang)" }
    }
}

# Pengaman: jangan pernah menulis ke D:\RM
function Assert-OutputPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith('D:\RM_rerun', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Output harus di bawah D:\RM_rerun, bukan: $full"
    }
}

function Assert-Python314 {
    Assert-File $Py314
    $v = (& $Py314 --version 2>&1 | Out-String).Trim()
    Write-Host "Interpreter: $Py314 -> $v"
    if ($v -ne $Py314Ver) {
        Write-Warning "Versi Python berbeda dari aslinya ($Py314Ver). Hasil mungkin tetap sama, tapi catat ini."
    }
}

# Jalankan program native, tampilkan stdout+stderr (masuk transcript), lempar error kalau exit code != 0.
# Mengembalikan semua baris output sebagai array string.
function Invoke-Native {
    param([Parameter(Mandatory)][string]$Exe, [string[]]$ArgList = @(), [int[]]$OkCodes = @(0))
    Write-Host ">> $Exe $($ArgList -join ' ')"
    $lines = New-Object System.Collections.Generic.List[string]
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe @ArgList 2>&1 | ForEach-Object { $s = "$_"; $lines.Add($s); Write-Host $s }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $old
    }
    if ($OkCodes -notcontains $code) { throw "$Exe selesai dengan exit code $code" }
    return $lines.ToArray()
}

# Salin skrip asli ke D:\RM_rerun\kode_salinan lalu ganti teks tertentu.
# Setiap penggantian harus cocok TEPAT satu kali; kalau tidak, berhenti.
# $Replacements = @( @('teks lama','teks baru'), ... )
function New-SalinanSkrip {
    param([string]$Source, [object[]]$Replacements, [switch]$DropFirstLineIfSlashComment)
    Assert-File $Source
    New-Item -ItemType Directory -Force $KodeSalin | Out-Null
    $dest = Join-Path $KodeSalin (Split-Path $Source -Leaf)
    $text = [IO.File]::ReadAllText($Source)
    if ($DropFirstLineIfSlashComment -and $text.StartsWith('//')) {
        $nl = $text.IndexOf("`n")
        Write-Host "Salinan: baris 1 dibuang (komentar '//' bukan sintaks Python): $($text.Substring(0,$nl).Trim())"
        $text = $text.Substring($nl + 1)
    }
    foreach ($r in $Replacements) {
        $n = ([regex]::Matches($text, [regex]::Escape($r[0]))).Count
        if ($n -ne 1) { throw "Penggantian '$($r[0])' ditemukan $n kali di $Source (harus 1)" }
        $text = $text.Replace($r[0], $r[1])
        Write-Host "Salinan: '$($r[0])'  ->  '$($r[1])'"
    }
    [IO.File]::WriteAllText($dest, $text, (New-Object Text.UTF8Encoding($false)))
    Write-Host "Salinan ditulis: $dest  (asli tidak diubah: $Source)"
    return $dest
}

function Write-Judul([string]$t) {
    Write-Host ""
    Write-Host ("=" * 70)
    Write-Host $t
    Write-Host ("=" * 70)
}
