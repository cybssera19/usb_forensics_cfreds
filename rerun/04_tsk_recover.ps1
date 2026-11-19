# 04_tsk_recover.ps1 - TAHAP 4: ekspor file (allocated + unallocated) + audit RM#2 vs seed
# Panduan Teknis poin 3 ("tsk_recover -e ...", "tandai file yang utuh")
# Interpreter: Sleuth Kit 4.14.0; audit pakai PowerShell Get-FileHash
# Input : image asli (read-only), seed files asli
# Output: D:\RM_rerun\data\exports\usb02\  (acuan: 41 file)
#         D:\RM_rerun\data\exports\pc\     (acuan: tsk_recover lapor 80.927; 80.778 ada di disk)
#         D:\RM_rerun\data\exports\usb02-list.txt, usb02-vs-seed.txt
#         D:\RM_rerun\data\labels\usb02_vs_seed.csv
# Sumber: history baris 434-436 (mkdir; tsk_recover -e -o 128 ...; tsk_recover -e -o 206848 ...),
#         445 (usb02-list.txt), 446-452 (usb02-vs-seed.txt), 464-475 (usb02_vs_seed.csv)
# Waktu : RM#2 beberapa detik. PC +- 9 menit (jam tulis file ekspor asli 11:28:32 -> 11:37:00), 21 GB.
# Catatan: 4 file cache IE gagal diekspor karena path > 260 karakter (manifest.txt bagian 5).
#          Path rerun 6 karakter lebih panjang; path terpanjang di ekspor asli 241 -> 247, masih aman.
param([switch]$LewatiPC)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force 'D:\RM_rerun\logs' | Out-Null
Start-Transcript -Path 'D:\RM_rerun\logs\04_tsk_recover.log' -Append
try {
    . "$PSScriptRoot\_common.ps1"
    Assert-File $ImgPC
    Assert-File $ImgRM2
    Assert-Dir $SeedDir
    Assert-File (Join-Path $TskBin 'tsk_recover.exe')
    $env:Path += ";$TskBin"
    $usbOut = Join-Path $RRData 'exports\usb02'
    $pcOut  = Join-Path $RRData 'exports\pc'
    Assert-OutputPath $usbOut
    Assert-EmptyOrMissing $usbOut
    if (-not $LewatiPC) {
        Assert-EmptyOrMissing $pcOut
        $free = (Get-PSDrive D).Free / 1GB
        Write-Host ("Ruang kosong D: {0:N1} GB (ekspor PC butuh +- 21 GB)" -f $free)
        if ($free -lt 25) { throw "Ruang kosong D: kurang dari 25 GB" }
    }
    New-Item -ItemType Directory -Force $usbOut, $pcOut | Out-Null

    Write-Judul "tsk_recover RM#2 (offset 128)"
    $t0 = Get-Date
    Invoke-Native 'tsk_recover' @('-e', '-o', '128', $ImgRM2, $usbOut) | Out-Null
    $nUsb = @(Get-ChildItem -LiteralPath $usbOut -Recurse -File -Force).Count
    Write-Host ("RM#2: {0} file di disk (acuan 41), {1:N0} detik" -f $nUsb, ((Get-Date) - $t0).TotalSeconds)

    if (-not $LewatiPC) {
        Write-Judul "tsk_recover PC (offset 206848)  -- LAMA, +- 9 menit"
        $t0 = Get-Date
        # tsk_recover memberi peringatan untuk path yang terlalu panjang; itu bukan kegagalan total.
        # Exit code 1 diterima (diduga muncul kalau ada file yang gagal ditulis); baca baris
        # "Files Recovered" dan pesan error di log untuk memastikan.
        $lines = Invoke-Native 'tsk_recover' @('-e', '-o', '206848', $ImgPC, $pcOut) -OkCodes @(0, 1)
        $lines | Where-Object { $_ -match 'Files Recovered|rror' } | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" }
        $nPc = @(Get-ChildItem -LiteralPath $pcOut -Recurse -File -Force -ErrorAction SilentlyContinue).Count
        Write-Host ("PC: {0} file di disk (acuan 80778; tsk_recover lapor 80927), {1:N1} menit" -f $nPc, ((Get-Date) - $t0).TotalMinutes)
    }

    Write-Judul "Audit ekspor RM#2"
    # history 445
    Get-ChildItem -Path $usbOut -Recurse -File | Select-Object FullName, Length | Format-Table -AutoSize |
        Out-File (Join-Path $RRData 'exports\usb02-list.txt')
    # history 446-452 (path prefix diganti ke folder rerun)
    $usb  = Get-ChildItem $usbOut -Recurse -File | Get-FileHash -Algorithm SHA256
    $seed = Get-ChildItem $SeedDir -Recurse -File | Get-FileHash -Algorithm SHA256
    $usb | ForEach-Object {
        $h = $_.Hash
        $m = $seed | Where-Object Hash -eq $h
        [pscustomobject]@{ FileUSB = $_.Path.Replace("$usbOut\", ''); CocokSeed = if ($m) { $m[0].Path.Replace("$SeedDir\", '') } else { '-' } }
    } | Format-Table -AutoSize | Out-File (Join-Path $RRData 'exports\usb02-vs-seed.txt')
    # history 464-475
    New-Item -ItemType Directory -Force (Join-Path $RRData 'labels') | Out-Null
    $rows = $usb | ForEach-Object {
        $h = $_.Hash
        $m = $seed | Where-Object Hash -eq $h
        [pscustomobject]@{
            file_usb  = $_.Path.Replace("$usbOut\", '')
            sha256    = $h
            seed_path = if ($m) { $m[0].Path.Replace("$SeedDir\", '') } else { '' }
        }
    }
    $rows | Export-Csv (Join-Path $RRData 'labels\usb02_vs_seed.csv') -NoTypeInformation -Encoding UTF8
    $cocok = @($rows | Where-Object seed_path).Count
    Write-Host "File RM#2 yang SHA-256-nya ada di seed: $cocok / $(@($rows).Count)   (acuan: 17 / 41, data\labels\usb02_vs_seed.csv asli)"
    Write-Host "`nSELESAI 04_tsk_recover."
} finally {
    Stop-Transcript
}
