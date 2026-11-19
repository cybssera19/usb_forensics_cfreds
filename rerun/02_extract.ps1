# 02_extract.ps1 - TAHAP 2: ekstrak arsip NIST  [SETARA, ASLINYA GUI]
# Panduan Teknis poin 3 ("sesuaikan dengan hasil ekstraksi arsip")
# Aslinya: WinRAR 7.13 lewat GUI ("Extract to <nama folder>"), 20 Okt 2026. Tidak ada command yang tercatat.
# Di sini: command-line WinRAR (default) atau 7-Zip 25.01 (-Alat 7zip). Keduanya terpasang di laptop ini.
# Input : D:\RM\02_unduhan_asli\cfreds_2015_data_leakage_{pc.7z.001, rm#2.7z, seed_files.7z}
# Output: D:\RM_rerun\extract\<nama folder sama dengan aslinya>\
# Disk  : butuh +- 25 GB kosong (pc.dd 20 GB + rm#2.dd 3,7 GB + seed 150 MB).
# Langkah ini OPSIONAL. Tahap 3 dst. membaca image asli (read-only); tahap ini hanya membuktikan
# bahwa ekstraksi ulang menghasilkan image dengan hash yang sama.
param([ValidateSet('WinRAR', '7zip')][string]$Alat = 'WinRAR')

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force 'D:\RM_rerun\logs' | Out-Null
Start-Transcript -Path 'D:\RM_rerun\logs\02_extract.log' -Append
try {
    . "$PSScriptRoot\_common.ps1"
    $dst = Join-Path $RR 'extract'
    Assert-OutputPath $dst
    Assert-EmptyOrMissing $dst
    $free = (Get-PSDrive D).Free / 1GB
    Write-Host ("Ruang kosong D: {0:N1} GB" -f $free)
    if ($free -lt 30) { throw "Ruang kosong D: kurang dari 30 GB" }

    $jobs = @(
        @{ arc = 'cfreds_2015_data_leakage_pc.7z.001';    folder = 'cfreds_2015_data_leakage_pc.7z' },
        @{ arc = 'cfreds_2015_data_leakage_rm#2.7z';      folder = 'cfreds_2015_data_leakage_rm#2' },
        @{ arc = 'cfreds_2015_data_leakage_seed_files.7z'; folder = 'cfreds_2015_data_leakage_seed_files' }
    )
    foreach ($j in $jobs) {
        $arc = Join-Path $Unduhan $j.arc
        Assert-File $arc
        $target = Join-Path $dst $j.folder
        New-Item -ItemType Directory -Force $target | Out-Null
        Write-Judul "Ekstrak $($j.arc) -> $target  ($Alat)"
        if ($Alat -eq 'WinRAR') {
            # WinRAR.exe x = extract with full paths; -ibck = jalan di latar; -y = jawab ya.
            # Folder tujuan diakhiri "\" dan sengaja TIDAK diberi tanda kutip (\" akan dibaca sebagai kutip ter-escape);
            # path tujuan ini tidak mengandung spasi.
            $exe = 'C:\Program Files\WinRAR\WinRAR.exe'
            Assert-File $exe
            if ($target -match ' ') { throw "Path tujuan mengandung spasi: $target" }
            $p = Start-Process -FilePath $exe -ArgumentList @('x', '-ibck', '-y', "`"$arc`"", "$target\") -Wait -PassThru
        } else {
            $exe = 'C:\Program Files\7-Zip\7z.exe'
            Assert-File $exe
            $p = Start-Process -FilePath $exe -ArgumentList @('x', "`"$arc`"", "-o`"$target`"", '-y') -Wait -PassThru -NoNewWindow
        }
        Write-Host "exit code: $($p.ExitCode)"
        if ($p.ExitCode -ne 0) { throw "Ekstraksi gagal: $($j.arc)" }
    }

    Write-Judul "Bandingkan hash hasil ekstraksi ulang dengan image/seed asli"
    $cek = @(
        @{ baru = "$dst\cfreds_2015_data_leakage_pc.7z\cfreds_2015_data_leakage_pc.dd"; sha256 = '026C143638295DB1FBFA598C5B35BCAC4860BA73EC5DA1CC87B67AFD598BE4E2' },
        @{ baru = "$dst\cfreds_2015_data_leakage_rm#2\cfreds_2015_data_leakage_rm#2.dd"; sha256 = 'D930AFA23F8905E88A28041786EDBE3791B5BF41B01468027EE27A19CD59D407' }
    )
    foreach ($c in $cek) {
        Assert-File $c.baru
        $hb = (Get-FileHash -LiteralPath $c.baru -Algorithm SHA256).Hash
        Write-Host ("{0}  {1}  {2}" -f $(if ($hb -eq $c.sha256) { 'SAMA' } else { 'BEDA' }), $hb, $c.baru)
    }
    $seedBaru = Get-ChildItem "$dst\cfreds_2015_data_leakage_seed_files" -Recurse -File | Get-FileHash -Algorithm SHA256
    $seedAsli = Get-ChildItem $SeedDir -Recurse -File | Get-FileHash -Algorithm SHA256
    $a = $seedAsli | ForEach-Object { $_.Path.Substring($SeedDir.Length) + '|' + $_.Hash } | Sort-Object
    $b = $seedBaru | ForEach-Object { $_.Path.Substring("$dst\cfreds_2015_data_leakage_seed_files".Length) + '|' + $_.Hash } | Sort-Object
    $diff = Compare-Object $a $b
    Write-Host ("Seed files: {0} file asli, {1} file baru, selisih {2}  -> {3}" -f $a.Count, $b.Count, @($diff).Count, $(if (-not $diff) { 'SAMA' } else { 'BEDA' }))
    Write-Host "`nSELESAI 02_extract. Folder ini boleh dihapus setelah hash dicek (makan +- 25 GB)."
} finally {
    Stop-Transcript
}
