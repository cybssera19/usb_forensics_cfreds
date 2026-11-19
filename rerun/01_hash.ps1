# 01_hash.ps1 - TAHAP 1: verifikasi SHA-1 6 arsip NIST + SHA-1/SHA-256 image .dd
# Panduan Teknis poin 2-3 ("Unduh melalui halaman resmi NIST", "Catat checksum image")
# Interpreter: PowerShell (Get-FileHash). Tidak pakai Python.
# Input : D:\RM\02_unduhan_asli\cfreds_* (arsip dipindah ke sini oleh rapikan_RM.ps1; aslinya di D:\RM\)
#         D:\RM\cfreds_2015_data_leakage_pc.7z\...pc.dd, D:\RM\cfreds_2015_data_leakage_rm#2\...rm#2.dd
# Output: D:\RM_rerun\hash\arsip_sha1.txt|.csv, image_sha1.txt, image_sha256.txt, image_hash.csv
# Sumber command: history baris 416, 418, 419 (Get-FileHash ... | Format-Table Hash, Path -AutoSize | Out-File)
# Perkiraan waktu: arsip ~5,5 GB + image ~21 GB dua kali. Dari jam tulis file hash asli
#   (hash-sha1 11:10:29 -> hash-image 11:12:55 -> hash-image-sha256 11:14:34) image ~2-3 menit per algoritma.
#   Pakai -TanpaImage untuk melewati image.
param([switch]$TanpaImage)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force 'D:\RM_rerun\logs' | Out-Null
Start-Transcript -Path 'D:\RM_rerun\logs\01_hash.log' -Append
try {
    . "$PSScriptRoot\_common.ps1"
    $out = Join-Path $RR 'hash'
    New-Item -ItemType Directory -Force $out | Out-Null

    # Nilai acuan: manifest.txt bagian 2 ("Hasil: SEMUA COCOK" dengan hash resmi NIST,
    # https://cfreds-archive.nist.gov/data_leakage_case/hash_values.html)
    $nist = [ordered]@{
        'cfreds_2015_data_leakage_pc.7z.001'     = 'F07632FAA66A47088DEB07BDB45CC568E4BF650B'
        'cfreds_2015_data_leakage_pc.7z.002'     = '5DEE46ABF6FA833268E5AE199A13854CCF42689B'
        'cfreds_2015_data_leakage_pc.7z.003'     = '1687686F819092E05047F195F102D8FA0C38ED66'
        'cfreds_2015_data_leakage_rm#1.E01'      = 'FFD0F3CBA3DFE3291F786B845A06A8AA56C1CD8C'
        'cfreds_2015_data_leakage_rm#2.7z'       = 'DDFE97AA3D8D0B33CC6092123090A8154945F38E'
        'cfreds_2015_data_leakage_seed_files.7z' = 'E79C8C245F990EA8E79D9A099B0AA7A1E78EC0DE'
    }
    foreach ($n in $nist.Keys) { Assert-File (Join-Path $Unduhan $n) }

    Write-Judul "SHA-1 arsip unduhan (6 file)"
    # setara history baris 416, tapi folder sumber sekarang 02_unduhan_asli
    $h = Get-ChildItem -Path $Unduhan -File -Filter "cfreds*" | Get-FileHash -Algorithm SHA1
    $h | Format-Table Hash, Path -AutoSize | Out-File (Join-Path $out 'arsip_sha1.txt') -Width 300
    $rows = foreach ($x in $h) {
        $name = Split-Path $x.Path -Leaf
        [pscustomobject]@{ file = $name; sha1 = $x.Hash; nist = $nist[$name]; cocok = ($x.Hash -eq $nist[$name]) }
    }
    $rows | Export-Csv (Join-Path $out 'arsip_sha1.csv') -NoTypeInformation -Encoding UTF8
    $rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    $ok = @($rows | Where-Object cocok).Count
    Write-Host "COCOK dengan NIST: $ok / $($nist.Count)   (acuan: 6/6)"
    if ($ok -ne 6) { Write-Warning "Ada arsip yang tidak cocok dengan hash NIST!" }

    if (-not $TanpaImage) {
        Assert-File $ImgPC
        Assert-File $ImgRM2
        # acuan: manifest.txt bagian 3
        $acuan = @{
            'cfreds_2015_data_leakage_pc.dd|SHA1'     = 'AFE5C9AB487BD47A8A9856B1371C2384D44FD785'
            'cfreds_2015_data_leakage_pc.dd|SHA256'   = '026C143638295DB1FBFA598C5B35BCAC4860BA73EC5DA1CC87B67AFD598BE4E2'
            'cfreds_2015_data_leakage_rm#2.dd|SHA1'   = '048961A85CA3ECED8CC73F1517442D31D4DCA0A3'
            'cfreds_2015_data_leakage_rm#2.dd|SHA256' = 'D930AFA23F8905E88A28041786EDBE3791B5BF41B01468027EE27A19CD59D407'
        }
        $all = @()
        foreach ($alg in 'SHA1', 'SHA256') {
            Write-Judul "$alg image .dd (lama)"
            # sumber: history baris 418 (SHA1) dan 419 (SHA256). Folder image sama dengan aslinya.
            $hi = Get-ChildItem -Path "D:\RM\cfreds_2015_data_leakage_pc.7z", "D:\RM\cfreds_2015_data_leakage_rm#2" -File -Recurse | Get-FileHash -Algorithm $alg
            $hi | Format-Table Hash, Path -AutoSize | Out-File (Join-Path $out ("image_" + $alg.ToLower() + ".txt")) -Width 300
            foreach ($x in $hi) {
                $name = Split-Path $x.Path -Leaf
                $key = "$name|$alg"
                $all += [pscustomobject]@{ file = $name; alg = $alg; hash = $x.Hash; acuan = $acuan[$key]; cocok = ($x.Hash -eq $acuan[$key]) }
            }
        }
        $all | Export-Csv (Join-Path $out 'image_hash.csv') -NoTypeInformation -Encoding UTF8
        $all | Format-Table -AutoSize | Out-String -Width 250 | Write-Host
        Write-Host "Catatan: NIST tidak mempublikasikan hash .dd; acuannya hash yang dicatat 20 Okt 2026 (manifest.txt bagian 3)."
    }
    Write-Host "`nSELESAI 01_hash. Output: $out"
} finally {
    Stop-Transcript
}
