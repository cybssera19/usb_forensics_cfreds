# 05_uji_dosen.ps1 - TAHAP 5: uji kode dosen (unittest + demo)
# Panduan Teknis bagian penutup ("Untuk mencoba sekarang ... python3 -m unittest -v ; python3 demo.py --out demo-baru")
# Interpreter: Python 3.14 (C:\Python314\python.exe). Kode dosen TIDAK diubah.
# Folder kerja: D:\RM\usb-forensics-starter\usb-forensics-starter (unittest mencari test_*.py di folder kerja)
# Output: D:\RM_rerun\demo-baru\  (aslinya: <folder kode>\demo-baru)
# Sumber: history baris 438-440 (cd ...; python -m unittest -v; python demo.py --out demo-baru)
# Acuan : 15/15 tes lulus (manifest.txt bagian 7)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force 'D:\RM_rerun\logs' | Out-Null
Start-Transcript -Path 'D:\RM_rerun\logs\05_uji_dosen.log' -Append
try {
    . "$PSScriptRoot\_common.ps1"
    Assert-Python314
    Assert-File (Join-Path $Starter 'test_usb_forensics.py')
    Assert-File (Join-Path $Starter 'demo.py')
    $demoOut = Join-Path $RR 'demo-baru'
    Assert-OutputPath $demoOut
    Assert-EmptyOrMissing $demoOut

    Push-Location $Starter
    try {
        Write-Judul "python -m unittest -v"
        $u = Invoke-Native $Py314 @('-m', 'unittest', '-v')
        $ran = ($u | Select-String -Pattern '^Ran (\d+) test').Matches | ForEach-Object { $_.Groups[1].Value }
        $ok  = [bool]($u | Where-Object { $_ -match '^OK' })
        Write-Host "Ran $ran tests, OK=$ok   (acuan: 15/15 lulus)"

        Write-Judul "python demo.py --out $demoOut"
        Invoke-Native $Py314 @('demo.py', '--out', $demoOut) | Out-Null
    } finally {
        Pop-Location
    }

    Write-Judul "Bandingkan demo-baru rerun dengan demo-baru asli"
    $asli = Join-Path $Starter 'demo-baru'
    foreach ($f in Get-ChildItem $asli -File -Recurse) {
        $rel = $f.FullName.Substring($asli.Length + 1)
        $b = Join-Path $demoOut $rel
        if (-not (Test-Path -LiteralPath $b)) { Write-Host "TIDAK ADA  $rel"; continue }
        $s = if ((Get-FileHash -LiteralPath $f.FullName).Hash -eq (Get-FileHash -LiteralPath $b).Hash) { 'SAMA' } else { 'BEDA' }
        Write-Host "$s  $rel"
    }
    Write-Host "`nSELESAI 05_uji_dosen. Catatan: hasil demo = data sintetis, bukan temuan penelitian."
} finally {
    Stop-Transcript
}
