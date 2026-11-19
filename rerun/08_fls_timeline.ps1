# 08_fls_timeline.ps1 - TAHAP 8: timeline MACB (fls -m -> body2csv.py) RM#2 dan PC
# Panduan Teknis poin 5 (metadata filesystem) dan poin 6 (NTFS = UTC, FAT = waktu lokal)
# Interpreter: Sleuth Kit 4.14.0 + Python 3.14 (body2csv.py asli dipanggil dengan path; skrip tidak diubah)
# Folder kerja: D:\RM_rerun\data\metadata (aslinya D:\RM\data\metadata)
# Input : image asli (read-only); D:\RM_rerun\data\exports\pc\Windows\inf\setupapi.dev.log (tahap 4)
# Output: usb02_body.txt, usb02_timeline.csv, pc_body.txt (38 MB), pc_timeline.csv (126 MB), pc_0935_1015.txt
# Sumber: history baris 513-522
#   RM#2 : cmd /c 'fls -r -m "USB02/" -z UTC0 -o 128 "<rm#2.dd>" > usb02_body.txt'
#   PC   : cmd /c 'fls -r -m "C:/" -o 206848 "<pc.dd>" > pc_body.txt'     <- TANPA -z (NTFS sudah UTC)
#   cmd /c dipakai supaya redirect menulis byte apa adanya (PowerShell 5.1 ">" menulis UTF-16).
#   setupapi : history baris 523 (Select-String ... "Device Install.*USBSTOR" -Context 0,1)
#   Eksplorasi lain (history 507, 508-511, 512) tidak menghasilkan file; dicatat di COMMANDS.md saja.
# Waktu : fls PC beberapa menit; body2csv PC +- 1 menit (126 MB CSV).
# Acuan : 17 file target lahir (B) 09:59:27 - 10:00:18 EDT, 24 Mar 2015 (dicek di verify.ps1)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force 'D:\RM_rerun\logs' | Out-Null
Start-Transcript -Path 'D:\RM_rerun\logs\08_fls_timeline.log' -Append
try {
    . "$PSScriptRoot\_common.ps1"
    Assert-Python314
    Assert-File $ImgPC
    Assert-File $ImgRM2
    Assert-File (Join-Path $TskBin 'fls.exe')
    $body2csv = Join-Path $RMData 'metadata\body2csv.py'
    Assert-File $body2csv
    $env:Path += ";$TskBin"
    $md = Join-Path $RRData 'metadata'
    Assert-OutputPath $md
    Assert-EmptyOrMissing $md
    New-Item -ItemType Directory -Force $md | Out-Null

    Push-Location $md
    try {
        Write-Judul "fls RM#2 (FAT32, -z UTC0)"
        Invoke-Native 'cmd' @('/c', "fls -r -m `"USB02/`" -z UTC0 -o 128 `"$ImgRM2`" > usb02_body.txt") | Out-Null
        Invoke-Native $Py314 @($body2csv, 'usb02_body.txt', 'usb02_timeline.csv', 'fat') | Out-Null

        Write-Judul "fls PC (NTFS, tanpa -z)  -- beberapa menit"
        Invoke-Native 'cmd' @('/c', "fls -r -m `"C:/`" -o 206848 `"$ImgPC`" > pc_body.txt") | Out-Null
        Invoke-Native $Py314 @($body2csv, 'pc_body.txt', 'pc_timeline.csv', 'ntfs') | Out-Null

        Write-Judul "Potongan timeline PC 09:35-10:15 EDT (history 522)"
        Import-Csv pc_timeline.csv | Where-Object { $_.eastern_edt -ge "2015-03-24 09:35" -and $_.eastern_edt -le "2015-03-24 10:15" } |
            Format-Table eastern_edt, jenis, path -AutoSize | Out-File pc_0935_1015.txt -Width 400

        Write-Judul "Waktu lahir/ubah file RM#2 (history 519)"
        Import-Csv usb02_timeline.csv | Where-Object { $_.jenis -in "B", "M" } | Sort-Object path, jenis |
            Format-Table eastern_edt, jenis, path -AutoSize | Out-String -Width 250 | Write-Host
    } finally {
        Pop-Location
    }

    Write-Judul "setupapi.dev.log: pemasangan USBSTOR (history 523)"
    $sa = Join-Path $RRData 'exports\pc\Windows\inf\setupapi.dev.log'
    if (Test-Path $sa) {
        Select-String -Path $sa -Pattern "Device Install.*USBSTOR" -Context 0, 1 | Out-String -Width 300 | Write-Host
    } else { Write-Warning "Belum ada $sa (jalankan 04 dulu)" }
    Write-Host "`nSELESAI 08. Output: $md"
} finally {
    Stop-Transcript
}
