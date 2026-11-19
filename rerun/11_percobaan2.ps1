# 11_percobaan2.ps1 - TAHAP 11: Percobaan 2 (PC saja): analyze_cfreds.py + masking_path_b.py (30 dan 1000 seed)
# Panduan Teknis poin 5 (artefak Windows) dan poin 7 (uji kehilangan bukti); pendukung, bukan inti paper.
# Interpreter: Python 3.14 untuk analyze/masking (stdlib saja; history 607 memakai "python" = 3.14.4).
#              Dissect percobaan 2 aslinya Python 3.12 di akun Windows labsUSB  -> [PERLU DARI AKUN labsUSB]
# Folder kerja: D:\RM\04_percobaan2_host_only
# Input : D:\RM\04_percobaan2_host_only\input_dissect\ (asli, read-only), ground_truth\truth_cfreds.json
# Output: D:\RM_rerun\percobaan2\
#           analyze_input_dissect.txt          (TODO 2a: input apa adanya)
#           input_lnk_pcrun2\ + analyze_lnk_pcrun2.txt   (TODO 2b: lnk.jsonl diganti output Dissect pc-run2)
#           hasil\30seed\, hasil\1000seed\, hasil\path_b_*_{30,1000}seed.*
#           (opsional -Dissect312) input_dissect_312\
# Sumber:
#   analyze  : history 606-607 (cd D:\RM\04_percobaan2_host_only ; python kode\analyze_cfreds.py --dir input_dissect --truth ground_truth\truth_cfreds.json)
#   masking  : 00_BACA_DULU.md (python kode\masking_path_b.py input_dissect kode\analyze_cfreds.py ground_truth\truth_cfreds.json hasil\ulang 30)
#              + usage masking_path_b.py baris 19 dan 26-27 (argumen ke-5 = jumlah seed)
#   rename *_30seed/*_1000seed : [REKONSTRUKSI] tidak ada command; masking_path_b.py baris 125 dan 140 selalu menulis
#              path_b_experiments.csv dan path_b_summary.json, jadi nama berakhiran _Nseed pasti hasil ganti nama manual.
# Waktu : analyze detik. Masking 30 seed = 125 run; 1000 seed = 4005 run (+- 32x lebih lama). Durasi asli tidak tercatat.
# Acuan : Record mentah 744 (usn 327, shellbag 125, jumplist 85, lnk 207); reference 6/6 benar;
#         akurasi (benar/6) acak 10/30/50/70% = 1.00/0.90/0.67/0.34 (30 seed); 1000 seed = 0.99/0.88/0.63/0.37
param([switch]$Lewati1000, [switch]$Dissect312, [string]$Venv312 = '')

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force 'D:\RM_rerun\logs' | Out-Null
Start-Transcript -Path 'D:\RM_rerun\logs\11_percobaan2.log' -Append
try {
    . "$PSScriptRoot\_common.ps1"
    Assert-Python314
    $inDir  = Join-Path $P2 'input_dissect'
    $truth  = Join-Path $P2 'ground_truth\truth_cfreds.json'
    $acf    = Join-Path $P2 'kode\analyze_cfreds.py'
    $mpb    = Join-Path $P2 'kode\masking_path_b.py'
    foreach ($f in 'usn_filtered.jsonl', 'shellbags.jsonl', 'jumplist.jsonl', 'lnk.jsonl') { Assert-File (Join-Path $inDir $f) }
    Assert-File $truth; Assert-File $acf; Assert-File $mpb
    Assert-OutputPath $RRP2
    Assert-EmptyOrMissing $RRP2
    New-Item -ItemType Directory -Force $RRP2 | Out-Null
    if (Test-Path (Join-Path $inDir 'lnk_paste.json')) {
        Write-Warning "input_dissect\lnk_paste.json ADA - analyze_cfreds.py (baris 84-87) akan ikut membacanya!"
    }

    # ---------- (opsional) Dissect Python 3.12 - [PERLU DARI AKUN labsUSB] ----------
    if ($Dissect312) {
        Write-Judul "[REKONSTRUKSI] Dissect Python 3.12 -> input_dissect_312"
        # Dasar rekonstruksi:
        #  - nama plugin dari recorddescriptor di file input asli: windows/registry/usb (usb), windows/filesystem/lnk (lnk),
        #    windows/jumplist (jumplist), windows/shellbag (shellbags; ada di daftar plugin pc-run2\plugins.jsonl)
        #  - semua file input asli diawali BOM UTF-8 -> ditulis lewat PowerShell "Out-File -Encoding utf8"
        #  - usn_filtered.jsonl: 327 record, baris terpotong (analyze_cfreds.py baris 16: "sambung baris yang terpotong
        #    oleh Out-File/Select-String") -> dibuat dengan "target-query -f usnjrnl -j | Select-String <pola> | Out-File".
        #    POLA FILTERNYA TIDAK DIKETAHUI -> tidak direkonstruksi.  [PERLU DARI AKUN labsUSB]
        #  - setupapi.dev.log: SHA-256 identik dengan ekspor tsk_recover (Windows\inf\setupapi.dev.log); cara ambilnya
        #    di akun labsUSB tidak tercatat.  [PERLU DARI AKUN labsUSB]
        if (-not $Venv312) { throw "Isi -Venv312 <folder venv Python 3.12 yang sudah berisi dissect>" }
        $tq = Join-Path $Venv312 'Scripts\target-query.exe'
        Assert-File $tq
        Assert-File $ImgPC
        $o312 = Join-Path $RRP2 'input_dissect_312'
        New-Item -ItemType Directory -Force $o312 | Out-Null
        & (Join-Path $Venv312 'Scripts\python.exe') --version
        foreach ($p in @(@('usb', 'usb_registry.jsonl'), @('lnk', 'lnk.jsonl'), @('jumplist', 'jumplist.jsonl'), @('shellbags', 'shellbags.jsonl'))) {
            Write-Host ">> target-query <pc.dd> -f $($p[0]) -j | Out-File $($p[1]) -Encoding utf8"
            & $tq $ImgPC -f $p[0] -j | Out-File (Join-Path $o312 $p[1]) -Encoding utf8
            if ($LASTEXITCODE -ne 0) { throw "target-query -f $($p[0]) gagal ($LASTEXITCODE)" }
            $n = @(Select-String -Path (Join-Path $o312 $p[1]) -Pattern '"_type": "record"' -SimpleMatch:$false).Count
            Write-Host "   record: $n"
        }
        Write-Host "usn_filtered.jsonl dan setupapi.dev.log TIDAK dibuat (lihat catatan di atas)."
    }

    Push-Location $P2
    try {
        Write-Judul "TODO 2a: analyze_cfreds.py pada input_dissect apa adanya (history 607)"
        $a1 = Invoke-Native $Py314 @('kode\analyze_cfreds.py', '--dir', 'input_dissect', '--truth', 'ground_truth\truth_cfreds.json')
        $a1 | Out-File (Join-Path $RRP2 'analyze_input_dissect.txt') -Encoding utf8
        $nl = @(Select-String -Path (Join-Path $inDir 'lnk.jsonl') -Pattern '"_type": "record"').Count
        Write-Host "lnk.jsonl di input_dissect: $nl record (SHA-256 $((Get-FileHash (Join-Path $inDir 'lnk.jsonl')).Hash))"

        Write-Judul "TODO 2b: analyze_cfreds.py dengan lnk.jsonl = output Dissect asli pc-run2 (artifact-2.jsonl)"
        # [REKONSTRUKSI] Variasi ini belum pernah dijalankan. Tujuannya memastikan hasil tidak bergantung pada
        # salinan LNK dari chat. usn/shellbag/jumplist tetap dari input_dissect (disalin, bukan dipindah).
        $alt = Join-Path $RRP2 'input_lnk_pcrun2'
        New-Item -ItemType Directory -Force $alt | Out-Null
        foreach ($f in 'usn_filtered.jsonl', 'shellbags.jsonl', 'jumplist.jsonl') { Copy-Item (Join-Path $inDir $f) $alt }
        $lnkAsli = Join-Path $RMData 'artifacts\pc-run2\artifact-2.jsonl'
        Assert-File $lnkAsli
        Copy-Item $lnkAsli (Join-Path $alt 'lnk.jsonl')
        $a2 = Invoke-Native $Py314 @('kode\analyze_cfreds.py', '--dir', $alt, '--truth', 'ground_truth\truth_cfreds.json')
        $a2 | Out-File (Join-Path $RRP2 'analyze_lnk_pcrun2.txt') -Encoding utf8
        $d = Compare-Object $a1 $a2
        Write-Host "Output 2a vs 2b: $(if (-not $d) {'SAMA'} else {'BEDA - lihat di bawah'})"
        if ($d) { $d | Format-Table -AutoSize -Wrap | Out-String -Width 250 | Write-Host }

        $seedRuns = @(30)
        if (-not $Lewati1000) { $seedRuns += 1000 }
        foreach ($n in $seedRuns) {
            Write-Judul "masking_path_b.py $n seed"
            $o = Join-Path $RRP2 "hasil\${n}seed"
            $t0 = Get-Date
            Invoke-Native $Py314 @('kode\masking_path_b.py', 'input_dissect', 'kode\analyze_cfreds.py', 'ground_truth\truth_cfreds.json', $o, "$n") | Out-Null
            Write-Host ("Selesai dalam {0:N1} menit" -f ((Get-Date) - $t0).TotalMinutes)
            # [REKONSTRUKSI] penamaan seperti file di 04_percobaan2_host_only\hasil\
            Copy-Item (Join-Path $o 'path_b_experiments.csv') (Join-Path $RRP2 "hasil\path_b_experiments_${n}seed.csv")
            Copy-Item (Join-Path $o 'path_b_summary.json')    (Join-Path $RRP2 "hasil\path_b_summary_${n}seed.json")
        }
    } finally { Pop-Location }
    Write-Host "`nSELESAI 11. Jalankan verify.ps1."
} finally {
    Stop-Transcript
}
