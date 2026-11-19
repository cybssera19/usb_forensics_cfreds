# verify.ps1 - bandingkan hasil rerun (D:\RM_rerun) dengan hasil asli (D:\RM\data, D:\RM\04_percobaan2_host_only)
# HANYA MEMBACA D:\RM. Menulis tabel ke D:\RM_rerun\logs\verify.txt dan verify.csv.
# Dua jenis cek:
#   (1) FILE  : hash SHA-256 file output. Status:
#                 SAMA           = byte identik
#                 SAMA*          = identik setelah path "D:\RM_rerun" dinormalisasi jadi "D:\RM"
#                                  (file yang menyimpan path input/output, mis. events_report.json, manifest.json)
#                 BEDA           = isi berbeda (lihat angka kunci; beberapa file memang berisi waktu proses)
#                 BELUM          = file rerun belum ada (tahapnya belum dijalankan)
#   (2) ANGKA : angka kunci paper dihitung dari file asli DAN file rerun, dibanding acuan.
# Jalankan kapan saja; tahap yang belum dijalankan muncul sebagai BELUM.
param([switch]$TanpaHitungEkspor)   # lewati penghitungan 80 ribu file ekspor PC (+- 1 menit per folder)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force 'D:\RM_rerun\logs' | Out-Null
Start-Transcript -Path 'D:\RM_rerun\logs\verify.log' -Append
try {
    . "$PSScriptRoot\_common.ps1"
    $rows = New-Object System.Collections.Generic.List[object]
    function Add-Row($tahap, $item, $acuan, $asli, $rerun, $status) {
        $rows.Add([pscustomobject]@{ tahap = $tahap; item = $item; acuan = "$acuan"; asli = "$asli"; rerun = "$rerun"; status = $status })
    }

    # ------------------------------------------------------------------ (1) FILE
    function Get-NormHash([string]$Path) {
        $text = [IO.File]::ReadAllText($Path)
        $text = $text.Replace('D:\\RM_rerun\\data', 'D:\\RM\\data').Replace('D:\RM_rerun\data', 'D:\RM\data')
        $text = $text.Replace('D:\\RM_rerun', 'D:\\RM').Replace('D:\RM_rerun', 'D:\RM')
        $sha = [Security.Cryptography.SHA256]::Create()
        return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    function Compare-OneFile($tahap, [string]$asli, [string]$baru, [string]$catatan = '') {
        $name = $baru.Replace('D:\RM_rerun\', '')
        if (-not (Test-Path -LiteralPath $asli)) { Add-Row $tahap $name '' 'tidak ada' '' 'TANPA PEMBANDING'; return }
        if (-not (Test-Path -LiteralPath $baru)) { Add-Row $tahap $name $catatan 'ada' '' 'BELUM'; return }
        $ha = (Get-FileHash -LiteralPath $asli -Algorithm SHA256).Hash
        $hb = (Get-FileHash -LiteralPath $baru -Algorithm SHA256).Hash
        if ($ha -eq $hb) { Add-Row $tahap $name $catatan $ha.Substring(0, 12) $hb.Substring(0, 12) 'SAMA'; return }
        $size = (Get-Item -LiteralPath $baru).Length
        if ($size -lt 60MB) {
            $na = Get-NormHash $asli; $nb = Get-NormHash $baru
            if ($na -eq $nb) { Add-Row $tahap $name $catatan $ha.Substring(0, 12) $hb.Substring(0, 12) 'SAMA*'; return }
        }
        Add-Row $tahap $name $catatan $ha.Substring(0, 12) $hb.Substring(0, 12) 'BEDA'
    }

    $dataFiles = @(
        @('04', 'labels\usb02_vs_seed.csv', ''),
        @('06', 'labels\rm2_labels.json', ''),
        @('06', 'normalized\usb02.json', ''),
        @('06', 'normalized\usb02_complete.json', ''),
        @('06', 'normalized\usb02_complete_check.json', 'berisi path input'),
        @('07', 'normalized\pc.json', ''),
        @('07', 'normalized\pc_filter_stats.json', 'berisi "seconds" -> wajar BEDA'),
        @('07', 'results\matches_pc_usb02.json', ''),
        @('08', 'metadata\usb02_body.txt', ''),
        @('08', 'metadata\usb02_timeline.csv', ''),
        @('08', 'metadata\pc_body.txt', ''),
        @('08', 'metadata\pc_timeline.csv', 'asli ditulis ulang 11:55, tak tercatat'),
        @('09', 'artifacts\pc-run2\version.jsonl', ''),
        @('09', 'artifacts\pc-run2\plugins.jsonl', ''),
        @('09', 'artifacts\pc-run2\artifact-0.jsonl', 'usb'),
        @('09', 'artifacts\pc-run2\artifact-1.jsonl', 'jumplist'),
        @('09', 'artifacts\pc-run2\artifact-2.jsonl', 'lnk'),
        @('09', 'artifacts\pc-run2\artifact-3.jsonl', 'usnjrnl 189 MB'),
        @('09', 'artifacts\pc-run2\artifact-4.jsonl', 'evtx'),
        @('09', 'artifacts\pc-run2\manifest.json', 'berisi path output'),
        @('09', 'artifacts\pc-run2\usn_0935_1015.jsonl', ''),
        @('10', 'normalized\events.json', ''),
        @('10', 'normalized\events_report.json', 'berisi path input'),
        @('10', 'normalized\device_inventory.json', ''),
        @('10', 'normalized\device_map.json', ''),
        @('10', 'labels\case_labels.json', ''),
        @('10', 'results\correlated.json', ''),
        @('10', 'results\eksperimen\baselines.json', ''),
        @('10', 'results\eksperimen\experiments.csv', ''),
        @('10', 'results\eksperimen\experiments_summary.json', 'sumber angka paper'),
        @('10', 'results\eksperimen\correlated_full.json', '')
    )
    Write-Judul "Membandingkan file (hash)"
    foreach ($f in $dataFiles) {
        Compare-OneFile $f[0] (Join-Path $RMData $f[1]) (Join-Path $RRData $f[1]) $f[2]
    }
    foreach ($f in 'path_b_summary_30seed.json', 'path_b_experiments_30seed.csv', 'path_b_summary_1000seed.json', 'path_b_experiments_1000seed.csv') {
        Compare-OneFile '11' (Join-Path $P2 "hasil\$f") (Join-Path $RRP2 "hasil\$f") ''
    }

    # ------------------------------------------------------------------ (2) ANGKA KUNCI
    Write-Judul "Menghitung angka kunci"
    function Read-Json([string]$p) { if (Test-Path -LiteralPath $p) { Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null } }
    function St($acuan, $nilai) { if ("$nilai" -eq '') { 'BELUM' } elseif ("$acuan" -eq "$nilai") { 'SAMA' } else { 'BEDA' } }
    function Add-Angka($tahap, $item, $acuan, $asli, $rerun) { Add-Row $tahap $item $acuan $asli $rerun (St $acuan $rerun) }

    # 01 hash
    $csv = Join-Path $RR 'hash\arsip_sha1.csv'
    $v = if (Test-Path $csv) { "$(@(Import-Csv $csv | Where-Object { $_.cocok -eq 'True' }).Count)/6" } else { '' }
    Add-Angka '01' 'arsip SHA-1 cocok NIST' '6/6' '6/6 (manifest.txt)' $v
    $csv = Join-Path $RR 'hash\image_hash.csv'
    $v = if (Test-Path $csv) { "$(@(Import-Csv $csv | Where-Object { $_.cocok -eq 'True' }).Count)/4" } else { '' }
    Add-Angka '01' 'image .dd SHA-1+SHA-256 cocok' '4/4' '4/4 (manifest.txt)' $v

    # 03 mmls
    $p = Join-Path $RR 'mmls\pc_mmls.txt'
    $v = if (Test-Path $p) { if (Select-String -Path $p -Pattern '\b0*206848\b' -Quiet) { '206848' } else { 'tidak ada' } } else { '' }
    Add-Angka '03' 'offset NTFS PC' '206848' '206848' $v
    $p = Join-Path $RR 'mmls\rm2_mmls.txt'
    $v = if (Test-Path $p) { if (Select-String -Path $p -Pattern '\b0*128\b.*FAT32' -Quiet) { '128' } else { 'tidak ada' } } else { '' }
    Add-Angka '03' 'offset FAT32 RM#2' '128' '128' $v

    # 04 tsk_recover
    function Count-Files($d) { if (Test-Path -LiteralPath $d) { @(Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue).Count } else { '' } }
    Add-Angka '04' 'file ekspor RM#2 di disk' '41' (Count-Files "$RMData\exports\usb02") (Count-Files "$RRData\exports\usb02")
    if (-not $TanpaHitungEkspor) {
        Add-Angka '04' 'file ekspor PC di disk' '80778' (Count-Files "$RMData\exports\pc") (Count-Files "$RRData\exports\pc")
    }
    $log = Join-Path $RR 'logs\04_tsk_recover.log'
    $fr = if (Test-Path $log) { (Select-String -Path $log -Pattern 'Files Recovered:\s*(\d+)' | ForEach-Object { $_.Matches[0].Groups[1].Value }) -join ' / ' } else { '' }
    Add-Angka '04' 'tsk_recover "Files Recovered" RM#2 / PC' '41 / 80927' '41 / 80927 (manifest.txt)' $fr

    # 05 unittest
    $log = Join-Path $RR 'logs\05_uji_dosen.log'
    $v = ''
    if (Test-Path $log) {
        $ran = (Select-String -Path $log -Pattern '^Ran (\d+) test' | Select-Object -Last 1)
        $ok  = Select-String -Path $log -Pattern '^OK\s*$' -Quiet
        if ($ran) { $v = "$($ran.Matches[0].Groups[1].Value)/15 " + $(if ($ok) { 'OK' } else { 'GAGAL' }) }
    }
    Add-Angka '05' 'unittest kode dosen' '15/15 OK' '15/15 OK (manifest.txt)' $v

    # 06 label + tahap A
    function K-Labels($root) { $j = Read-Json "$root\labels\rm2_labels.json"; if ($j) { "$(@($j.targets).Count)/$(@($j.negatives).Count)" } else { '' } }
    Add-Angka '06' 'rm2_labels target/negatif' '17/24' (K-Labels $RMData) (K-Labels $RRData)
    function K-A($root) { $j = Read-Json "$root\normalized\usb02_complete_check.json"; if ($j) { "$($j.marked_complete)/$($j.usb_files)" } else { '' } }
    Add-Angka '06' 'tahap A: file RM#2 utuh' '17/41' (K-A $RMData) (K-A $RRData)

    # 07 scan + analyze
    function K-Stats($root) { $j = Read-Json "$root\normalized\pc_filter_stats.json"; if ($j) { "$($j.pc_files_total)/$($j.distinct_usb_sizes)/$($j.pc_files_hashed_same_size)" } else { '' } }
    Add-Angka '07' 'scan_pc_filtered total/ukuran unik/di-hash' '80778/41/51' (K-Stats $RMData) (K-Stats $RRData)
    function K-Match($root) {
        $j = Read-Json "$root\results\matches_pc_usb02.json"
        if (-not $j) { return '' }
        $n = @($j.matches).Count
        $di = @($j.matches | Where-Object { $_.usb_path -like '*desktop.ini' }).Count
        "$n pasangan, $di desktop.ini"
    }
    Add-Angka '07' 'pencocokan hash PC<->RM#2' '3 pasangan, 3 desktop.ini' (K-Match $RMData) (K-Match $RRData)

    # 08 timeline RM#2
    function K-Birth($root) {
        $lab = Read-Json "$root\labels\rm2_labels.json"
        $tl = "$root\metadata\usb02_timeline.csv"
        if (-not $lab -or -not (Test-Path $tl)) { return '' }
        $t = @{}; $lab.targets | ForEach-Object { $t['USB02/' + $_.export_path] = 1 }
        $b = Import-Csv $tl -Encoding UTF8 | Where-Object { $_.jenis -eq 'B' -and $t.ContainsKey(($_.path -replace ' \(deleted\)$', '')) }
        $m = $b | Measure-Object eastern_edt -Minimum -Maximum
        "$(@($b).Count) file, $(([string]$m.Minimum).Substring(11))-$(([string]$m.Maximum).Substring(11)) EDT"
    }
    Add-Angka '08' 'RM#2: target lahir (B)' '17 file, 09:59:27-10:00:18 EDT' (K-Birth $RMData) (K-Birth $RRData)

    # 09 Dissect
    function K-Manifest($root) { $j = Read-Json "$root\artifacts\pc-run2\manifest.json"; if ($j) { "$(@($j.runs | Where-Object { $_.returncode -eq 0 }).Count)/$(@($j.runs).Count) rc=0" } else { '' } }
    Add-Angka '09' 'Dissect pc-run2 run sukses' '7/7 rc=0' (K-Manifest $RMData) (K-Manifest $RRData)
    function K-Ver($root) { $p = "$root\artifacts\pc-run2\version.jsonl"; if (Test-Path $p) { (Get-Content $p -Raw).Trim() } else { '' } }
    Add-Angka '09' 'target-query --version' 'dissect.target version 3.25.1' (K-Ver $RMData) (K-Ver $RRData)

    # 10 tahap B-E
    function K-C($root) { $j = Read-Json "$root\normalized\device_map.json"; if ($j) { "$($j.USB02.serial) $($j.USB02.status)" } else { '' } }
    Add-Angka '10' 'tahap C: serial RM#2' '4C530012550531106501 verified_against_nist_documentation' (K-C $RMData) (K-C $RRData)
    function K-B($root) {
        $j = Read-Json "$root\normalized\events_report.json"
        if (-not $j) { return '' }
        $g = $j.records_per_group
        "usn=$($g.usnjrnl) fs_usb=$($g.fs_usb) jumplist=$($g.jumplist) lnk=$($g.lnk) setupapi=$($g.setupapi)"
    }
    Add-Angka '10' 'tahap B: record per kelompok' 'usn=412 fs_usb=82 jumplist=2 lnk=2 setupapi=2' (K-B $RMData) (K-B $RRData)
    function K-Roots($root) {
        $j = Read-Json "$root\results\eksperimen\experiments_summary.json"
        if (-not $j) { return '' }
        "$(@($j.PSObject.Properties.Name | Where-Object { $_ -like 'tanpa_*' }).Count) kelompok, $($j.acuan.roots_total.mean) root"
    }
    Add-Angka '10' 'kelompok bukti / root' '6 kelompok, 499 root' (K-Roots $RMData) (K-Roots $RRData)
    function K-D($root) {
        $j = Read-Json "$root\results\correlated.json"
        if (-not $j) { return '' }
        $f = @($j.files | Where-Object { $_.direction -eq 'pc_to_usb' })
        $d = $f | ForEach-Object { ([datetimeoffset]$_.time_interval_utc[1] - [datetimeoffset]$_.time_interval_utc[0]).TotalSeconds } | Sort-Object
        $med = if ($d.Count % 2) { $d[[int][math]::Floor($d.Count / 2)] } else { ($d[$d.Count / 2 - 1] + $d[$d.Count / 2]) / 2 }
        "$($f.Count)/17, $([math]::Floor($d[0]))-$([math]::Floor($d[-1])) s, median $([math]::Floor($med)) s"
    }
    Add-Angka '10' 'tahap D: PC->USB + interval' '17/17, 56-107 s, median 73 s' (K-D $RMData) (K-D $RRData)
    function K-Land($root) {
        $j = Read-Json "$root\results\correlated.json"
        if (-not $j) { return '' }
        "$(@(($j.files | Where-Object { $_.usb_path -like '*landscape*' }).pc_candidates).Count) kandidat"
    }
    Add-Angka '10' 'tahap D: landscape.png' '2 kandidat' (K-Land $RMData) (K-Land $RRData)
    function K-E($root) {
        $p = "$root\results\eksperimen\experiments.csv"
        if (-not (Test-Path $p)) { return '' }
        $c = Import-Csv $p -Encoding UTF8
        $mx = ($c | ForEach-Object { [double]$_.fp + [double]$_.device_wrong + [double]$_.direction_wrong + [double]$_.time_inconsistent } | Measure-Object -Maximum).Maximum
        "$(@($c).Count) run, maks error $mx"
    }
    Add-Angka '10' 'tahap E: run, fp+device_wrong+direction_wrong+time_inconsistent' '127 run, maks error 0' (K-E $RMData) (K-E $RRData)

    # 11 percobaan 2
    function K-P2($file) {
        $j = Read-Json $file
        if (-not $j) { return '' }
        $g = $j.roots_per_group
        "$($j.roots_total) (usn $($g.usn), shellbag $($g.shellbag), jumplist $($g.jumplist), lnk $($g.lnk))"
    }
    Add-Angka '11' 'record mentah' '744 (usn 327, shellbag 125, jumplist 85, lnk 207)' (K-P2 "$P2\hasil\path_b_summary_30seed.json") (K-P2 "$RRP2\hasil\path_b_summary_30seed.json")
    function K-Acc($file) {
        $j = Read-Json $file
        if (-not $j) { return '' }
        $s = $j.scenarios
        $ref = "$($s.reference.correct)/6"
        $acc = ('random_10', 'random_30', 'random_50', 'random_70' | ForEach-Object { ([math]::Round($s.$_.correct / 6, 2)).ToString('0.00', [Globalization.CultureInfo]::InvariantCulture) }) -join '/'
        "ref $ref, op4 nama $($s.reference.op4_names_mean)/17, acak $acc"
    }
    Add-Angka '11' 'masking 30 seed' 'ref 6/6, op4 nama 1/17, acak 1.00/0.90/0.67/0.34' (K-Acc "$P2\hasil\path_b_summary_30seed.json") (K-Acc "$RRP2\hasil\path_b_summary_30seed.json")
    Add-Angka '11' 'masking 1000 seed' 'ref 6/6, op4 nama 1/17, acak 0.99/0.88/0.63/0.37' (K-Acc "$P2\hasil\path_b_summary_1000seed.json") (K-Acc "$RRP2\hasil\path_b_summary_1000seed.json")
    $a = Join-Path $RRP2 'analyze_input_dissect.txt'
    $b = Join-Path $RRP2 'analyze_lnk_pcrun2.txt'
    if ((Test-Path $a) -and (Test-Path $b)) {
        $same = -not (Compare-Object (Get-Content $a) (Get-Content $b))
        Add-Row '11' 'TODO 2: analyze input_dissect vs lnk pc-run2' 'sama' '-' $(if ($same) { 'sama' } else { 'beda' }) $(if ($same) { 'SAMA' } else { 'BEDA' })
    } else { Add-Row '11' 'TODO 2: analyze input_dissect vs lnk pc-run2' 'sama' '-' '' 'BELUM' }

    # ------------------------------------------------------------------ laporan
    $tbl = $rows | Format-Table tahap, status, item, acuan, asli, rerun -AutoSize -Wrap | Out-String -Width 260
    Write-Host $tbl
    $tbl | Out-File (Join-Path $RR 'logs\verify.txt') -Encoding utf8
    $rows | Export-Csv (Join-Path $RR 'logs\verify.csv') -NoTypeInformation -Encoding UTF8
    $grp = $rows | Group-Object status | ForEach-Object { "$($_.Name)=$($_.Count)" }
    Write-Host "Ringkasan: $($grp -join '  ')"
    Write-Host "Tabel: $RR\logs\verify.txt  |  CSV: $RR\logs\verify.csv"
} finally {
    Stop-Transcript
}
