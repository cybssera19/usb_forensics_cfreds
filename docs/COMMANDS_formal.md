# Command Record and Reproduction Guide

**Research title:** *Reconstructing Document Transfers to USB Storage through Windows Artifact Correlation and Evaluation of Evidence Loss* (original title: *Rekonstruksi Perpindahan Dokumen ke USB melalui Korelasi Artefak Windows dan Evaluasi Kehilangan Bukti*)

## 1. Overview

This document records every command used in the research, from the integrity verification of the downloaded evidence to the evidence-loss experiments. The analysis uses the public NIST CFReDS *Data Leakage Case* (DD version). The study determines which documents moved from the suspect personal computer (PC) to removable medium RM#2, identifies the device, establishes the direction and time window of each transfer, and measures how these conclusions degrade when parts of the evidence are removed. For each command, the document states its purpose, working directory, interpreter, inputs, outputs, expected result, and provenance. Section 6 explains how the published results can be reproduced with the scripts in `rerun/`.

---

## 2. Environment

### 2.1 Tools and versions

| Component | Version | Used for |
|---|---|---|
| Windows PowerShell | 5.1 | Hashing (`Get-FileHash`), orchestration, rerun scripts |
| Python (primary) | **3.14.4** | Supervisor's code, stage scripts `tahap_*.py`, `body2csv.py`, `make_rm2_labels.py`, `scan_pc_filtered.py`, `analyze_cfreds.py`, `masking_path_b.py` |
| Python (Dissect environment) | **3.11.9**, virtual environment `.venv311` | Dissect, Experiment 1 (`pc-run2`) |
| dissect / dissect.target | **3.22 / 3.25.1** | Windows artifact extraction (`target-query`) |
| Python (Experiment 2) | **3.12** (exact patch version not recorded) | Dissect, Experiment 2, run on a secondary lab account |
| The Sleuth Kit | **4.14.0** (Windows binaries) | `mmls`, `tsk_recover`, `fls` |
| WinRAR | **7.13** | Archive extraction (graphical interface) |
| 7-Zip | 25.01 | Optional command-line alternative for extraction |

A first Dissect environment based on Python 3.14 (`.venv`) failed to import `dissect.target`. Its run (`pc-run1`) is documented for completeness only.

### 2.2 Path variables

All paths in this document are relative to the repository root unless stated otherwise. The following variables are used inside command blocks and are defined once here:

```powershell
$RM_ROOT    = '<absolute path of the repository root>'
$RERUN_ROOT = '<absolute path of the reproduction output folder>'   # a sibling folder named RM_rerun in the original setup
$TSK_BIN    = '<Sleuth Kit 4.14.0 bin folder>'
$DATA_DRIVE = '<drive letter that holds the repository, e.g. X:>'
```

**Note on substitution.** The original commands used literal absolute paths, and these variables replace them. PowerShell expands variables in bare arguments and double-quoted strings, but not inside single-quoted strings, for example `cmd /c '...'` and `.Replace('...','')`. In those places, substitute the value textually before running the command.

The rerun scripts in `rerun/` do not use these variables. They define the two roots as constants in `rerun/_common.ps1` and in the `Start-Transcript` line of each script, so those lines must be edited if the repository is moved.

---

## 3. Directory layout

```text
<repository root>/
├── 00_BACA_DULU.md                          folder map (Indonesian)
├── 01_dokumen/                              case description, NIST answer key, supervisor's guideline
├── 02_unduhan_asli/                         NIST archives (not versioned) + hash records, manifest.txt
├── cfreds_2015_data_leakage_pc.7z/          extracted PC image  ...pc.dd          (not versioned)
├── cfreds_2015_data_leakage_rm#2/           extracted RM#2 image ...rm#2.dd       (not versioned)
├── cfreds_2015_data_leakage_seed_files/     NIST reference documents              (not versioned)
├── usb-forensics-starter/usb-forensics-starter/
│   ├── usb_forensics.py, demo.py, extract_pc_artifacts.py, test_usb_forensics.py   supervisor's code
│   ├── scan_pc_filtered.py, tahap_a_*.py … tahap_e_*.py                          additional scripts
│   └── .venv311/                            Dissect environment                   (not versioned)
├── data/                                    Experiment 1 data and results
│   ├── exports/{pc,usb02}/                  tsk_recover output                    (not versioned)
│   ├── metadata/                            fls body files, MACB timelines, body2csv.py
│   ├── artifacts/pc-run1/, pc-run2/         Dissect raw output + manifest.json
│   ├── normalized/                          records in the supervisor's schema
│   ├── labels/                              labels from the NIST answer key, make_rm2_labels.py
│   └── results/                             correlated.json, eksperimen/ (source of the reported figures)
├── 04_percobaan2_host_only/                 Experiment 2 (host-only)
│   ├── input_dissect/  kode/  ground_truth/  hasil/
├── rerun/                                   reproduction scripts 00–11 + verify.ps1
└── docs/                                    this document
```

---

## 4. Provenance legend

| Label | Meaning |
|---|---|
| **Recorded** | Taken verbatim from the PowerShell history of the primary workstation, from a tool manifest (`data/artifacts/pc-run*/manifest.json`), or from the project's run notes (`00_BACA_DULU.md`, `PANDUAN_JALANKAN.txt`). Only the path substitution of Section 2.2 has been applied. |
| **Reconstructed** | Rebuilt from a script's argument parser or source code. The basis is stated. |
| **Equivalent** | A command-line equivalent of a step that was originally performed in a graphical interface. |
| **Unavailable** | The command cannot be recovered. The reason is stated. |

History references take the form *PowerShell history, primary workstation, line N*. Mappings to the supervisor's technical guideline use the form **TG n**, where the guideline's numbered points are: 1 define what is to be proven; 2 use the NIST CFReDS dataset; 3 extract files and artifacts from the images; 4 match documents by content; 5 link document pairs to the removable device and Windows activity; 6 build the timeline without turning assumptions into facts; 7 test what happens when evidence is removed; 8 evaluate each question separately; 9 compare file-name, hash, and combined-artifact methods; 10 research contribution. The guideline's closing section (“to try it now”) prescribes the unit tests and the demo.

Interpreter labels: **Py3.14** (`python` on PATH, Python 3.14.4), **Py3.11-venv** (`.venv311`), **Py3.12** (secondary lab account).

---

## 5. Procedure

### Stage 0 — Environment (TG 3: record tool versions)

**0.1 Tool inventory**

| Field | Value |
|---|---|
| Purpose | List the installed archivers, forensic tools, and Python distributions. |
| Working directory | any |
| Interpreter | PowerShell |
| Input / Output | registry uninstall keys / console |
| Expected result | WinRAR 7.13, 7-Zip 25.01, Python entries |
| Provenance | Recorded — PowerShell history, primary workstation, line 420 |

```powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match "WinRAR|7-Zip|Autopsy|FTK|Python" } | Select-Object DisplayName, DisplayVersion
```

**0.2 Python versions and Sleuth Kit path**

| Field | Value |
|---|---|
| Purpose | Confirm the primary interpreter version, list available interpreters, and add The Sleuth Kit to PATH. |
| Working directory | any |
| Interpreter | PowerShell / Py3.14 |
| Expected result | `Python 3.14.4`; interpreters 3.14 and 3.11 listed |
| Provenance | Recorded — PowerShell history, primary workstation, lines 538, 540, 431 (repeated at 506 and 513) |

```powershell
python --version
py -0
$env:Path += ";$TSK_BIN"
```

**0.3 First Dissect environment (failed)**

| Field | Value |
|---|---|
| Purpose | Create a Dissect environment with the primary interpreter. |
| Working directory | `usb-forensics-starter/usb-forensics-starter` |
| Interpreter | Py3.14 → `.venv` |
| Output | `.venv/`, `environment.txt` (later overwritten) |
| Expected result | Installation succeeds, but `target-query` fails at import time (see Stage 9a) |
| Provenance | Recorded — PowerShell history, primary workstation, lines 525–530 and 539 |

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install dissect
python -m pip freeze > environment.txt
target-query --version
deactivate
```

**0.4 Dissect environment used in Experiment 1**

| Field | Value |
|---|---|
| Purpose | Create a Python 3.11 environment with Dissect and record its package list. |
| Working directory | `usb-forensics-starter/usb-forensics-starter` |
| Interpreter | Py3.11-venv |
| Output | `.venv311/`, `environment.txt` (UTF-16, written by the PowerShell 5.1 `>` operator) |
| Expected result | Python 3.11.9; `dissect.target version 3.25.1`; `environment.txt` lists `dissect==3.22`, `dissect.target==3.25.1` |
| Provenance | Recorded — PowerShell history, primary workstation, lines 541–548 |

```powershell
cd $RM_ROOT\usb-forensics-starter\usb-forensics-starter
py -3.11 -m venv .venv311
Set-ExecutionPolicy -Scope Process Bypass
.\.venv311\Scripts\Activate.ps1
python --version
python -m pip install dissect
python -m pip freeze > environment.txt
target-query --version
```

The Python 3.12 version and package list used in Experiment 2 are **Unavailable** (see Section 8).

---

### Stage 1 — Hash verification (TG 2–3)

Purpose of the stage: show that the downloaded archives match the official NIST hash values, and record the hashes of the extracted images.

| Field | Value |
|---|---|
| Purpose | Compute MD5/SHA-1 of the six NIST archives, create the data folder structure, and compute SHA-1/SHA-256 of the extracted `.dd` images. |
| Working directory | repository root |
| Interpreter | PowerShell (`Get-FileHash`) |
| Input | `cfreds_2015_data_leakage_{pc.7z.001–.003, rm#1.E01, rm#2.7z, seed_files.7z}` (now in `02_unduhan_asli/`); `pc.dd` (20 GB), `rm#2.dd` (3.7 GB) |
| Output | `hash-hasil.txt` (MD5 of the four archives available at that time), `hash-sha1.txt` (six archives), `hash-image.txt`, `hash-image-sha256.txt`, all UTF-16 and now in `02_unduhan_asli/` |
| Expected result | **6/6 archive SHA-1 values match NIST**. `pc.dd` SHA-1 `AFE5C9AB…D785`, SHA-256 `026C1436…BE4E2`; `rm#2.dd` SHA-1 `048961A8…A0A3`, SHA-256 `D930AFA2…D407` |
| Duration | approx. 2–3 minutes per algorithm for the images (from output file timestamps) |
| Provenance | Recorded — PowerShell history, primary workstation, lines 414–419 (earlier MD5 attempts on another drive: lines 409–413). The comparison with the NIST hash page was done manually; the NIST values are transcribed in `02_unduhan_asli/manifest.txt`, section 2. |

```powershell
# Archives were located in the repository root at that time; they are now in 02_unduhan_asli
cd $RM_ROOT
Get-ChildItem -Path $RM_ROOT -File -Filter "cfreds*" | Get-FileHash -Algorithm MD5  | Format-Table Hash, Path -AutoSize | Out-File $DATA_DRIVE\hash-hasil.txt
Get-ChildItem -Path $RM_ROOT -File -Filter "cfreds*" | Get-FileHash -Algorithm SHA1 | Format-Table Hash, Path -AutoSize | Out-File $DATA_DRIVE\hash-sha1.txt

# Data folder structure (TG 3)
mkdir $RM_ROOT\data\raw, $RM_ROOT\data\exports, $RM_ROOT\data\artifacts, $RM_ROOT\data\normalized, $RM_ROOT\data\labels, $RM_ROOT\data\results, $RM_ROOT\data\reference

# Image hashes (after extraction, Stage 2)
Get-ChildItem -Path "$RM_ROOT\cfreds_2015_data_leakage_pc.7z", "$RM_ROOT\cfreds_2015_data_leakage_rm#2" -File -Recurse | Get-FileHash -Algorithm SHA1   | Format-Table Hash, Path -AutoSize | Out-File $RM_ROOT\hash-image.txt
Get-ChildItem -Path "$RM_ROOT\cfreds_2015_data_leakage_pc.7z", "$RM_ROOT\cfreds_2015_data_leakage_rm#2" -File -Recurse | Get-FileHash -Algorithm SHA256 | Format-Table Hash, Path -AutoSize | Out-File $RM_ROOT\hash-image-sha256.txt
```

---

### Stage 2 — Archive extraction (TG 3)

| Field | Value |
|---|---|
| Purpose | Extract the `.dd` images and the seed files from the 7z archives. |
| Working directory | any |
| Interpreter | WinRAR 7.13 (graphical interface); command-line equivalents shown below |
| Input | `02_unduhan_asli/cfreds_2015_data_leakage_{pc.7z.001, rm#2.7z, seed_files.7z}` |
| Output | original: `cfreds_2015_data_leakage_pc.7z/`, `cfreds_2015_data_leakage_rm#2/`, `cfreds_2015_data_leakage_seed_files/`; reproduction: `$RERUN_ROOT\extract\…` |
| Expected result | SHA-256 of the re-extracted `.dd` files equals the values in Stage 1; requires approx. 25 GB |
| Provenance | **Equivalent** — originally done with “Extract to …” in the WinRAR interface; no command was recorded |

```powershell
# WinRAR (default)
Start-Process "C:\Program Files\WinRAR\WinRAR.exe" -ArgumentList 'x','-ibck','-y','"$RM_ROOT\02_unduhan_asli\cfreds_2015_data_leakage_pc.7z.001"','$RERUN_ROOT\extract\cfreds_2015_data_leakage_pc.7z\' -Wait
# 7-Zip (alternative)
& "C:\Program Files\7-Zip\7z.exe" x "$RM_ROOT\02_unduhan_asli\cfreds_2015_data_leakage_pc.7z.001" -o"$RERUN_ROOT\extract\cfreds_2015_data_leakage_pc.7z" -y
```

The WinRAR arguments are single-quoted, so substitute the variables textually (Section 2.2).

---

### Stage 3 — Partition tables (TG 3)

| Field | Value |
|---|---|
| Purpose | Find the sector offsets of the analysed file systems. |
| Working directory | repository root |
| Interpreter | The Sleuth Kit 4.14.0 |
| Input | `pc.dd`, `rm#2.dd` |
| Output | console only (recorded in `02_unduhan_asli/manifest.txt`, section 4) |
| Expected result | PC: sector 2048 NTFS System Reserved, **sector 206848 NTFS C:** (≈19.9 GB). RM#2: **sector 128 FAT32** (≈1 GB), 2097280–7821311 unallocated |
| Provenance | Recorded — PowerShell history, primary workstation, lines 431–433 (lines 427 and 430 failed because PATH was incorrect) |

```powershell
$env:Path += ";$TSK_BIN"
mmls "$RM_ROOT\cfreds_2015_data_leakage_pc.7z\cfreds_2015_data_leakage_pc.dd"
mmls "$RM_ROOT\cfreds_2015_data_leakage_rm#2\cfreds_2015_data_leakage_rm#2.dd"
```

---

### Stage 4 — File export and export audit (TG 3)

**4.1 Export with `tsk_recover`**

| Field | Value |
|---|---|
| Purpose | Export allocated and unallocated files from both images. |
| Working directory | repository root |
| Interpreter | The Sleuth Kit 4.14.0 |
| Input | `pc.dd` (offset 206848), `rm#2.dd` (offset 128) |
| Output | `data/exports/usb02/` (41 files, 0.17 GB), `data/exports/pc/` (21 GB) |
| Expected result | RM#2: **41 files**. PC: **80,927 files** reported and **80,778** present on disk; four Internet Explorer cache files could not be written because their paths exceed 260 characters (see Section 8) |
| Duration | RM#2 about 1 second; **PC about 8.5 minutes** |
| Provenance | Recorded — PowerShell history, primary workstation, lines 434–436 |

```powershell
mkdir $RM_ROOT\data\exports\pc, $RM_ROOT\data\exports\usb02 -Force
tsk_recover -e -o 128    "$RM_ROOT\cfreds_2015_data_leakage_rm#2\cfreds_2015_data_leakage_rm#2.dd" $RM_ROOT\data\exports\usb02
tsk_recover -e -o 206848 "$RM_ROOT\cfreds_2015_data_leakage_pc.7z\cfreds_2015_data_leakage_pc.dd"   $RM_ROOT\data\exports\pc
```

**4.2 Audit of the RM#2 export against the seed files**

| Field | Value |
|---|---|
| Purpose | List the RM#2 export and find which files are byte-identical (SHA-256) to a NIST seed file. |
| Working directory | repository root |
| Interpreter | PowerShell |
| Input | `data/exports/usb02/`, `cfreds_2015_data_leakage_seed_files/` |
| Output | `data/exports/usb02-list.txt`, `data/exports/usb02-vs-seed.txt`, `data/labels/usb02_vs_seed.csv` |
| Expected result | 41 rows; **17** with a non-empty `seed_path` |
| Provenance | Recorded — PowerShell history, primary workstation, lines 445, 446–452, 464–475 (the block was first entered at line 453 and repeated after line 464) |

```powershell
Get-ChildItem -Path $RM_ROOT\data\exports\usb02 -Recurse -File | Select-Object FullName, Length | Format-Table -AutoSize | Out-File $RM_ROOT\data\exports\usb02-list.txt
# -> usb02-vs-seed.txt
$usb  = Get-ChildItem $RM_ROOT\data\exports\usb02 -Recurse -File | Get-FileHash -Algorithm SHA256
$seed = Get-ChildItem $RM_ROOT\cfreds_2015_data_leakage_seed_files -Recurse -File | Get-FileHash -Algorithm SHA256
$usb | ForEach-Object {
  $h = $_.Hash
  $m = $seed | Where-Object Hash -eq $h
  [pscustomobject]@{ FileUSB = $_.Path.Replace('$RM_ROOT\data\exports\usb02\',''); CocokSeed = if ($m) { $m[0].Path.Replace('$RM_ROOT\cfreds_2015_data_leakage_seed_files\','') } else { '-' } }
} | Format-Table -AutoSize | Out-File $RM_ROOT\data\exports\usb02-vs-seed.txt
# -> labels\usb02_vs_seed.csv
mkdir $RM_ROOT\data\labels -Force
$usb  = Get-ChildItem $RM_ROOT\data\exports\usb02 -Recurse -File | Get-FileHash -Algorithm SHA256
$seed = Get-ChildItem $RM_ROOT\cfreds_2015_data_leakage_seed_files -Recurse -File | Get-FileHash -Algorithm SHA256
$usb | ForEach-Object {
  $h = $_.Hash
  $m = $seed | Where-Object Hash -eq $h
  [pscustomobject]@{
    file_usb  = $_.Path.Replace('$RM_ROOT\data\exports\usb02\','')
    sha256    = $h
    seed_path = if ($m) { $m[0].Path.Replace('$RM_ROOT\cfreds_2015_data_leakage_seed_files\','') } else { '' }
  }
} | Export-Csv $RM_ROOT\data\labels\usb02_vs_seed.csv -NoTypeInformation -Encoding UTF8
```

The `.Replace('…')` arguments are single-quoted, so substitute `$RM_ROOT` textually.

---

### Stage 5 — Supervisor's code self-test (TG closing section)

| Field | Value |
|---|---|
| Purpose | Run the supervisor's unit tests and the synthetic demonstration. |
| Working directory | `usb-forensics-starter/usb-forensics-starter` |
| Interpreter | Py3.14 |
| Input | `test_usb_forensics.py`, `demo.py` (unmodified) |
| Output | `demo-baru/` |
| Expected result | **15/15 tests pass**; demo completes (synthetic data, not a research finding) |
| Provenance | Recorded — PowerShell history, primary workstation, lines 438–440 (repeated at 441–443; listing at 444). An earlier attempt at lines 422–424 was run from the wrong directory. |

```powershell
cd $RM_ROOT\usb-forensics-starter\usb-forensics-starter
python -m unittest -v
python demo.py --out demo-baru
Get-ChildItem demo-baru
```

---

### Stage 6 — RM#2 labels and Stage A: marking complete files (TG 3, TG 8)

Original order: `make_rm2_labels.py`, then the USB02 inventory (Stage 7), then Stage A. Stage A reads `usb02.json`, which is why the rerun script for this stage also creates the USB02 inventory.

**6.1 Labels from the NIST answer key**

| Field | Value |
|---|---|
| Purpose | Build target and negative labels for RM#2 from NIST answers Q53–Q55 and Q59 (for evaluation only). |
| Working directory | `data/labels` |
| Interpreter | Py3.14 |
| Input | `data/exports/usb02/` |
| Output | `data/labels/rm2_labels.json` |
| Expected result | `Target : 17 / 17`, `Contoh negatif : 24` |
| Provenance | Recorded — PowerShell history, primary workstation, lines 478–479. The script has no argument parser; its data root is fixed in line 15 (`DATA = Path(r"…\data")`). |

```powershell
cd $RM_ROOT\data\labels
python make_rm2_labels.py
```

**6.2 Installing the stage scripts**

| Field | Value |
|---|---|
| Purpose | Place `tahap_a_*.py` … `tahap_e_*.py` and `PANDUAN_JALANKAN.txt` next to the supervisor's code. |
| Working directory | `usb-forensics-starter/usb-forensics-starter` |
| Provenance | Recorded — PowerShell history, primary workstation, lines 555–560 |

```powershell
Expand-Archive "$env:USERPROFILE\Downloads\tahap_lanjutan.zip" -DestinationPath "$RM_ROOT\usb-forensics-starter\usb-forensics-starter" -Force
cd $RM_ROOT\usb-forensics-starter\usb-forensics-starter
Get-ChildItem .\tahap_lanjutan -Recurse -Include tahap_*.py, PANDUAN_JALANKAN.txt | Move-Item -Destination . -Force
dir tahap_*.py
```

**6.3 Stage A — `tahap_a_tandai_utuh.py`**

| Field | Value |
|---|---|
| Purpose | Set `complete=True` only on USB records whose (SHA-256, size) equals a NIST seed file. |
| Working directory | `usb-forensics-starter/usb-forensics-starter` |
| Interpreter | Py3.14 |
| Input | `data/normalized/usb02.json`, `cfreds_2015_data_leakage_seed_files/` (defaults of `--usb`, `--seed`; argument parser lines 25–28) |
| Output | `data/normalized/usb02_complete.json`, `data/normalized/usb02_complete_check.json` |
| Expected result | 40 seed files hashed; **`Ditandai complete : 17`** of 41 USB files |
| Provenance | Recorded — PowerShell history, primary workstation, line 561 |

```powershell
python tahap_a_tandai_utuh.py
```

---

### Stage 7 — Inventory and hash matching PC ↔ RM#2 (TG 4; TG 9 hash baseline)

| Field | Value |
|---|---|
| Purpose | Inventory both exports with SHA-256 and size, then match PC and RM#2 files by content. |
| Working directory | `usb-forensics-starter/usb-forensics-starter` |
| Interpreter | Py3.14 |
| Input | `data/exports/usb02/`, `data/exports/pc/` |
| Output | `data/normalized/usb02.json`, `data/normalized/pc.json` (51 records), `data/normalized/pc_filter_stats.json`, `data/results/matches_pc_usb02.json`, `data/results/matches_summary.txt` |
| Expected result | `scan_pc_filtered.py`: 80,778 PC files read, 41 distinct USB sizes, **51 PC files hashed**, 4.7 s. `analyze`: **3 pairs, all `desktop.ini`**; none of the 17 target documents is present in the PC export |
| Provenance | Recorded — PowerShell history, primary workstation, lines 480–495 and 499–502. Full PC scans (lines 483, 484, 486) were attempted, and their `pc.json` was later overwritten by `scan_pc_filtered.py`. The script was moved from the Downloads folder (line 491) and edited in a text editor (line 493). |

```powershell
cd $RM_ROOT\usb-forensics-starter\usb-forensics-starter
mkdir $RM_ROOT\data\normalized, $RM_ROOT\data\results -Force
python usb_forensics.py scan --folder $RM_ROOT\data\exports\usb02 --media USB02 --out $RM_ROOT\data\normalized\usb02.json

# Full PC scans (superseded)
python usb_forensics.py scan --folder $RM_ROOT\data\exports\pc --media PC --out $RM_ROOT\data\normalized\pc.json
python usb_forensics.py scan --folder $RM_ROOT\data\exports\pc\Users --media PC --complete --out $RM_ROOT\data\normalized\pc.json

# USB02 scan repeated, then the size-filtered PC scan
python usb_forensics.py scan --folder $RM_ROOT\data\exports\usb02 --media USB02 --out $RM_ROOT\data\normalized\usb02.json
Move-Item "$env:USERPROFILE\Downloads\scan_pc_filtered.py" "$RM_ROOT\usb-forensics-starter\usb-forensics-starter\scan_pc_filtered.py"
python scan_pc_filtered.py

python usb_forensics.py analyze --inputs $RM_ROOT\data\normalized\pc.json $RM_ROOT\data\normalized\usb02.json --out $RM_ROOT\data\results\matches_pc_usb02.json

# Summary
$r = Get-Content $RM_ROOT\data\results\matches_pc_usb02.json -Raw | ConvertFrom-Json
"Jumlah pasangan: " + $r.matches.Count
$r.matches | Select-Object pc_path, usb_path | Format-Table -AutoSize -Wrap | Out-File $RM_ROOT\data\results\matches_summary.txt -Width 300
Get-Content $RM_ROOT\data\results\matches_summary.txt
```

When this document was prepared, line 1 of `scan_pc_filtered.py` was a `//` comment, which is not valid Python syntax, and the script's paths were fixed in lines 9–12. See Section 8.

Exploratory commands at lines 503 and 505 of the history produced no file that was used later.

---

### Stage 8 — MACB timelines with `fls` and `body2csv.py` (TG 5; TG 6: NTFS stores UTC, FAT stores local time)

| Field | Value |
|---|---|
| Purpose | Create body files and readable timelines for RM#2 and the PC, and inspect USB device installations in `setupapi.dev.log`. |
| Working directory | `data/metadata` |
| Interpreter | The Sleuth Kit 4.14.0 + Py3.14 (`body2csv.py`, usage in its docstring, lines 3–5) |
| Input | `rm#2.dd`, `pc.dd`, `data/exports/pc/Windows/inf/setupapi.dev.log` |
| Output | `usb02_body.txt`, `usb02_timeline.csv`, `pc_body.txt` (38 MB), `pc_timeline.csv` (126 MB), `pc_0935_1015.txt` |
| Expected result | **The 17 target files have creation (B) times between 09:59:27 and 10:00:18 EDT on 24 March 2015** |
| Provenance | Recorded — PowerShell history, primary workstation, lines 513–523 |

```powershell
$env:Path += ";$TSK_BIN"
mkdir $RM_ROOT\data\metadata -Force
cd $RM_ROOT\data\metadata
cmd /c 'fls -r -m "USB02/" -z UTC0 -o 128 "$RM_ROOT\cfreds_2015_data_leakage_rm#2\cfreds_2015_data_leakage_rm#2.dd" > usb02_body.txt'
python body2csv.py usb02_body.txt usb02_timeline.csv fat
Select-String -Path usb02_timeline.csv -Pattern "2015-03-24" | Select-Object -First 40
Import-Csv usb02_timeline.csv | Where-Object { $_.jenis -in "B","M" } | Sort-Object path, jenis | Format-Table eastern_edt, jenis, path -AutoSize
cmd /c 'fls -r -m "C:/" -o 206848 "$RM_ROOT\cfreds_2015_data_leakage_pc.7z\cfreds_2015_data_leakage_pc.dd" > pc_body.txt'
python body2csv.py pc_body.txt pc_timeline.csv ntfs
Import-Csv pc_timeline.csv | Where-Object { $_.eastern_edt -ge "2015-03-24 09:35" -and $_.eastern_edt -le "2015-03-24 10:15" } | Format-Table eastern_edt, jenis, path -AutoSize | Out-File pc_0935_1015.txt -Width 400

# USB device installation records
Select-String -Path "$RM_ROOT\data\exports\pc\Windows\inf\setupapi.dev.log" -Pattern "Device Install.*USBSTOR" -Context 0,1
```

Notes:
- Only the FAT32 image uses `-z UTC0`, after which `body2csv.py … fat` adds four hours (EDT, UTC−4). The PC (NTFS) body file is created without `-z`.
- `cmd /c` is used so that the redirection writes raw bytes, whereas the PowerShell 5.1 `>` operator writes UTF-16. Because the `cmd /c` arguments are single-quoted, substitute `$RM_ROOT` textually.
- Exploratory commands (history lines 507, 508–511, 512, 563) searched deleted entries in the “S data” folder, the desktop of the case user, path strings inside a LNK file, and two names in the RM#2 body file. They produced no files.

---

### Stage 9 — PC artifacts with Dissect (TG 5)

**9a. `pc-run1` (failed, Python 3.14)**

| Field | Value |
|---|---|
| Purpose | First artifact extraction attempt. |
| Working directory | `usb-forensics-starter/usb-forensics-starter` |
| Interpreter | Py3.14 → `.venv` |
| Output | `data/artifacts/pc-run1/` |
| Expected result | All seven runs return code 1 with empty output (SHA-256 `e3b0c442…`). `version.stderr.txt` contains a traceback raised while importing `dissect.target` |
| Provenance | Recorded — PowerShell history, primary workstation, lines 531–537; tool manifest `data/artifacts/pc-run1/manifest.json` |

```powershell
cd $RM_ROOT\usb-forensics-starter\usb-forensics-starter
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
python extract_pc_artifacts.py --image "$RM_ROOT\cfreds_2015_data_leakage_pc.7z\cfreds_2015_data_leakage_pc.dd" --out $RM_ROOT\data\artifacts\pc-run1 --plugins usb jumplist lnk usnjrnl evtx
(Get-Content $RM_ROOT\data\artifacts\pc-run1\manifest.json | ConvertFrom-Json).runs | Format-Table returncode, status, output -AutoSize
Get-ChildItem $RM_ROOT\data\artifacts\pc-run1 | Format-Table Name, Length -AutoSize
Get-Content $RM_ROOT\data\artifacts\pc-run1\version.stderr.txt
```

**9b. `pc-run2` (used, Python 3.11)**

| Field | Value |
|---|---|
| Purpose | Export raw Dissect records for USB, Jump Lists, LNK files, `$UsnJrnl`, and event logs, keeping each command and output hash. |
| Working directory | `usb-forensics-starter/usb-forensics-starter` |
| Interpreter | Py3.11-venv (Python 3.11.9, dissect.target 3.25.1) |
| Input | `pc.dd` |
| Output | `data/artifacts/pc-run2/` (`version`, `plugins`, `artifact-0` … `artifact-4` as `.jsonl` + `.stderr.txt`, `manifest.json`) |
| Expected result | Seven runs, all return code 0 (table below) |
| Duration | approx. 4 minutes after the wrapper hashes the 20 GB image; `usnjrnl` approx. 2 minutes |
| Provenance | Recorded — PowerShell history, primary workstation, lines 541–551; tool manifest `data/artifacts/pc-run2/manifest.json` |

```powershell
cd $RM_ROOT\usb-forensics-starter\usb-forensics-starter
py -3.11 -m venv .venv311
Set-ExecutionPolicy -Scope Process Bypass
.\.venv311\Scripts\Activate.ps1
python --version
python -m pip install dissect
python -m pip freeze > environment.txt
target-query --version
python extract_pc_artifacts.py --image "$RM_ROOT\cfreds_2015_data_leakage_pc.7z\cfreds_2015_data_leakage_pc.dd" --out $RM_ROOT\data\artifacts\pc-run2 --plugins usb jumplist lnk usnjrnl evtx
(Get-Content $RM_ROOT\data\artifacts\pc-run2\manifest.json | ConvertFrom-Json).runs | Format-Table returncode, status, output -AutoSize
Get-ChildItem $RM_ROOT\data\artifacts\pc-run2 | Format-Table Name, Length -AutoSize
```

Commands executed by `extract_pc_artifacts.py` as recorded in the manifest (status `raw_export_needs_review`):

| Output | Command | Size (bytes) | SHA-256 (manifest) |
|---|---|---|---|
| `version.jsonl` | `.venv311\Scripts\target-query.EXE --version` | 31 | `c61397b6…3979` |
| `plugins.jsonl` | `target-query.EXE <pc.dd> -l` | 15,243 | `3c816705…ddb0` |
| `artifact-0.jsonl` | `target-query.EXE <pc.dd> -f usb -j` | 6,214 | `b012bdde…a102` |
| `artifact-1.jsonl` | `target-query.EXE <pc.dd> -f jumplist -j` | 121,420 | `d53e367c…47a9` |
| `artifact-2.jsonl` | `target-query.EXE <pc.dd> -f lnk -j` | 233,871 | `aacb6885…397e` |
| `artifact-3.jsonl` | `target-query.EXE <pc.dd> -f usnjrnl -j` | 189,140,318 | `18ca15af…75ed` |
| `artifact-4.jsonl` | `target-query.EXE <pc.dd> -f evtx -j` | 6,299,778 | `75e1ae73…96b3` |

`<pc.dd>` is `cfreds_2015_data_leakage_pc.7z/cfreds_2015_data_leakage_pc.dd`, whose SHA-256 `026c1436…e4e2` is recorded in the manifest.

**9c. `$UsnJrnl` subset and `setupapi.dev.log`**

| Field | Value |
|---|---|
| Purpose | Extract the `$UsnJrnl` records between 13:30 and 14:19 UTC on 24 March 2015 for manual review. |
| Working directory | `data/artifacts/pc-run2` |
| Interpreter | PowerShell |
| Output | `usn_0935_1015.jsonl` (2.8 MB) |
| Provenance | Recorded — PowerShell history, primary workstation, lines 552–554 |

```powershell
cd $RM_ROOT\data\artifacts\pc-run2
Select-String -Path artifact-3.jsonl -Pattern '2015-03-24T(13:[3-5]\d|14:[01]\d)' | ForEach-Object { $_.Line } | Out-File usn_0935_1015.jsonl -Encoding utf8
Get-Item usn_0935_1015.jsonl | Format-Table Name, Length
```

`setupapi.dev.log` is not extracted with Dissect. Stage B reads the copy produced by `tsk_recover` (`data/exports/pc/Windows/inf/setupapi.dev.log`, the default of `--setupapi` in `tahap_b_adapter.py`, line 226). That file is byte-identical (SHA-256 `0588540A…65EB`) to `04_percobaan2_host_only/input_dissect/setupapi.dev.log`.

---

### Stage 10 — Stages B → C → D → E (TG 5–9)

All four scripts were run from `usb-forensics-starter/usb-forensics-starter` with **Py3.14** and **without arguments**, so they used their default paths under `data/`. The rerun script passes every argument explicitly, based on the argument parsers in `tahap_b_adapter.py` (lines 217–229), `tahap_c_label_kasus.py` (lines 25–32), `tahap_d_korelasi.py` (lines 217–223), and `tahap_e_eksperimen.py` (lines 109–118).

| Field | Value |
|---|---|
| Purpose | Normalise the artifacts (B), write the acquisition map and evaluation labels (C), correlate the evidence (D), and run the ablation and evaluation experiments (E). |
| Working directory | `usb-forensics-starter/usb-forensics-starter` |
| Interpreter | Py3.14 |
| Provenance | Recorded — PowerShell history, primary workstation, lines 562–583 |

```powershell
python tahap_b_adapter.py                                   # run 1 (before patch)
Select-String -Path $RM_ROOT\data\metadata\usb02_body.txt -Pattern "amalfi|winter_storm" | ForEach-Object { $_.Line.Split("|")[1,3] -join "   " }
(Get-Content tahap_b_adapter.py) -replace 'if not mode\.startswith\("r/"\):', 'if mode.startswith(("d/", "V/")):' | Set-Content tahap_b_adapter.py -Encoding ascii   # in-place patch
Select-String -Path tahap_b_adapter.py -Pattern 'mode.startswith'
python tahap_b_adapter.py                                   # final run
python tahap_c_label_kasus.py --serial-verified
python tahap_d_korelasi.py                                  # run 1 (before patch)
$r = Get-Content $RM_ROOT\data\results\correlated.json -Raw | ConvertFrom-Json
$r.files | Where-Object direction -eq 'pc_to_usb' | ForEach-Object {
  $f = $_
  $f.pc_candidates | ForEach-Object {
    [pscustomobject]@{ file = ($f.usb_path -split '/')[-1]; kandidat = $_.pc_entity; nama_asal = $_.earliest_name_seen; dibuat_pc = $_.created_on_pc_utc; dihapus_pc = $_.deleted_on_pc_utc }
  }
} | Format-Table -AutoSize | Out-File $RM_ROOT\data\results\kandidat.txt -Width 300
Get-Content $RM_ROOT\data\results\kandidat.txt
(Get-Content tahap_d_korelasi.py) -replace [regex]::Escape('segs = {c["pc_entity"] for r in leaked for c in r["pc_candidates"]}'), 'segs = {r["pc_candidates"][0]["pc_entity"] for r in leaked if len(r["pc_candidates"]) == 1}' | Set-Content tahap_d_korelasi.py -Encoding ascii   # in-place patch
Select-String -Path tahap_d_korelasi.py -Pattern 'segs = '
python tahap_d_korelasi.py                                  # final run
python tahap_e_eksperimen.py
$r = Get-Content $RM_ROOT\data\results\correlated.json -Raw | ConvertFrom-Json
($r.files | Where-Object usb_path -like '*landscape*').pc_candidates | Select-Object pc_entity, names_seen, name_acquired_utc | Format-List
Get-Content $RM_ROOT\data\results\eksperimen\experiments_summary.json | Select-String '"fp"|"device_wrong"|"direction_wrong"|"time_inconsistent"' -Context 0,1
```

Per-stage details:

| Stage | Input | Output | Expected result | Duration |
|---|---|---|---|---|
| **B** `tahap_b_adapter.py` | `usb02_complete.json`, `usb02_body.txt`, `pc-run2/artifact-0..3.jsonl`, `exports/pc/Windows/inf/setupapi.dev.log` | `normalized/events.json`, `events_report.json`, `device_inventory.json` | records/roots per group: fs_usb 82/41, **usnjrnl 412**/412, jumplist 2/2, lnk 2/1, setupapi 2/2 | 2–5 min |
| **C** `tahap_c_label_kasus.py --serial-verified` | `labels/rm2_labels.json` | `normalized/device_map.json`, `labels/case_labels.json` | serial **4C530012550531106501**, status `verified_against_nist_documentation`; 17 targets, 24 negatives | seconds |
| **D** `tahap_d_korelasi.py` | `usb02_complete.json`, `events.json`, `device_map.json`, `device_inventory.json` | `results/correlated.json` | **17/17 PC→USB**; transfer interval width **56–107 s, median 73 s**; `landscape.png` has **2 PC candidates** | seconds |
| **E** `tahap_e_eksperimen.py` | the above + `normalized/pc.json`, `exports/pc`, `labels/case_labels.json` | `results/eksperimen/baselines.json`, `experiments.csv`, `experiments_summary.json`, `correlated_full.json` | **6 evidence groups, 499 roots, 127 runs** (1 reference + 6 group removals + 4 × 30 random); `fp`, `device_wrong`, `direction_wrong`, `time_inconsistent` = **0** in every scenario. Baselines (recall on 17 targets): file name 0/17, hash 0/17, combined artifacts 17/17 | ≈1 min |

An optional 1,000-seed run of Stage E is described in the project notes (`00_BACA_DULU.md`; Provenance: Recorded, project notes). It has not been executed, so no reference output exists.

```powershell
python tahap_e_eksperimen.py --seeds 1000 --out-dir $RM_ROOT\data\results\eksperimen_1000
```

---

### Stage 11 — Experiment 2: host-only analysis (TG 5, TG 7; supporting experiment)

**11a. Dissect under Python 3.12**

| Field | Value |
|---|---|
| Purpose | Export the USB registry, LNK, Jump List, ShellBag, and filtered `$UsnJrnl` records from the PC image. |
| Interpreter | Py3.12 (secondary lab account) |
| Output | `04_percobaan2_host_only/input_dissect/` |
| Provenance | **Unavailable** — run from a secondary lab account whose shell history is not accessible from the primary workstation. The command forms below are **Reconstructed** (basis given after the block). The `$UsnJrnl` filter pattern and the way `setupapi.dev.log` was obtained cannot be reconstructed. |

Characteristics of the input files:

| File | Records | Record type (`recorddescriptor`) | Note |
|---|---|---|---|
| `usb_registry.jsonl` | 8 | `windows/registry/usb` | UTF-8 with BOM |
| `lnk.jsonl` | 207 | `windows/filesystem/lnk` | UTF-8 with BOM |
| `jumplist.jsonl` | 85 | `windows/jumplist` | UTF-8 with BOM |
| `shellbags.jsonl` | 125 | `windows/shellbag` | UTF-8 with BOM |
| `usn_filtered.jsonl` | 327 | `$UsnJrnl`, filtered | UTF-8 with BOM; records wrapped over 1,476 lines; `ts` from 2015-03-23T18:37 to 2015-03-25T15:14 UTC |
| `setupapi.dev.log` | — | not produced by Dissect | identical to the `tsk_recover` export |

```powershell
target-query "<pc.dd>" -f usb       -j | Out-File usb_registry.jsonl -Encoding utf8
target-query "<pc.dd>" -f lnk       -j | Out-File lnk.jsonl          -Encoding utf8
target-query "<pc.dd>" -f jumplist  -j | Out-File jumplist.jsonl     -Encoding utf8
target-query "<pc.dd>" -f shellbags -j | Out-File shellbags.jsonl    -Encoding utf8
target-query "<pc.dd>" -f usnjrnl   -j | Select-String <POLA TIDAK DIKETAHUI> | Out-File usn_filtered.jsonl -Encoding utf8
```

Basis for the reconstruction:
- Plugin names come from the record descriptors in the files. `shellbags` appears in `data/artifacts/pc-run2/plugins.jsonl`.
- The UTF-8 byte-order mark indicates output written with PowerShell 5.1 `Out-File -Encoding utf8`.
- The wrapped `$UsnJrnl` records match the loader in `analyze_cfreds.py` (line 16), which rejoins lines split by `Out-File`/`Select-String`.
- `<POLA TIDAK DIKETAHUI>` is a placeholder meaning “pattern unknown”.

`lnk.jsonl`, `jumplist.jsonl`, and `usb_registry.jsonl` are each exactly three bytes (the size of the BOM) larger than `pc-run2/artifact-2/1/0.jsonl`. Their contents are not byte-identical after the BOM is removed, so they come from separate Dissect runs.

**11b. Analysis runs on the primary workstation**

| Field | Value |
|---|---|
| Purpose | Classify transfer operations from the PC artifacts and compare them with the NIST ground truth. |
| Working directory | repository root; later `04_percobaan2_host_only` |
| Interpreter | Py3.14 (`analyze_cfreds.py` uses only the standard library) |
| Input | the Dissect files of Stage 11a, `ground_truth/truth_cfreds.json` |
| Output | console only |
| Provenance | Recorded — PowerShell history, primary workstation, lines 584–592, 598–599, 606–607. The command at line 586 ran before its script folder was created (lines 590–591). Earlier project notes describe the same analysis invoked with `py -3.12` and an ablation option `--drop shellbag`. |

```powershell
dir $RM_ROOT\*.jsonl
(Get-Content $RM_ROOT\lnk.jsonl).Count
python $RM_ROOT\skrip_b\analyze_cfreds.py --dir $RM_ROOT --truth $RM_ROOT\skrip_b\truth_cfreds.json
Get-ChildItem $DATA_DRIVE\, "$env:SystemDrive\Users" -Recurse -Filter usn_filtered.jsonl -ErrorAction SilentlyContinue | Select-Object FullName
dir "$RM_ROOT\cara 2"
Copy-Item $RM_ROOT\lnk.jsonl "$RM_ROOT\cara 2\"
New-Item -ItemType Directory -Force $RM_ROOT\skrip_b | Out-Null
Copy-Item "$env:USERPROFILE\Downloads\analyze_cfreds.py", "$env:USERPROFILE\Downloads\truth_cfreds.json" $RM_ROOT\skrip_b\
python $RM_ROOT\skrip_b\analyze_cfreds.py --dir "$RM_ROOT\cara 2" --truth $RM_ROOT\skrip_b\truth_cfreds.json

# Folder reorganisation (script kept outside the repository; log in _log_rapikan.txt)
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Downloads\rapikan_RM.ps1"
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Downloads\rapikan_RM.ps1" -Jalankan

# Last recorded analysis run
cd $RM_ROOT\04_percobaan2_host_only
python kode\analyze_cfreds.py --dir input_dissect --truth ground_truth\truth_cfreds.json
```

**11c. Evidence-loss experiment — `masking_path_b.py`**

| Field | Value |
|---|---|
| Purpose | Remove whole artifact groups, or a random 10/30/50/70 % of the raw records with recorded seeds, and re-run the classification each time. |
| Working directory | `04_percobaan2_host_only` |
| Interpreter | Py3.14 (standard library; it loads `analyze_cfreds.py` with three in-memory patches and does not modify the file) |
| Input | `input_dissect/{usn_filtered, shellbags, jumplist, lnk}.jsonl`, `kode/analyze_cfreds.py`, `ground_truth/truth_cfreds.json` |
| Output | `hasil/path_b_experiments_{30,1000}seed.csv`, `hasil/path_b_summary_{30,1000}seed.json` |
| Expected result (30 seeds) | **744 raw records** (usn 327, shellbag 125, jumplist 85, lnk 207); reference **6/6 operations correct**; operation 4 file names recovered **1/17**; accuracy (correct/6) at 10/30/50/70 % random removal = **1.00 / 0.90 / 0.67 / 0.34**; without usn/shellbag/jumplist/lnk = 0.17 / 0.50 / 0.67 / 0.83 |
| Expected result (1,000 seeds) | 0.99 / 0.88 / 0.63 / 0.37 |
| Duration | 30 seeds = 125 runs; 1,000 seeds = 4,005 runs (≈32 × longer). The original durations were not recorded |
| Provenance | 30 seeds: Recorded (project notes, `00_BACA_DULU.md`). 1,000 seeds: Reconstructed from the usage line of `masking_path_b.py` (line 19; the fifth argument is the number of seeds, line 27). File renaming to `_30seed`/`_1000seed`: Reconstructed. The script always writes `path_b_experiments.csv` and `path_b_summary.json` (lines 125 and 140), so the suffixed names were applied by hand; no command was recorded. |

```powershell
cd $RM_ROOT\04_percobaan2_host_only
python kode\masking_path_b.py input_dissect kode\analyze_cfreds.py ground_truth\truth_cfreds.json hasil\ulang 30
python kode\masking_path_b.py input_dissect kode\analyze_cfreds.py ground_truth\truth_cfreds.json hasil\ulang 1000
```

---

## 6. Reproducing the results

The scripts in `rerun/` repeat Stages 0–11. They only read the original data and write only to `$RERUN_ROOT`, whose `data/` subfolder mirrors `data/`. Each script records a transcript in `$RERUN_ROOT\logs\<script>.log`. Scripts that have hard-coded paths and no argument parser (`make_rm2_labels.py`, `scan_pc_filtered.py`) are run as copies in `$RERUN_ROOT\kode_salinan\`, with only the path constants replaced (and, for `scan_pc_filtered.py`, the invalid first line removed). The supervisor's code is neither copied nor modified. A script refuses to overwrite existing output, so to repeat a stage, remove or rename that stage's output folder first.

Run from a regular PowerShell session, not from inside a virtual environment:

```powershell
cd $RM_ROOT\rerun
powershell -ExecutionPolicy Bypass -File .\00_env.ps1
powershell -ExecutionPolicy Bypass -File .\01_hash.ps1           # long: about 10 min (hashes the 24 GB of images twice)
powershell -ExecutionPolicy Bypass -File .\02_extract.ps1        # optional, long, +25 GB
powershell -ExecutionPolicy Bypass -File .\03_mmls.ps1
powershell -ExecutionPolicy Bypass -File .\04_tsk_recover.ps1    # long: about 9 min, +21 GB
powershell -ExecutionPolicy Bypass -File .\05_uji_dosen.ps1
powershell -ExecutionPolicy Bypass -File .\06_tahap_a_labels.ps1
powershell -ExecutionPolicy Bypass -File .\07_scan_pc_analyze.ps1
powershell -ExecutionPolicy Bypass -File .\08_fls_timeline.ps1   # several minutes (126 MB PC timeline)
powershell -ExecutionPolicy Bypass -File .\09_dissect.ps1        # about 5 min
powershell -ExecutionPolicy Bypass -File .\10_tahap_bcde.ps1     # 3-7 min; add -Seeds1000 for the 1,000-seed test
powershell -ExecutionPolicy Bypass -File .\11_percobaan2.ps1     # the 1,000-seed run is the longest; -Lewati1000 skips it
powershell -ExecutionPolicy Bypass -File .\verify.ps1            # may be run at any time
```

| Script | Stage | Interpreter | Duration / disk | Parameters |
|---|---|---|---|---|
| `00_env.ps1` | 0 | Py3.14, Py3.11-venv | short | `-BuatVenvBaru`: build a new Dissect environment from `environment.txt` (Reconstructed) |
| `01_hash.ps1` | 1 | PowerShell | ≈10 min | `-TanpaImage`: skip image hashing |
| `02_extract.ps1` | 2 | WinRAR / 7-Zip | long, +25 GB, optional | `-Alat WinRAR\|7zip` |
| `03_mmls.ps1` | 3 | The Sleuth Kit | short | — |
| `04_tsk_recover.ps1` | 4 | The Sleuth Kit | ≈9 min, +21 GB | `-LewatiPC`: export RM#2 only |
| `05_uji_dosen.ps1` | 5 | Py3.14 | short | — |
| `06_tahap_a_labels.ps1` | 6 (+ USB02 inventory) | Py3.14 | short | — |
| `07_scan_pc_analyze.ps1` | 7 | Py3.14 | short | — |
| `08_fls_timeline.ps1` | 8 | The Sleuth Kit + Py3.14 | several minutes | — |
| `09_dissect.ps1` | 9 | Py3.11-venv | ≈5 min | `-Venv <folder>` |
| `10_tahap_bcde.ps1` | 10 | Py3.14 | 3–7 min | `-InputAsli`: read upstream inputs from `data/` (read-only); `-Seeds1000` |
| `11_percobaan2.ps1` | 11 | Py3.14 | 1,000 seeds is the longest step | `-Lewati1000`; `-Dissect312 -Venv312 <folder>` (Reconstructed Dissect commands) |
| `verify.ps1` | — | PowerShell | ≈2 min | `-TanpaHitungEkspor`: skip counting the 80,000-file PC export |

Dependencies: Stage 6 requires Stage 4; Stage 7 requires Stages 4 and 6; Stage 8 requires the images (and Stage 4 for `setupapi.dev.log`); Stage 10 requires Stages 4, 6, 7, 8, and 9; Stage 11 requires only `04_percobaan2_host_only/` and, for the alternative LNK input, `data/artifacts/pc-run2/artifact-2.jsonl`.

Besides the published runs, `11_percobaan2.ps1` runs `analyze_cfreds.py` a second time with `lnk.jsonl` replaced by the Experiment 1 LNK export (`pc-run2/artifact-2.jsonl`), and compares both outputs as a robustness check.

**Status values written by `verify.ps1`** (to `$RERUN_ROOT\logs\verify.txt` and `verify.csv`):

| Status | Meaning |
|---|---|
| `SAMA` | identical: the reproduced file is byte-identical to the original |
| `SAMA*` | identical after normalising the output root (`$RERUN_ROOT` → `$RM_ROOT`); applies to files that record their own input/output paths, e.g. `events_report.json`, `manifest.json` |
| `BEDA` | different content; see the key figures (some files contain processing times, e.g. `pc_filter_stats.json`) |
| `BELUM` | not yet produced; the corresponding stage has not been run |
| `TANPA PEMBANDING` | no original file exists to compare with |

For key figures, `verify.ps1` recomputes each value from the original and the reproduced files and compares both with the reference value.

---

## 7. Reproduction results

`verify.ps1` had not been executed when this document was prepared. This table is to be completed from `$RERUN_ROOT\logs\verify.txt`.

| Stage | Key figure | Reference | Reproduced | Status |
|---|---|---|---|---|
| 1 | Archive SHA-1 values matching NIST | 6/6 | — | pending |
| 1 | Image SHA-1 + SHA-256 matching record | 4/4 | — | pending |
| 3 | Partition offsets PC / RM#2 | 206848 / 128 | — | pending |
| 4 | Files exported RM#2 / PC (on disk) | 41 / 80,778 | — | pending |
| 4 | `tsk_recover` “Files Recovered” RM#2 / PC | 41 / 80,927 | — | pending |
| 5 | Unit tests | 15/15 OK | — | pending |
| 6 | Labels: targets / negatives | 17 / 24 | — | pending |
| 6 | Stage A: complete RM#2 files | 17/41 | — | pending |
| 7 | Filtered PC scan: total / distinct sizes / hashed | 80,778 / 41 / 51 | — | pending |
| 7 | Hash pairs PC ↔ RM#2 | 3, all `desktop.ini` | — | pending |
| 8 | Target creation times (EDT) | 17 files, 09:59:27–10:00:18 | — | pending |
| 9 | Dissect `pc-run2` runs with return code 0 | 7/7 | — | pending |
| 10 | Stage B records (usn / fs_usb / jumplist / lnk / setupapi) | 412 / 82 / 2 / 2 / 2 | — | pending |
| 10 | Evidence groups / roots | 6 / 499 | — | pending |
| 10 | Stage D: PC→USB, interval width | 17/17, 56–107 s, median 73 s | — | pending |
| 10 | Stage D: candidates for `landscape.png` | 2 | — | pending |
| 10 | Stage E: runs, maximum of fp + device_wrong + direction_wrong + time_inconsistent | 127, 0 | — | pending |
| 11 | Raw records (usn / shellbag / jumplist / lnk) | 744 (327 / 125 / 85 / 207) | — | pending |
| 11 | Masking, 30 seeds: reference; accuracy 10/30/50/70 % | 6/6; 1.00 / 0.90 / 0.67 / 0.34 | — | pending |
| 11 | Masking, 1,000 seeds: accuracy 10/30/50/70 % | 0.99 / 0.88 / 0.63 / 0.37 | — | pending |

---

## 8. Known gaps and limitations

1. **Export count discrepancy.** `tsk_recover` reported 80,927 recovered files for the PC image, but 80,778 files are present on disk. Four Internet Explorer cache files are known to have failed because their paths exceed the 260-character Windows limit. The remaining 145 have not been accounted for.
2. **Undocumented regeneration of `pc_timeline.csv`.** The timestamp of `data/metadata/pc_timeline.csv` (11:55:55) is later than that of `pc_0935_1015.txt` (10:58:29), which is derived from it. The timeline was therefore written again after the recorded command, and the command for that rewrite is not recorded.
3. **Experiment 2 Dissect commands.** The Dissect exports used in Experiment 2 were produced under Python 3.12 on a secondary lab account whose shell history is not accessible. The exact Python version, package list, `$UsnJrnl` filter pattern, and source of `setupapi.dev.log` are unavailable. Section 5, Stage 11a gives reconstructed command forms for the other four exports.
4. **In-place patches to Stage B and Stage D.** `tahap_b_adapter.py` (line 73) and `tahap_d_korelasi.py` (line 183) were modified in place during the analysis (history lines 564 and 577). The current files contain these patches, and the published outputs were produced after patching. The first run of each script (history lines 562 and 568) used the unpatched versions, and those versions are not preserved.
5. **`scan_pc_filtered.py` in its current form.** Line 1 of the file is a `//` comment, which is not valid Python syntax, so the file in its current form cannot be executed. The reproduction runs a copy without that line.
6. **Archive extraction.** Extraction was performed in the WinRAR interface. Only a command-line equivalent can be given.
7. **Unrecorded runs.** The 1,000-seed run of Experiment 2 and the renaming of its outputs were not recorded. The 1,000-seed variant of Stage E has never been run.
8. **Sources without research commands.** Transcripts of earlier AI-assisted sessions contain only read-only inspection commands, not research commands.
9. **Cosmetic whitespace.** In some command blocks (Stages 1, 4, 11a) the column alignment differs from the shell history. Only the number of spaces between tokens differs; the meaning of the commands is unchanged.

---

## 9. Acknowledgment of AI assistance

The additional scripts in this repository were written with assistance from Claude (Anthropic): the stage scripts `tahap_a_*.py` to `tahap_e_*.py`, `scan_pc_filtered.py`, `make_rm2_labels.py`, `body2csv.py`, `analyze_cfreds.py`, and `masking_path_b.py`, as well as the reproduction scripts in `rerun/` and this command record. The author executed all analyses and verified the results. The supervisor's code (`usb_forensics.py`, `demo.py`, `extract_pc_artifacts.py`, `test_usb_forensics.py`) was used without modification.
