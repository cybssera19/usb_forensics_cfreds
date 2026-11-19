# Atribusi dan lisensi

## Kode dosen (tidak diubah)
`src/usb_forensics.py`, `src/extract_pc_artifacts.py`, `src/demo.py`, `src/test_usb_forensics.py`, dan
`docs/README_dosen.md` berasal dari paket starter yang diberikan dosen pembimbing dan dipakai **tanpa modifikasi**.

> TODO sebelum repositori dibuat publik: pastikan dengan dosen bahwa kode tersebut boleh dipublikasikan, dan tentukan
> lisensinya. Jika belum jelas, buat repositori **private** atau hapus berkas-berkas itu dari repositori.

## Data
Dataset **NIST CFReDS Data Leakage Case** (<https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html>)
tidak disertakan. Folder `labels/` dan `percobaan2/ground_truth/` memuat label yang disusun dari kunci jawaban NIST
(Q53 sampai Q55, Q59), dan `percobaan2/input_dissect/` memuat keluaran Dissect dari image tersebut. Periksa ketentuan
penggunaan NIST sebelum mempublikasikan.

## Bantuan AI
Skrip tambahan ditulis dengan bantuan Claude (Anthropic): `tahap_a_*.py` sampai `tahap_e_*.py`, `scan_pc_filtered.py`,
`make_rm2_labels.py`, `body2csv.py`, `analyze_cfreds.py`, `masking_path_b.py`, skrip `rerun/`, prototipe `tools/`, dan
`docs/COMMANDS_formal.md`. Seluruh analisis dijalankan dan hasilnya diverifikasi oleh penulis.

## Lisensi
[Belum ditentukan. Tambahkan berkas LICENSE setelah ada keputusan.]
