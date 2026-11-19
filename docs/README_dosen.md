# Riset forensik perpindahan dokumen ke USB

Tujuan: menilai dokumen yang muncul pada komputer dan USB, menghubungkannya dengan perangkat fisik, memperkirakan waktu kejadian sesuai bukti, serta mengukur perubahan kesimpulan ketika bukti berkurang.

Judul kerja: **Rekonstruksi Perpindahan Dokumen ke USB melalui Korelasi Artefak Windows dan Evaluasi Kehilangan Bukti**.

Paket ini adalah prototipe pembelajaran dengan Python standard library. Mesin pencocokan, demo, dan eksperimen dapat dijalankan. Ekstraksi image NIST, adapter normalisasi Dissect, pemetaan perangkat fisik, dan inferensi interval dari beberapa artefak belum diimplementasikan sebagai satu proses otomatis. Jangan menyebut hasil demo sebagai temuan NIST.

## 1. Dataset penelitian

Gunakan [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html).

| Komponen | Kegunaan | Unduhan |
|---|---|---|
| PC | Dokumen dan artefak Windows 7/NTFS | pc.7z.001–003, total sekitar 5,05 GB terkompresi |
| RM#2 | USB tujuan yang diperiksa, FAT32 | rm#2.7z, sekitar 219 MB |
| Seed files | Dokumen acuan untuk pengenalan isi | seed-files.7z, sekitar 150 MB |
| RM#1 | USB resmi perusahaan, tambahan analisis sumber | rm#1.E01, sekitar 74,5 MB |

Ambil tautan unduhan dari halaman resmi; karakter # dalam nama file harus diperlakukan benar oleh downloader. Untuk mulai, gunakan PC, RM#2, dan seed files. Jangan memasukkan inventaris seed sebagai bukti bahwa file ada pada PC.

[Dokumentasi jawaban](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) menyediakan pembanding kasus. Bagian 53–55 membahas pemulihan RM#2 dan dokumen terkait. RM#2 mengalami quick format; pemulihan isi tidak selalu lengkap. Pisahkan label pembanding dari input algoritma.

Dataset ini satu skenario lama, bukan sampel representatif semua versi Windows. Tambahkan eksperimen Windows dengan pencatatan aksi yang terkontrol sebelum membuat klaim generalisasi.

## 2. Empat hasil yang dipisahkan

1. Identitas dokumen: isi yang sama pada dua lokasi.
2. Identitas media: image mana dan, bila pemetaannya tersedia, flashdisk fisik mana.
3. Arah dan waktu: apa yang benar-benar didukung artefak.
4. Dasar kesimpulan: sumber, lokasi record, dan dependensi bukti.

SHA-256 dan ukuran yang sama pada dua file utuh mendukung identitas isi. Nama file berbeda tidak menggagalkan pencocokan. Jika pemulihan parsial, kesamaan hanya berlaku untuk byte hasil ekspor.

Kesamaan isi tidak membuktikan sumber penyalinan. Dua file bisa berasal dari lokasi ketiga. Waktu file dibuat/dibuka juga tidak otomatis menjadi waktu penyalinan.

Gunakan status terpisah, misalnya identical_content, device_unresolved, direction_unknown, dan time_unknown. Hindari skor persentase keyakinan yang belum dikalibrasi.

## 3. Jalankan demo terlebih dahulu

Kebutuhan mesin pencocokan: Python 3.9 atau lebih baru; tidak memerlukan pip.

Di direktori paket:

~~~bash
python3 -m unittest -v
python3 demo.py --out demo-baru
~~~

Nama direktori output harus baru. Demo membuat:

- anggaran.txt pada PC dan foto_liburan.jpg pada USB, dengan byte yang sama.
- catatan.txt pada kedua media, dengan isi berbeda.
- Satu referensi aktivitas sintetis.
- Satu catatan operasi penyalinan sintetis yang menyebut kedua file secara eksplisit.

File berekstensi .jpg pada demo berisi teks, sengaja untuk mencontohkan penggantian ekstensi.

Hasil terdapat pada demo-baru/summary.json dan demo-baru/results/. Sampel hasil pengujian juga disertakan dalam demo-output/.

| Skenario | Pasangan identik | Arah |
|---|---:|---|
| Semua bukti | 1 | PC → USB, dilaporkan catatan operasi sintetis |
| Tanpa referensi aktivitas | 1 | Tetap dilaporkan catatan operasi |
| Tanpa catatan operasi | 1 | Tidak diketahui |
| Tanpa bukti isi | 0 | Tidak dapat dinilai |
| Penghilangan acak 30%, seed 42 | 1 | Tidak diketahui |

Angka ini hanya hasil fixture kecil, bukan akurasi penelitian.

## 4. Siapkan data NIST

Buat direktori terpisah untuk raw, exports, artifacts, normalized, results, dan labels. Simpan arsip serta image asli dan kerjakan salinannya.

Bandingkan checksum menggunakan algoritma yang sama dengan [checksum resmi](https://cfreds-archive.nist.gov/data_leakage_case/hash_values.html), lalu simpan SHA-256 tambahan pada manifest penelitian. Catat image asal, versi alat, perintah, waktu ekstraksi, dan hash output.

Unduh seluruh bagian arsip PC sebelum mengekstrak bagian pertama. Nama pc.dd dan usb02.dd di bawah adalah contoh nama image setelah ekstraksi; sesuaikan dengan file sebenarnya.

Ekspor file dengan alat forensik. Contoh Sleuth Kit:

~~~bash
tsk_recover -e data/raw/pc.dd data/exports/pc
tsk_recover -e data/raw/usb02.dd data/exports/usb02
~~~

-e meminta ekspor file allocated dan unallocated. Jika perlu memilih partisi, lihat tabel partisi image, lalu gunakan -o dengan offset sektor yang benar. Jangan menyalin nilai offset dari kasus lain. Baca [manual tsk_recover](https://www.sleuthkit.org/sleuthkit/man/tsk_recover.html).

Ekspor ini tidak menjamin semua file terhapus ditemukan. Evaluasi struktur FAT dan kebutuhan carving bila hasil kosong/parsial. Catat mana file utuh dan mana fragmen. Simpan pemetaan export_path ke image, partisi, metadata entry/offset, dan original_path jika tersedia. Label carved_file_001 tidak otomatis merupakan nama asli.

**Jangan menggunakan waktu pembuatan/modifikasi folder hasil ekspor sebagai waktu kejadian asli.** Metadata harus dibaca dari image. NTFS menyimpan waktu UTC; FAT menyimpan waktu lokal dengan ketelitian yang berbeda. Simpan nilai mentah, zona waktu sumber dan ketelitian sebelum konversi. Lihat [Microsoft File Times](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times).

## 5. Buat inventaris dan cocokkan isi

Tanpa --complete, program hanya mengklaim kesamaan byte ekspor:

~~~bash
python3 usb_forensics.py scan --folder data/exports/pc --media PC --out data/normalized/pc.json
python3 usb_forensics.py scan --folder data/exports/usb02 --media USB02 --out data/normalized/usb02.json
python3 usb_forensics.py analyze --inputs data/normalized/pc.json data/normalized/usb02.json --out data/results/matches.json
~~~

Jika semua file dalam suatu direktori telah diverifikasi sebagai ekspor utuh, tambahkan --complete saat scan. Untuk kumpulan campuran, pertahankan default lalu tandai complete:true hanya pada record yang telah diverifikasi, dengan catatan pemeriksaan di manifest pendamping.

Scanner memeriksa semua file, sehingga dokumen dengan ekstensi samaran tetap ditemukan. Hasil juga dapat mencakup file non-dokumen; kurasi jenis dokumen memakai signature/struktur internal, bukan ekstensi saja. Hash berbeda pada file yang diedit tidak dideteksi metode exact-match ini. Analisis kemiripan isi adalah pengembangan terpisah.

Contoh pemanggilan langsung:

~~~python
from usb_forensics import scan_export, analyze, write_json

# complete=True hanya untuk ekspor yang telah diperiksa utuh.
pc = scan_export("data/exports/pc", "PC", complete=False)
usb = scan_export("data/exports/usb02", "USB02", complete=False)

report = analyze(pc + usb)
write_json("data/results/matches.json", report)

for item in report["matches"]:
    print(item["pc_path"], "=>", item["usb_path"])
    print(item["identity_status"], item["direction"])
~~~

Identitas instance file memakai media dan path; identitas isi memakai hash dan ukuran. Bila dua file PC identik dengan satu file USB, program mempertahankan kedua kandidat. Tidak memilih satu sumber secara sewenang-wenang.

Input selain media PC dianggap media tujuan oleh mesin prototipe. Masukkan hanya inventaris USB tujuan pada analisis tersebut; inventaris seed harus dianalisis secara terpisah.

## 6. Ambil artefak Windows

[Dissect](https://docs.dissect.tools/en/latest/install.html) menyediakan antarmuka Python/CLI untuk membaca artefak image. Pasang dalam virtual environment:

~~~bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install dissect
python -m pip freeze > environment.txt
target-query data/raw/pc.dd -l
~~~

Pada Windows, aktivasi menggunakan .venv\Scripts\Activate.ps1. Simpan versi Python dan daftar paket bersama hasil.

Periksa fungsi kompatibel pada image, lalu gunakan fungsi yang tersedia, misalnya:

~~~bash
target-query data/raw/pc.dd -f usb -j > data/artifacts/usb.jsonl
target-query data/raw/pc.dd -f jumplist -j > data/artifacts/jumplist.jsonl
~~~

Buat folder data/artifacts terlebih dahulu. Dokumentasi [target-query](https://docs.dissect.tools/en/latest/target-query.html) menjelaskan opsi -l, -f, dan -j. Tidak semua plugin akan menghasilkan record pada setiap image.

Wrapper Python dalam paket dapat mencatat perintah, return code, output, stderr, serta hash:

~~~bash
python3 extract_pc_artifacts.py --image data/raw/pc.dd --out artifacts-baru --plugins usb jumplist lnk usnjrnl evtx
~~~

Status raw_export_needs_review berarti output perlu diperiksa, bukan bukti bahwa parsing lengkap atau interpretasinya benar. Daftar plugin dan versi juga disimpan sebagai output teks walau nama file wrapper menggunakan akhiran .jsonl. Periksa manifest untuk membedakannya.

**Output mentah Dissect belum dapat langsung dimasukkan ke analyze.** Buat adapter setelah memeriksa nama field, jenis timestamp, path, volume, dan record sumber yang benar-benar tersedia. Jangan mengubah seluruh timestamp menjadi “file dibuka” atau “file disalin”.

## 7. Hubungkan USB fisik, file, dan waktu

Tabel pemetaan perangkat sebaiknya memuat:

- ID image akuisisi dan serial perangkat fisik dari dokumentasi akuisisi.
- Identitas perangkat Windows dari Registry.
- Identitas volume serta bukti yang menghubungkannya dengan perangkat.
- Huruf drive beserta konteks waktu jika tersedia.
- Lokasi record sumber untuk setiap hubungan.

Serial perangkat keras dan volume serial bukan field yang sama. E: bisa digunakan perangkat lain pada waktu berbeda. USB02 pada kode hanya label image, bukan hasil identifikasi hardware.

LNK/JumpList memberikan referensi file dan informasi target tertentu; USB artifacts membantu riwayat perangkat. Cocokkan path bersama konteks volume dan waktu, bukan nama file atau huruf drive saja. Lihat dokumentasi [USB](https://docs.dissect.tools/en/latest/plugins/usb.html) dan [JumpList](https://docs.dissect.tools/en/latest/plugins/jumplist.html).

Contoh record normalisasi yang dibuat setelah peninjauan:

~~~json
{
  "id": "ref-001",
  "root_id": "record-asli-001",
  "depends_on": [],
  "kind": "file_reference",
  "group": "access",
  "file_id": "<ID file dari inventaris>",
  "time": "2015-03-24T07:05:00+00:00",
  "time_semantic": "<arti timestamp menurut artefak>",
  "source": "<path artefak dalam image PC>",
  "locator": "<nomor record atau offset>"
}
~~~

Angka waktu di contoh adalah placeholder, bukan hasil pemeriksaan NIST. Simpan record dalam JSON array. Isi depends_on dengan ID bukti yang benar-benar diperlukan untuk pemetaan. Bila dua ekspor berasal dari record mentah yang sama, gunakan root_id yang sama.

~~~bash
python3 usb_forensics.py analyze --inputs data/normalized/pc.json data/normalized/usb02.json data/normalized/events.json --out data/results/correlated.json
~~~

Mesin menyajikan referensi aktivitas bersama sumbernya. copy_operation hanya boleh digunakan jika tersedia catatan operasi eksplisit yang mengidentifikasi sumber, tujuan, dan interval. Jangan mengubah LNK atau catatan USB terpasang menjadi copy_operation. Demo memiliki catatan tersebut karena aksinya dibuat secara terkontrol; keberadaannya pada NIST tidak diasumsikan.

Untuk tahap riset berikutnya, buat mesin interval bersyarat:

1. Susun kandidat sesi perangkat dari bukti koneksi yang tersedia.
2. Hubungkan referensi file dengan sesi dan volume yang benar.
3. Bedakan waktu first seen, akses, perubahan isi, dan metadata.
4. Simpan batas waktu hanya bila hubungan sebab-akibatnya mendukung batas itu.
5. Jika beberapa sesi masih mungkin, pertahankan semuanya.
6. Jika hubungan bertentangan atau batas tidak tersedia, keluarkan unknown.

Contoh: USB terpasang pukul 10.00 dan file diakses pukul 10.05 tidak otomatis membuktikan disalin antara 10.00–10.05; file mungkin sudah ada dari sesi sebelumnya. Interval itu hanya menjadi hipotesis bersyarat jika asumsi tambahannya dinyatakan dan diperiksa. Modul inferensi interval ini belum ada dalam kode prototipe.

## 8. Eksperimen kehilangan jejak

Hapus bukti dari salinan input eksperimen, bukan image asli.

~~~bash
python3 usb_forensics.py experiment --inputs demo-output/pc.json demo-output/usb02.json demo-output/events.json --drop-group operation_log --truth demo-output/truth_identity_pairs.json --out experiment-no-operation.json
python3 usb_forensics.py experiment --inputs demo-output/pc.json demo-output/usb02.json demo-output/events.json --fraction 0.3 --seed 42 --truth demo-output/truth_identity_pairs.json --out experiment-random.json
~~~

Jalankan proporsi 0%, 10%, 30%, 50%, 70%, dengan misalnya 30 seed pada data yang memadai. Jumlah root yang hilang dibulatkan ke bawah; laporkan jumlah aktual. Bandingkan juga kehilangan satu keluarga artefak seluruhnya, misalnya LNK atau Registry, pada dataset normalisasi yang telah Anda bangun.

Setiap percobaan harus membangun kembali pemetaan dan kesimpulan dari bukti yang masih tampak. Jangan menggunakan pemetaan USB atau fitur yang dihitung dari dataset lengkap jika bukti pembentuknya sudah dihilangkan.

Dalam paket, mask_records menghapus seluruh record dengan root_id terpilih dan dependensinya secara transitif. group menentukan keluarga bukti. Penamaan root_id harus mengikuti unit kehilangan yang Anda teliti: record, file artefak, atau volume; jelaskan unit tersebut di metodologi. Eksperimen kehilangan record tidak sama dengan simulasi penghapusan fisik sektor.

## 9. Evaluasi yang tepat

Kunci jawaban/label disimpan terpisah dan tidak dibaca oleh analyze. Tetapkan label dari dokumentasi skenario serta pemeriksaan independen; catat bagian yang ambigu. Kunci jawaban NIST bukan label lengkap otomatis untuk setiap record.

Ukur tiap pertanyaan secara terpisah:

| Pertanyaan | Evaluasi |
|---|---|
| Dokumen identik apa saja? | Precision dan recall pasangan identitas |
| USB fisik mana? | Ketepatan atribusi, jumlah unknown, coverage |
| Arah perpindahan? | Ketepatan arah pada label yang diketahui; unknown dilaporkan |
| Kapan? | Error waktu/coverage interval pada kasus berlabel dan lebar interval |
| Urutan kejadian? | Proporsi pasangan event berlabel yang urutannya benar |

Fungsi identity_metrics dalam paket **hanya menghitung identitas isi**, bukan akurasi transfer, atribusi perangkat, atau kronologi. Precision yang tidak punya prediksi ditulis null, bukan 0 atau 100%. Penyebut recall tetap memakai label awal meskipun bukti dihilangkan.

Bandingkan baseline nama file, baseline exact hash, dan sistem gabungan setelah modul artefak selesai. Tambahkan contoh negatif: USB hanya dipasang, dokumen hanya dibuka, USB lain dengan huruf drive sama, nama sama isi berbeda, file serupa yang berasal dari sumber ketiga.

Pertanyaan riset yang dapat diuji: “Jenis bukti mana yang menjaga ketepatan atribusi dan urutan kejadian, serta pada tingkat kehilangan berapa sistem harus lebih sering menyatakan belum diketahui?”

## 10. Status validasi paket

Dijalankan pada Python 3.12.0: 15 unit test lulus dan lima skenario demo berhasil. Pengujian mencakup perubahan nama, nama sama dengan isi berbeda, file parsial, timestamp tanpa zona, dependensi bukti, duplikasi asal bukti, arah terbalik, dan beberapa kandidat sumber.

Image NIST berukuran besar belum diunduh/dianalisis dalam pembuatan paket ini. Wrapper Dissect disiapkan berdasarkan dokumentasi dan belum diuji terhadap image tersebut. Hasil nyata penelitian masih harus dihasilkan setelah ekstraksi, normalisasi, dan penilaian ground truth.

Urutan kerja praktis: jalankan demo → ekstrak PC/RM#2 → audit ekspor → inventaris/hash → periksa artefak → buat pemetaan perangkat dan adapter → jalankan korelasi → siapkan label → lakukan ablation → tulis temuan dan batasannya.
