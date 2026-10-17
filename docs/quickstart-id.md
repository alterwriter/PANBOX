# Mulai cepat PANBOX

Untuk instalasi baru, ikuti [panduan operator dan DevOps](product-guide-id.md): bagian 3/4 menyiapkan dashboard sekali, bagian 5 menambahkan **agent saja** ke pipeline, dan bagian 6 memilih jalur SCM publik ke PANBOX privat. Contoh di bawah adalah fixture lokal pada mesin pengembangan ini, bukan langkah wajib bagi runner CI.

PANBOX demo lokal sudah berjalan di `http://127.0.0.1:8092`. Email admin dan password acak ada di `.env` lokal yang diabaikan Git. Dua repo demo dan empat scan fixture sudah dimuat.

Untuk menjalankan ulang dari folder `PANBOX`:

```powershell
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
```

Kalau membuat instalasi baru, jalankan `./scripts/init-local.ps1 -HostPort 8092` sebelum Docker Compose. Jangan menjalankannya jika `.env` sudah ada; password bootstrap hanya dipakai saat database pertama kali dibuat.

Di UI:

1. **Repositories → Enroll repository**: pilih provider SCM, isi nama tampilan dan ID/path SCM stabil (contoh `alterwriter/PANBOX`), lalu klik **Test SCM connectivity and detect branch**. Untuk repo publik, default branch terisi otomatis; jika metadata privat/tidak terjangkau, isi branch manual dan konfirmasi tes di runner. Owner boleh kosong karena hanya label, bukan hak akses. Status SCM terlihat di tabel dan dapat diuji ulang dengan **Recheck SCM**. PANBOX tidak otomatis membuat repo dari scan pertama.
2. Salin **PANBOX ID for CI** dari dialog hasil atau kolom tabel Repositories. Ini ID internal PANBOX, berbeda dari path SCM. Isi variabel CI `PANBOX_REPOSITORY_ID` dengan ID ini.
3. **Generate scan key** pada dialog hasil atau baris repo. Simpan secret yang muncul sekali sebagai variabel CI `PANBOX_TOKEN` yang masked/protected. Key hanya berlaku untuk repo itu.
4. **Scan policy**: pilih modul, ambang gate, dan apakah scan baru aktif. Isi `PANBOX_SERVER` dengan URL API yang bisa dijangkau runner; agent mengambil policy sebelum scan online.
5. **Settings & Audit → RBAC**: buat role, assign user, lalu atur akses repo per user. `admin` tetap role tertinggi.
6. **Settings & Audit → API & access keys**: API key untuk integrasi dengan scope eksplisit; access key hanya untuk operasi baca. Nilai key hanya terlihat sekali.
7. **Findings → Recast severity** ada di samping rule temuan pada kolom pertama. Jika tidak terlihat, cek scan/filter serta izin `findings:recast` dan membership repo. **Reports** mengekspor PDF/CSV/JSON menurut repo, branch, modul, dan severity. **Settings & Audit → MCP setup** memuat konfigurasi bridge hanya-baca.

Tiap scan melaporkan branch checkout secara otomatis; branch fitur baru langsung muncul di Scans/Findings/Reports tanpa pendaftaran ulang. Overview memakai default branch yang didaftarkan, bukan branch dari scan pertama. Tes SCM di dashboard berbeda dari tes checkout SCM dan koneksi API di runner.

Untuk SCM publik ke dashboard lokal tanpa IP publik/domain, jalur termudah adalah runner lokal yang polling SCM melalui HTTPS keluar. Jalur SSH relay bisa membuat quality gate sinkron dari shared runner. Jalur pull artifact tidak memerlukan relay, tetapi hasil gate baru masuk dashboard setelah job selesai. Detail dan contoh YAML ada di [README.md](../README.md) dan folder `deploy/`.

Angka RAM yang diukur dalam fixture demo adalah sekitar 5 MiB untuk server dan 37 MiB untuk PostgreSQL; uji beban di Debian target masih diperlukan. Agent native PANBOX berjalan di runner, bukan container dashboard. ENETRON memakai data advisory OSV melalui HTTPS.
