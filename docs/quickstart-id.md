# Mulai cepat PANBOX

Untuk instalasi baru, ikuti [panduan operator dan DevOps](product-guide-id.md): bagian 3/4 menyiapkan dashboard sekali, bagian 5 menambahkan **agent saja** ke pipeline, dan bagian 6 memilih jalur SCM publik ke PANBOX privat. Contoh di bawah adalah fixture lokal pada mesin pengembangan ini, bukan langkah wajib bagi runner CI.

PANBOX demo lokal sudah berjalan di `http://127.0.0.1:8092`. Email admin dan password acak ada di `.env` lokal yang diabaikan Git. Dua repo demo dan empat scan fixture sudah dimuat.

Untuk menjalankan ulang dari folder `PANBOX`:

```powershell
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
```

Kalau membuat instalasi baru, jalankan `./scripts/init-local.ps1 -HostPort 8092` sebelum Docker Compose. Jangan menjalankannya jika `.env` sudah ada; password bootstrap hanya dipakai saat database pertama kali dibuat.

Di UI:

1. **Repositories → Enroll repository**: pilih provider SCM dan masukkan ID/path repositori stabil.
2. **Generate scan key** di baris repo tersebut. Simpan sebagai variabel CI `PANBOX_TOKEN` yang masked/protected dan simpan ID internal sebagai `PANBOX_REPOSITORY_ID`.
3. **Settings & Audit → RBAC**: buat role, assign user, lalu atur akses repo per user. `admin` tetap role tertinggi.
4. **Settings & Audit → API & access keys**: API key untuk integrasi dengan scope eksplisit; access key hanya untuk operasi baca. Nilai key hanya terlihat sekali.

Untuk SCM publik ke dashboard lokal tanpa IP publik/domain, jalur termudah adalah runner lokal yang polling SCM melalui HTTPS keluar. Jalur SSH relay bisa membuat quality gate sinkron dari shared runner. Jalur pull artifact tidak memerlukan relay, tetapi hasil gate baru masuk dashboard setelah job selesai. Detail dan contoh YAML ada di [README.md](../README.md) dan folder `deploy/`.

Angka RAM yang diukur dalam fixture demo adalah sekitar 5 MiB untuk server dan 37 MiB untuk PostgreSQL; uji beban di Debian target masih diperlukan. Agent native PANBOX berjalan di runner, bukan container dashboard. ENETRON memakai data advisory OSV melalui HTTPS.
