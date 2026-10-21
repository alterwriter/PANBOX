# PANBOX - Panduan Produk dan Operator

Mulai dari peranmu: **operator server** menyiapkan dashboard privat sekali; **DevOps** menambahkan satu langkah agent-only pada setiap job CI. Agent adalah satu binary Go. Runner tidak perlu Node, Python, Semgrep, Grype, atau instalasi server PANBOX.

## 1. Komponen dan lokasi kerja

```text
Host Git/CI -> runner terlindungi -> agent PANBOX -> API PANBOX privat -> PostgreSQL
                                       | VACCIN: aturan source       |
                                       | ENETRON: paket -> OSV       +-> UI React
```

**Hasil:** CI menerima status pass, gate gagal, scan tidak lengkap, atau akses ditolak; operator melihat snapshot repo dan branch. Bundle CI tidak memuat source mentah; review AI opsional di server mengambil potongan terbatas secara terpisah lewat koneksi SCM. ENETRON mengirim nama dan versi paket ke API advisory kompatibel OSV. Agent mengunggah temuan ternormalisasi dengan API key PANBOX, tanpa potongan source mentah. Lihat [diagram arsitektur dan jaringan](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.11/docs/architecture.md).

### Alasan tim memilih PANBOX

Nilai praktis PANBOX adalah **gabungan** kontrol berikut dalam satu pilot self-hosted, bukan klaim bahwa tidak ada vendor lain yang memiliki salah satunya:

| Kemampuan | Perilaku PANBOX yang tersedia |
|---|---|
| Pengiriman privat | Runner lokal terlindungi, relay SSH, atau impor artifact belakangan dapat menjangkau dashboard privat tanpa IP publik PANBOX. Hanya dua jalur pertama yang dapat menerapkan gate CI sinkron. |
| Source tetap di runner | VACCIN native memeriksa checkout di CI; API menerima temuan ternormalisasi, path, dan baris, bukan potongan source mentah. ENETRON mengirim koordinat paket ke data advisory kompatibel OSV. |
| Review dan policy | Modul/gate per repo, RBAC, key berscope, recast dan disposition teraudit, riwayat branch, serta ekspor terfilter ada bersama temuan. |
| Konteks tindakan | Temuan memuat file/baris, tautan source pada commit yang dipindai bila tersedia, saran perbaikan, dan referensi remediasi publik yang dikurasi. Teks ini adalah panduan; bukan bukti exploit atau perbaikan kode otomatis. |

Platform SAST/SCA lain dapat memiliki fitur serupa. Scanner alpha PANBOX masih leksikal, belum melakukan taint lintas fungsi, dan belum punya angka false positive maupun benchmark skala produksi. Uji kualitas deteksi pada repo representatif sebelum mengganti kontrol yang sudah dipakai.

## 2. Pilih jalur setup

- **Operator server, sekali:** siapkan Docker Engine/Desktop dengan Linux containers dan Compose v2. Ikuti bagian 3 untuk Debian/Linux/macOS atau bagian 4 untuk Windows. Debian adalah target produksi awal.
- **DevOps, per repo:** daftarkan repo, buat API key dengan `scans:write`, isi secret CI, lalu jalankan bagian 5. Runner perlu HTTPS keluar ke GitHub Releases dan API advisory, serta jalur ke API PANBOX privat.
- **Tanpa IP/domain publik:** pilih jalur koneksi pada bagian 6 sebelum menulis job CI.

PANBOX mengikat HTTP `8080` dan PostgreSQL `5434` ke loopback host. Ubah `PANBOX_HOST_PORT` atau `PANBOX_DB_HOST_PORT` di `.env` jika perlu. Jangan buka PostgreSQL ke internet.

## 3. Jalankan dashboard di Debian/Linux/macOS

**Tujuan:** hidupkan API dan UI privat sekali di host server:

```bash
git clone https://github.com/alterwriter/PANBOX.git
cd PANBOX
sh scripts/init-local.sh
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
curl -fsS http://127.0.0.1:8080/readyz
```

**Hasil yang diharapkan:** `/readyz` berhasil. Buka `http://127.0.0.1:8080` di host server lalu login dengan `PANBOX_BOOTSTRAP_EMAIL` dan `PANBOX_BOOTSTRAP_PASSWORD` dari `.env` yang diabaikan Git. Initializer membuat secret dengan izin terbatas dan menolak menimpa `.env`. Kredensial bootstrap hanya berlaku saat database pertama kali dibuat; simpan volume pada restart rutin.

**Demo opsional:** `PANBOX_SERVER=http://127.0.0.1:8080 bash scripts/seed-demo.sh` memerlukan `curl` dan `jq`, lalu meminta password admin. Temuan demo adalah data fiktif.

## 4. Jalankan dashboard di Windows

**Tujuan:** jalankan container Linux yang sama melalui Docker Desktop. Di PowerShell:

```powershell
git clone https://github.com/alterwriter/PANBOX.git
cd PANBOX
./scripts/init-local.ps1
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
Invoke-RestMethod http://127.0.0.1:8080/readyz
```

**Hasil yang diharapkan:** dashboard dan API sama seperti bagian 3. Jalankan `./scripts/seed-demo.ps1` hanya untuk data demo opsional. Saat membuat `.env` baru, pakai satu initializer saja.

### Variabel server dan upgrade dashboard

| Variabel `.env` server | Wajib | Fungsi |
|---|---:|---|
| `PANBOX_DB_PASSWORD` | Ya | Password PostgreSQL; gunakan nilai acak kuat. |
| `PANBOX_BOOTSTRAP_EMAIL` / `PANBOX_BOOTSTRAP_PASSWORD` | Ya | Akun admin awal; password hanya dipakai saat database pertama dibuat. |
| `PANBOX_SECURE_COOKIE` | Produksi | Set `true` jika dashboard diakses lewat HTTPS. |
| `PANBOX_HOST_PORT` / `PANBOX_DB_HOST_PORT` | Tidak | Port host; default `8080` / `5434`, tetap bind ke loopback. |
| `PANBOX_SCM_ALLOWED_HOSTS` | Opsional | Host HTTPS self-hosted SCM yang diizinkan, dipisahkan koma. |
| `PANBOX_SCM_ENCRYPTION_KEY` | Integrasi SCM privat | 64 karakter heksadesimal acak untuk enkripsi kredensial GitLab/GitHub di PostgreSQL. Initializer baru membuatnya otomatis. Backup bersama database. |

**Upgrade di server Debian/Linux:** simpan backup dan commit aktif, lalu build ulang dari `main`. Jalankan dari direktori clone PANBOX:

```bash
docker compose --env-file .env -f deploy/docker-compose.yml exec -T db pg_dump -U panbox panbox > "panbox-db-$(date -u +%Y%m%dT%H%M%SZ).sql"
git rev-parse HEAD > .panbox-previous-version
git pull --ff-only origin main
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
curl -fsS http://127.0.0.1:8080/readyz
```

Migrasi skema berjalan saat server baru start. Simpan backup sebelum upgrade; untuk rollback yang melibatkan migrasi, pulihkan database backup bersama versi kode sebelumnya. Jangan menjalankan `docker compose down -v` saat upgrade.

## 5. Kelola koneksi SCM GitHub dan GitLab

**Fungsi:** koneksi SCM membuat server PANBOX bisa membaca metadata repo yang diizinkan, termasuk repo privat dan default branch. Dashboard tidak melakukan clone source, memulai pipeline, atau memakai kredensial ini untuk upload scan. Runner CI melakukan checkout dan scan, lalu upload memakai `PANBOX_API_KEY` serta `PANBOX_REPOSITORY_ID` miliknya sendiri.

**Sebelum menyambung:** simpan `PANBOX_SCM_ENCRYPTION_KEY` yang stabil di `.env` server (instalasi baru membuatnya; instalasi lama dapat menjalankan `openssl rand -hex 32`). Backup bersama PostgreSQL. Host PANBOX memerlukan HTTPS keluar ke SCM. Untuk GitLab self-managed atau GitHub Enterprise, allowlist host persisnya di `PANBOX_SCM_ALLOWED_HOSTS` dan isi origin HTTPS; kosongkan origin untuk cloud publik. PANBOX tidak membutuhkan IP publik atau webhook.

| Provider | Siapkan di SCM | Isi di PANBOX |
|---|---|---|
| GitLab | Buat [service account](https://docs.gitlab.com/user/profile/service_accounts/) dengan akses ke group/proyek tujuan dan token berscope [`read_api`](https://docs.gitlab.com/security/tokens/access_token_scopes/). | Pilih **GitLab service account**, isi label dan token, lalu pilih cloud atau origin HTTPS self-managed yang diizinkan. |
| GitHub | Buat [GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation), beri izin repository **Metadata: read**, pasang hanya pada repo tujuan, lalu unduh private key. | Pilih **GitHub App**, isi App ID, installation ID, private key PEM, label, dan origin Enterprise yang diizinkan jika perlu. |

1. Masuk sebagai Admin, buka **Settings & Audit → GitHub & GitLab connections → Manage SCM connections**. Klik **Connect GitHub or GitLab**. Tombol ini **membuka form koneksi baru**; tidak ada koneksi atau impor sampai form dikirim.
2. Aktifkan **Connection enabled** untuk mengizinkan pembacaan. Aktifkan **Automatically enroll** hanya jika semua repo yang terlihat oleh kredensial ini memang ingin didaftarkan sebagai proyek PANBOX. Klik **Connect, test and discover**. PANBOX menguji kredensial, menyimpannya terenkripsi, membaca maksimal 500 repo yang diizinkan, dan mengimpor hanya saat auto-enroll aktif.
3. Di **Repositories**, salin PANBOX project ID tiap repo ke variabel CI `PANBOX_REPOSITORY_ID`. Buat API key PANBOX terpisah dengan `scans:write` sebagai `PANBOX_API_KEY`. Tes koneksi runner ke PANBOX sebelum scan pertama; tes SCM hanya memeriksa jalur **server ke SCM**.

| Tombol | Fungsi |
|---|---|
| **Edit** | Membuka form koneksi terpilih; ubah label, status, auto-enroll, atau ganti kredensial. Save menguji akses lagi. |
| **Discover** | Membaca repo yang saat ini terlihat dan menampilkan status terdaftar, siap, atau dikecualikan. Tidak mengimpor bila auto-enroll mati. |
| **Sync** | Memperbarui metadata dan mengimpor repo baru yang terlihat saat auto-enroll aktif. Tidak memulai scan CI. |
| **Disable / Enable** | Menghentikan atau melanjutkan akses metadata dan sync berikutnya; proyek serta riwayat scan tetap ada. |
| **Delete** | Menghapus koneksi SCM tersimpan; proyek terdaftar dan riwayat scan tetap ada. |
| **Allow reimport** | Menghapus pengecualian repo impor yang sengaja di-remove; jalankan **Sync** untuk mengimpor ulang. |

Batasi kredensial SCM pada repo yang memang ingin ditemukan. Jika tes akses gagal, periksa izin token/App, cakupan instalasi, HTTPS keluar, serta hostname self-hosted yang diizinkan secara persis. Layar koneksi menampilkan error sebelum menyimpan.

## 6. Tambahkan hanya agent ke CI

| Variabel CI | Disimpan sebagai | Fungsi |
|---|---|---|
| `PANBOX_SERVER` | Variable | URL dashboard yang bisa dijangkau runner, idealnya HTTPS. |
| `PANBOX_REPOSITORY_ID` | Variable | ID internal PANBOX dari halaman repository; bukan project ID SCM. |
| `PANBOX_API_KEY` | Masked/protected secret | API key PANBOX berscope `scans:write`; tidak perlu token repository. |
| `PANBOX_VERSION` | Variable | Tag agent yang dipin, misalnya `v0.1.0-alpha.11`. |
| `PANBOX_MODULES` | Variable opsional | Modul yang dijalankan; contoh GitLab default `vaccin,enetron`. Gunakan `vaccin` bila memang hanya ingin menjalankan SAST. |
| `PANBOX_DEFAULT_BRANCH` | Opsional | Isi jika CI tidak menyediakan metadata default branch. |

**Model onboarding:** Koneksi service account GitLab atau GitHub App dapat mendaftarkan repo privat yang diizinkan secara otomatis; enrollment manual tetap tersedia. Project ID PANBOX adalah penanda tujuan, bukan secret. Satu API key dengan `scans:write` dipakai untuk mengambil policy dan mengunggah hasil. Kredensial checkout bawaan CI mengambil source, sementara PANBOX hanya menerima hasil ternormalisasi.

**Sekali per repo, sebelum mengubah pipeline:**

1. Masuk sebagai admin atau user dengan `repos:write`, buka **Repositories -> Enroll repository**. Pilih GitHub, GitLab, Bitbucket, Azure Repos, Gitea, atau Other Git.
2. Isi **name** (label tampilan, misalnya `PANBOX`) dan **SCM repository ID or path** (misalnya `alterwriter/PANBOX`; GitLab dapat memakai `group/subgroup/project`). Klik **Test SCM connectivity and detect branch**. Metadata publik GitHub, GitLab, Bitbucket, Azure Repos, atau Gitea yang diizinkan operator mengisi **default branch** otomatis. **Owner** boleh kosong; ini hanya label tampilan, bukan RBAC atau izin scan. Nama tampilan, path SCM, dan ID internal PANBOX adalah tiga nilai berbeda.
3. Baca hasil tes sebelum klik **Enroll repository**. **Verified metadata** berarti host PANBOX membaca default branch, termasuk repo GitLab/GitHub privat jika koneksi SCM memiliki akses. **Waiting for CI** berarti tidak ada koneksi yang dapat dipakai atau metadata tidak terjangkau; biarkan **Auto-detect**. Upload CI pertama dapat melaporkan default branch sebenarnya meski memindai feature branch. PANBOX tidak menebak branch scan pertama sebagai default. Untuk Git self-hosted, tambahkan host HTTPS persis ke `PANBOX_SCM_ALLOWED_HOSTS`. Salin **PANBOX ID for CI** ke `PANBOX_REPOSITORY_ID`; ID internal ini berbeda dari path SCM atau project ID GitLab.
4. Klik **Create CI API key**. Admin/key manager membutuhkan `tokens:manage`, `scans:write`, dan akses proyek. Gunakan `scans:write`, batasi ke proyek PANBOX ini jika perlu, lalu simpan secret yang tampil sekali sebagai secret CI terlindungi `PANBOX_API_KEY`. Tidak perlu repository token lain. Pemilik key tetap perlu membership proyek kecuali admin.
5. Buka **Scan policy** pada baris repo: aktifkan scan, pilih VACCIN/ENETRON, dan ambang gate. Atur `PANBOX_SERVER` ke URL API yang dijangkau runner. `127.0.0.1` hanya benar jika runner dan server satu host. Jangan taruh API key di file repo atau job pull request yang tidak tepercaya.
6. Dari runner dengan kredensial checkout SCM milik CI, pastikan checkout berhasil (`git rev-parse --is-inside-work-tree`), lalu cek koneksi dashboard, key, dan ID dengan perintah berikut. Tes metadata dashboard pada langkah 2 tidak membuktikan jalur runner. Setelah berhasil, jalankan job agent di bawah. Scan lengkap pertama muncul di **Scans**, lalu temuannya di **Findings**.

```bash
curl -fsS "$PANBOX_SERVER/readyz"
curl -fsS -H "Authorization: Bearer $PANBOX_API_KEY" \
  "$PANBOX_SERVER/v1/repos/$PANBOX_REPOSITORY_ID/scan-config"
```

**Branch setelah enrollment:** tiap job melaporkan branch checkout sendiri; feature branch muncul setelah CI menjalankan PANBOX di situ. GitLab `CI_DEFAULT_BRANCH` dan `PANBOX_DEFAULT_BRANCH` pada template GitHub melaporkan default sebenarnya walau job berjalan dari feature branch. CI lain dapat mengisi `PANBOX_DEFAULT_BRANCH` atau `--default-branch`. Tanpa metadata, default tetap pending. Job GitLab contoh hanya berjalan pada branch terlindungi; perluas rules untuk branch lain. Overview memakai default branch sebagai baseline. **Recheck SCM** memperbarui metadata otomatis.

**Perbaiki enrollment yang salah:** klik baris repo untuk detail. **Edit** mengubah nama, owner, dan default branch; gunakan **Manual override** bila perlu. Untuk GitHub Enterprise atau GitLab mandiri, isi origin HTTPS dan allowlist host persisnya di `PANBOX_SCM_ALLOWED_HOSTS`. Identitas SCM dapat diubah sampai scan pertama, lalu dikunci agar riwayat konsisten. Admin memakai **Pause/Resume** untuk menghentikan/melanjutkan scan. **Remove** menghapus enrollment yang belum dipindai atau mengarsipkan yang sudah dipindai dan mencabut key terikat proyek. Repo impor tetap dikecualikan dari Sync berikutnya; **Allow reimport** membatalkannya. **Restore** mengaktifkannya lagi; gunakan API key dengan akses proyek. Owner kosong tidak memberikan izin.

**Rule VACCIN native kustom:** commit `.panbox/rules.json` di repositori yang dipindai. PANBOX membacanya di runner bersama rule bawaan; file yang tidak valid membuat modul VACCIN gagal, bukan diam-diam lulus. Contoh:

```json
{"rules":[{"id":"custom.team.unsafe-call","severity":"medium","message":"Unsafe call needs review","pattern":"unsafeCall\\(","extensions":[".js"]}]}
```

Pola JSON di atas mewakili regex `unsafeCall\(`. ID dimulai `custom.`; ekstensi yang didukung `.py`, `.pyw`, `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.mts`, `.cts`, `.go`, `.java`, `.jsp`, `.php`, dan `.phtml`. Batas: 64 rule, 256 karakter per pola, file 64 KiB. Regex dapat lintas baris setelah penyaringan komentar/string secara leksikal; ini bukan analisis AST atau taint. Review file rule seperti perubahan kode lain dan uji di repo representatif. Lihat [matriks coverage deteksi alpha](detection-coverage.md) untuk keluarga rule bawaan dan batas manifest SCA.

**Setiap job Linux/macOS:** ambil installer versi tetap dari [release PANBOX v0.1.0-alpha.11](https://github.com/alterwriter/PANBOX/releases/tag/v0.1.0-alpha.11). Installer memilih OS/CPU, mengunduh hanya binary agent, memeriksa [SHA256SUMS](https://github.com/alterwriter/PANBOX/releases/download/v0.1.0-alpha.11/SHA256SUMS), lalu memasang di workspace job tanpa sudo:

```bash
PANBOX_VERSION=v0.1.0-alpha.11
curl -fsSL "https://github.com/alterwriter/PANBOX/releases/download/${PANBOX_VERSION}/install-agent.sh" -o install-panbox-agent.sh
sh install-panbox-agent.sh "$PANBOX_VERSION" .panbox/bin
.panbox/bin/panbox version
.panbox/bin/panbox go --server "$PANBOX_SERVER" --repo "$PANBOX_REPOSITORY_ID" --path .
```

**Hasil yang diharapkan:** exit `0` scan lengkap/pass; `1` gate gagal; `2` scan/transport/konfigurasi tidak lengkap; `3` autentikasi atau izin ditolak. Salin contoh [GitHub Actions](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.11/deploy/github-actions-local-runner.yml) atau [GitLab CI](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.11/deploy/gitlab-ci-local-runner.yml). Untuk runner Windows, unduh [install-agent.ps1](https://github.com/alterwriter/PANBOX/releases/download/v0.1.0-alpha.11/install-agent.ps1), lalu jalankan `./install-agent.ps1 -Version v0.1.0-alpha.11`; hasilnya `./.panbox/bin/panbox.exe` setelah verifikasi checksum. [Binary agent langsung](https://github.com/alterwriter/PANBOX/releases/tag/v0.1.0-alpha.11) juga tersedia.

**Hemat pemakaian CI:** tambahkan satu pemanggilan PANBOX ke job build terlindungi yang sudah ada setelah checkout; jangan membuat job scan/analisis kedua jika menit shared runner terbatas. PANBOX membaca source dan manifest dependensi dari checkout, bukan image container hasil build. Jika tidak ada manifest yang didukung, ENETRON menjadi `skipped` dan VACCIN tetap bisa selesai. Gunakan `--modules vaccin` hanya jika sengaja menjalankan SAST saja.

VACCIN menyediakan rule leksikal buatan PANBOX untuk lima keluarga bahasa; lihat [matriks coverage](detection-coverage.md) untuk keluarga pemeriksaan dan batasannya. ENETRON membaca lock npm v1/v2/v3, pnpm, Yarn, Bun JSON; requirements/Pipfile/Poetry/uv/PDM untuk Python; `go.mod`/`go.sum`; `pom.xml` Maven; `gradle.lockfile`; dan `composer.lock` PHP. Maven hanya membaca versi eksplisit atau dependencyManagement lokal, bukan property/BOM/parent inheritance. ENETRON mengirim koordinat dan versi paket ke data advisory OSV; OSV adalah sumber data, bukan engine scanner. Query dibatch dan dipaginasi. `PANBOX_ADVISORY_URL` atau `--advisory-url` memilih mirror kompatibel OSV. Jika tidak ada manifest dependensi yang didukung, ENETRON dicatat `skipped` dan scan VACCIN yang selesai tetap dapat lulus; manifest malformed atau tidak memiliki versi tetap tetap error. Branch fitur tetap didukung; `baseline unknown` normal sampai ada scan sebelumnya di branch/base tersebut.

**Urutan CI ke dashboard:** (1) runner mengunduh agent versi tetap; (2) `panbox go` mengakses `GET /v1/repos/{id}/scan-config` dengan API key CI; (3) agent memindai modul aktif pada checkout; (4) mengirim satu bundle JSON ke `POST /v1/scans` dengan `Authorization: Bearer $PANBOX_API_KEY`; (5) API menyimpan snapshot dan mengembalikan keputusan gate; (6) agent keluar 0 (lulus), 1 (gate gagal), 2 (tidak lengkap/jaringan), atau 3 (autentikasi). Tidak ada setup upload terpisah. Cek policy dari runner: `curl -fsS -H "Authorization: Bearer $PANBOX_API_KEY" "$PANBOX_SERVER/v1/repos/$PANBOX_REPOSITORY_ID/scan-config"`.

## 7. Hubungkan SCM publik ke PANBOX privat

- **Runner lokal terlindungi (disarankan):** polling SCM apa pun lewat HTTPS keluar, lalu mengirim ke PANBOX di LAN. Tidak perlu port PANBOX publik; gate sinkron. Contoh [GitHub](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.11/deploy/github-actions-local-runner.yml) dan [GitLab](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.11/deploy/gitlab-ci-local-runner.yml).
- **SSH relay:** PANBOX membuka reverse tunnel keluar ke relay yang terjangkau; shared runner membuka forward tunnel. PANBOX tidak menerima port internet masuk; gate sinkron. Pin host key dan batasi identity. Lihat [contoh relay GitLab](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.11/deploy/gitlab-ci-ssh-relay.yml).
- **Impor artifact:** CI menulis `panbox-results.json`; host privat mengambil dan mengimpornya belakangan. Tanpa jalur masuk/relay; gate belakangan tidak dapat memblokir job CI itu. [Contoh artifact GitLab](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.11/deploy/gitlab-ci-pull-artifact.yml) dan `panbox relay-pull` mengotomasi GitLab; SCM lain memerlukan langkah unduh artifact sebelum impor generik `panbox go --bundle`.

**Cek:** dari runner sinkron, `curl -fsS "$PANBOX_SERVER/readyz"` harus berhasil. Repo publik tidak otomatis membuat artifact CI publik.

## 8. Batasi akses sesuai kebutuhan

**Setup admin:** Settings & Audit -> RBAC -> buat role dengan izin eksplisit -> assign user -> beri membership repo. `admin` adalah role tertinggi dan tidak dapat diedit. Role bawaan: `security_reviewer`, `developer`, `executive_viewer`, dan `scanner_ci`; role custom tidak dapat diberi `rbac:manage`.

**Cek:** akses data memerlukan izin dan membership repo. Izin pilot: `repos:read`, `repos:write`, `scans:read`, `scans:write`, `findings:read`, `findings:recast`, `reports:export`, `rbac:manage`, `tokens:manage`, dan `audit:read`.

## 9. Kelola API key dan access key

**Lokasi:** Settings & Audit -> API & access keys. Pilih label, tipe, expiry, scope, dan repo bila perlu. API key memiliki scope integrasi terpilih; access key hanya baca; API key CI memakai `scans:write` dan scope proyek opsional. Salin secret yang tampil sekali ke secret manager. Key disimpan sebagai hash, punya masa berlaku, dan dapat dicabut.

**Tes API baca:**

```bash
curl -H "Authorization: Bearer $PANBOX_ACCESS_KEY" "$PANBOX_SERVER/v1/repos"
```

Browser memakai password, session cookie HttpOnly, dan CSRF token. [Kontrak OpenAPI](https://github.com/alterwriter/PANBOX/blob/v0.1.0-alpha.11/api/openapi.yaml) memuat endpoint pilot. Gunakan **Rotate** untuk membuat secret pengganti dan mencabut key lama secara atomik; perbarui secret CI sebelum job berikutnya.

**Menghapus key yang dicabut:** daftar menampilkan key aktif terlebih dahulu. Aktifkan **Show revoked keys** untuk melihat record yang tidak berlaku. Admin dapat memilih **Delete** setelah konfirmasi; record hilang dari daftar, tetapi ID dan tindakannya tetap tercatat di audit log. Key aktif harus dicabut sebelum dihapus.

**Setup Codex MCP:** pada mesin yang menjalankan Codex, pasang binary `panbox` dan cek `curl -fsS "$PANBOX_SERVER/readyz"`. Buat Access key hanya-baca di dashboard dengan `repos:read`, `scans:read`, dan `findings:read`; simpan secret sekali tampil sebagai `PANBOX_TOKEN` di lingkungan privat mesin tersebut. Jalankan `codex login` dengan ChatGPT sebagai user OS yang sama, lalu `codex login status`. Atur `~/.codex/config.toml` dengan server stdio `command = "/absolute/path/to/panbox"`, `args = ["mcp"]`, `PANBOX_SERVER`, dan `PANBOX_TOKEN`. Restart Codex, cek `codex mcp list`, lalu minta daftar repo PANBOX. Tidak ada tombol login Codex di dashboard; status login klien interaktif tidak dikirim ke PANBOX. [Panduan MCP lengkap di website (EN)](https://boxsploit.com/products/panbox/#mcp-codex) membedakan jalur ini dari worker otomatis di host PANBOX.

## 10. Periksa dan kontrol scan di dashboard

**Row dan waktu di dashboard:** Repositories, Findings, Scans, serta tabel repo Overview menampilkan 10 row per halaman dengan tombol Previous/Next. Tabel dan detail Repositories menampilkan **Latest scan** dari branch apa pun; posture Overview tetap memakai snapshot lengkap terbaru pada default branch. Halaman Scans menampilkan 100 scan terbaru yang dikirim API pilot, sedangkan Findings maksimal 1.000 row setelah filter. Gunakan filter repo dan branch untuk mempersempit hasil; ekspor terpisah dari batas row tabel.

**Source dan remediasi:** Temuan VACCIN menampilkan path relatif repo dan nomor baris. Jika identitas SCM serta commit valid, **Open source** menuju commit dan baris persis yang dipindai. Detailnya memuat saran spesifik rule atau keluarga masalah, serta URL referensi publik OWASP atau Django yang dikurasi; temuan ENETRON menuju advisory OSV. PANBOX tidak mengirim source ke situs dokumentasi tersebut atau menganggap tautannya sebagai bukti exploit. Prompt perbaikan hanya teks lokal, bukan perbaikan AI otomatis.

**Log CI:** output teks default menampilkan rilis/branch/commit, verdict gate, status modul, jumlah severity, maksimal 10 lokasi temuan dengan severity tertinggi, dan URL dashboard. Di GitLab, daftar temuan dapat dilipat pada job log; bila metadata SCM tersedia, tiap lokasi memiliki URL source pada commit yang dipindai. Output JSON dan SARIF tetap untuk mesin. Exit code tetap membedakan pass (`0`), gate gagal (`1`), tidak lengkap (`2`), dan izin ditolak (`3`).

**Periksa dan triase:** klik baris repo untuk detail serta aksi langsung **View findings / View scans**. Klik scan untuk daftar temuannya, lalu klik finding untuk path, baris, URL source bila tautan commit aman dibentuk, advisory, petunjuk remediasi, dan 100 scan lengkap terakhir pada branch itu. Temuan yang hilang pada scan lengkap berikutnya untuk modulnya berstatus **resolved**; riwayat lama tetap terlihat. **Recast severity** mengubah effective severity dengan alasan yang diaudit. **Triage** dapat menandai false positive, accepted risk, closed, atau reopen, juga dengan alasan; status ini merevisi gate terkait dan mengeluarkan temuan dari hitungan posture aktif sambil mempertahankannya dalam riwayat/laporan. Penutupan manual tetap berlaku sampai dibuka lagi. Tombol prompt remediasi hanya menyalin template lokal; tidak memanggil AI atau mengubah source. Bridge MCP hanya-baca dapat memasok finding ke klien, tetapi klien yang mengatur penggunaan AI. Persentase false positive pilot ini belum diukur.

Panel finding kini memisahkan lokasi source, riwayat scan, saran remediasi, dan triase. Pilih status triase secara eksplisit dan isi alasan 10–500 karakter sebelum menyimpan. Panduan khusus tersedia untuk konfigurasi Django, SQL, CSRF, template output, redirect, dan kredensial; rule lain memakai langkah pemeriksaan umum. Saran ini bukan bukti exploit. Untuk aplikasi Django, agent saat ini memeriksa file `.py` serta HTML di bawah `templates/`; JavaScript bundel yang dikenal di `static/` atau `assets/` dilewati agar hasil aplikasi tidak tertutup noise. Lihat [cakupan deteksi](detection-coverage.md) sebelum mempresentasikan hasil.

**Recast:** buka **Findings**, kosongkan filter bila daftar belum terlihat, lalu klik **Recast severity** di samping rule temuan (kolom pertama). Pilih effective severity atau pulihkan severity scanner -> isi alasan (10-500 karakter) -> Save. Tombol hanya terlihat jika akun memiliki `findings:recast` dan akses repo; admin atau `security_reviewer` dengan membership repo dapat memakainya. Jika tidak ada baris, selesaikan scan pertama atau periksa filter. Jika ada baris tetapi tidak ada tombol, minta admin memeriksa role dan membership di **Settings & Audit -> RBAC**. Raw severity tidak berubah. Riwayat tersedia di `GET /v1/findings/{id}/recasts`; gate lama memperoleh revisi dengan ambang asli masing-masing scan. Recast bukan persetujuan atau pengabaian temuan.

**Ekspor:** Reports -> pilih repo, branch tepat, modul scan (VACCIN/ENETRON), dan severity opsional -> Export PDF, CSV, atau JSON. Data berasal dari scan lengkap terbaru tiap branch. PDF adalah ringkasan teknis; CSV/JSON menyimpan kolom lengkap. Perlu `reports:export`.

**MCP:** Settings & Audit -> API & access keys -> buat Access key hanya-baca dengan `repos:read`, `scans:read`, dan `findings:read`. Buka Settings & Audit -> MCP setup dan ikuti konfigurasi host stdio generik. Host MCP menjalankan `panbox mcp` dengan `PANBOX_SERVER` dan `PANBOX_TOKEN` di secret environment. Empat tool hanya-baca menampilkan repo, temuan, daftar scan, dan detail scan. Tidak ada endpoint MCP publik.


**Setelah CI:** Overview menampilkan cakupan/severity; Repositories menampilkan proyek; Scans menampilkan status run/gate; Findings dapat difilter menurut repo/branch/modul/severity; Reports mengekspor PDF/CSV/JSON teknis terfilter; Settings & Audit menampilkan RBAC, key, dan audit. Tema light dan dark tersedia.

**Arti hasil:** scan parsial tetap unverified dan mempertahankan posture sukses terakhir. ARK menandai Critical/High dan BUG-STER menandai Medium/Low, sementara severity standar tetap disimpan dan diekspor. Recast dan perubahan scan policy tercatat di audit.

## 11. Operasikan sesuai batas pilot

Biarkan PostgreSQL di loopback. Untuk browser jarak jauh, gunakan reverse proxy HTTPS dengan kontrol akses atau jalur privat; set `PANBOX_SECURE_COOKIE=true` pada HTTPS. Backup PostgreSQL dan uji restore.

Host Debian 2 GB adalah **target untuk divalidasi**, bukan jaminan. Fixture kecil Docker Desktop Windows mengukur sekitar 5,1 MiB RAM server dan 37,3 MiB PostgreSQL; 100 panggilan API berurutan menghasilkan median 7,1 ms dan p95 9,3 ms. Agent berada di runner dan butuh sizing terpisah. Ukur `docker stats --no-stream` dengan repo dan bundle yang representatif.

## 12. Telusuri langkah yang gagal

- **Dashboard belum siap:** jalankan `docker compose --env-file .env -f deploy/docker-compose.yml ps` dan `logs db server`; periksa kesehatan PostgreSQL.
- **Unduhan agent gagal:** periksa tag release, nama asset OS/CPU, akses GitHub keluar, `curl`, dan alat SHA-256. Jangan lewati checksum.
- **Runner gagal menjangkau PANBOX:** `127.0.0.1` di container menunjuk ke container itu; gunakan alamat host/jaringan privat atau SSH relay.
- **Exit 2:** cek manifest, endpoint advisory, path kerja, endpoint PANBOX, dan log; tidak lengkap bukan pass.
- **ENETRON skipped:** repo tidak memiliki manifest dependensi yang didukung; VACCIN tetap bisa selesai. Tambahkan lockfile ekosistem untuk mengaktifkan SCA. Periksa `panbox version` untuk memastikan job CI memakai rilis yang dipin.
- **ENETRON error:** manifest didukung tetapi malformed/tidak memiliki versi tetap, atau lookup advisory gagal. Perbaiki/commit lockfile atau akses jaringan; scan tetap unverified.
- **Exit 3:** cek expiry/revocation API key, `scans:write`, ID repo internal, role, dan membership.
- **Impor artifact terlambat:** cek timer, `GITLAB_READ_TOKEN`, ref yang diizinkan, Jobs API/artifact, dan state relay.

## 13. Pahami batas alpha

Yang tersedia: server/UI, pemeriksaan source native VACCIN, pencocokan dependensi tetap native ENETRON dengan data OSV, snapshot repo/branch, gate, RBAC, key berscope, audit, ekspor PDF/CSV/JSON terfilter, serta contoh jalur koneksi di atas. Validasi runner nyata, OSV/mirror, beban Debian, backup/restore, TLS, dan rotasi key di lingkungan target.

Cakupan masih sempit. RIDER secrets, TESLA IaC, alur persetujuan, template laporan PDF eksekutif, penemuan kerentanan mandiri oleh AI, OIDC, dan rate limiting API masih roadmap. Panduan online ini menjelaskan pilot; laporan kerentanan PANBOX diekspor terpisah dari dashboard.

## 14. Tinjau temuan dengan AI di server PANBOX

**Alur:** CI menjalankan agent native VACCIN/ENETRON lalu mengunggah scan biasa. PANBOX langsung mengembalikan hasil gate. Jika Admin mengaktifkan review AI, PANBOX membaca potongan source pada commit scan melalui koneksi GitHub/GitLab. Pilih worker Codex CLI opsional pada host PANBOX dengan login ChatGPT, atau jalur API OpenAI/Anthropic dengan tagihan terpisah. Keduanya menyimpan penilaian dan log tahapan terpisah. CI tidak menjalankan atau menunggu AI.

**Variabel server:**

| Variabel | Lokasi | Fungsi |
|---|---|---|
| `PANBOX_OPENAI_API_KEY` | `.env` server PANBOX/secret manager | API key model coding OpenAI; hanya untuk pilihan OpenAI. |
| `PANBOX_ANTHROPIC_API_KEY` | `.env` server PANBOX/secret manager | API key Claude; hanya untuk pilihan Anthropic. |
| `PANBOX_SCM_ENCRYPTION_KEY` | Server PANBOX | Mengenkripsi kredensial koneksi GitHub/GitLab yang juga dipakai untuk discovery repo. |
| `DATABASE_URL` | Worker Codex di host | Mengakses PostgreSQL PANBOX melalui loopback (port Compose bawaan 5434). |
| `PANBOX_MIGRATIONS_DIR` | Worker Codex di host | Path absolut ke direktori `migrations` pada checkout ini. |
| `CODEX_HOME` | Worker Codex di host | Profil Codex khusus dengan login ChatGPT, bila digunakan. |

**Setup:** beri GitHub App izin `Metadata: read` dan `Contents: read`, atau beri service account GitLab `read_api` pada proyek yang diizinkan. Untuk jalur Codex, pasang binary rilis `panbox-ai-worker` dan Codex CLI pada host PANBOX, login **memakai ChatGPT** sebagai user OS khusus, lalu jalankan worker dengan variabel di tabel. Buka **Settings & Audit → Server-side AI review → Configure and view runs**, pilih **Codex CLI · ChatGPT login**, atur 1–10 temuan per scan (default 3), lalu aktifkan. Model ID opsional untuk Codex. Panel menampilkan heartbeat worker. Tidak perlu API key OpenAI atau Anthropic. Untuk jalur API dengan tagihan terpisah, isi key provider dan Model ID pada server dashboard. Untuk scan lama, buka **Scans → detail scan → Queue AI review on server**. Ikuti [langkah worker](ai-review.md#codex-plan-route-no-provider-api-key).

**Pantau:** panel Admin menampilkan status queued/running/completed/partial/failed, log tahapan, dan verdict, confidence, penjelasan, bukti, serta saran perbaikan tiap temuan. Kegagalan izin baca source juga tampak di sana. Yang dipilih hanya temuan VACCIN Critical/High/Medium dengan path source, dimulai dari severity tertinggi. Saran AI tidak menutup temuan, mengubah severity, atau mengubah gate secara otomatis; lakukan triase/recast manual dengan alasan yang diaudit. Ini review atas temuan scanner, bukan penemuan AI SAST mandiri atau angka false positive terukur. Baca [desain dan batas review AI](ai-review.md).

**Plugin Codex / MCP:** [plugin Codex lokal](../plugins/panbox/plugin.json) memakai bridge stdio `panbox mcp` hanya-baca untuk pemeriksaan interaktif dengan Access key berscope. Memasang plugin saja tidak memicu review otomatis; worker Codex terpisah yang menjalankannya. Review Codex memakai kuota atau kredit Codex akun tersebut, sedangkan jalur API provider ditagih terpisah. Keduanya tidak butuh variabel CI tambahan.
