# Zero Trust Security — Sistem Nilai

Backend tugas praktikum Zero Trust untuk pengelolaan nilai dan transkrip. Implementasi menempatkan API Gateway sebagai pintu akses, memeriksa identitas dan konteks pada Gateway serta service, memakai policy default-deny, dan mencatat keputusan ke SQLite. Frontend tidak termasuk lingkup proyek.

## Arsitektur

```text
Client ──> API Gateway :3000 ──> Service Nilai :3001
                    └─────────> Service Transkrip :3002
                                  ▲
Service Nilai ──service token──> Gateway ──> Service Transkrip

Gateway, Service Nilai, dan Service Transkrip memakai satu database SQLite.
```

Ketiga server bind ke `127.0.0.1`. Gateway hanya meneruskan header yang diizinkan, lalu menetapkan `X-Gateway-Secret` sendiri. Setiap service memvalidasi secret dan token secara mandiri. Service Nilai memakai jalur Gateway juga untuk meminta service token dan mengirim sinkronisasi transkrip.

## Persyaratan dan instalasi

- Node.js `>=24.19.0 <25` dan npm `>=11` (root `package.json` membatasi versi ini).
- Dependency database: `better-sqlite3@12.11.1`; database lokal bersama default `data/zero-trust.sqlite`.
- Jalankan perintah berikut dari root proyek di PowerShell:

```powershell
npm install
Copy-Item .env.example .env
```

Isi `.env` lokal dengan secret acak yang berbeda dan sekurang-kurangnya 32 byte untuk `JWT_ACCESS_SECRET`, `GATEWAY_SECRET`, `SERVICE_TOKEN_SECRET`, dan `SERVICE_NILAI_CLIENT_SECRET`. Jangan commit `.env` atau menyalin nilai secret ke laporan. Atur `SERVICE_NILAI_CLIENT_ID` ke `service-nilai`. `DATABASE_PATH` dapat diarahkan ke lokasi SQLite bersama lain; semua service harus memakai path yang sama.

Jalankan migrasi dan seed akun:

```powershell
npm run db:migrate
$env:ALLOW_DEMO_SEED = 'true'
npm run db:seed:demo
npm run nilai:seed:demo
Remove-Item Env:ALLOW_DEMO_SEED
```

Kedua seed aman dijalankan ulang: akun, password, kelas, dan nilai yang sudah ada tidak ditimpa. Migrasi menggunakan versi berurutan dan tidak menghapus tabel/data. Akun demo hanya untuk mesin lokal.

## Menjalankan service

Buka tiga terminal PowerShell terpisah setelah `.env`, migrasi, dan seed tersedia:

```powershell
# Terminal 1
npm run dev:transkrip
```

```powershell
# Terminal 2
npm run dev:nilai
```

```powershell
# Terminal 3
npm run dev:gateway
```

Gateway mendengarkan di `127.0.0.1:3000`, Service Nilai di `127.0.0.1:3001`, dan Service Transkrip di `127.0.0.1:3002`. `GET http://127.0.0.1:3000/health` memeriksa database dan kedua service; status `503 degraded` berarti salah satu upstream belum siap. Tiap service juga menyediakan `/health` lokal yang hanya memeriksa proses dan database.

## Akun demo lokal

Akun dan device berikut berasal dari `npm run db:seed:demo`; kelas, enrollment, dan nilai berasal dari `npm run nilai:seed:demo`.

| Role | Email | Password lokal | `X-Device-ID` | NIM |
|---|---|---|---|---|
| Admin | `admin.demo@zero-trust.local` | `AdminDemo-Local-2026!` | `demo-device-admin-001` | — |
| Dosen 1 | `dosen1.demo@zero-trust.local` | `Dosen1Demo-Local-2026!` | `demo-device-dosen1-001` | — |
| Dosen 2 | `dosen2.demo@zero-trust.local` | `Dosen2Demo-Local-2026!` | `demo-device-dosen2-001` | — |
| Mahasiswa 1 | `mahasiswa1.demo@zero-trust.local` | `Mhs1Demo-Local-2026!` | `demo-device-mhs1-001` | `demo-student-001` |
| Mahasiswa 2 | `mahasiswa2.demo@zero-trust.local` | `Mhs2Demo-Local-2026!` | `demo-device-mhs2-001` | `demo-student-002` |
| Mahasiswa 3 | `mahasiswa3.demo@zero-trust.local` | `Mhs3Demo-Local-2026!` | `demo-device-mhs3-001` | `demo-student-003` |

Seed kelas membuat `demo-class-algoritma-2026` untuk Dosen 1 dan `demo-class-keamanan-2026` untuk Dosen 2. Data demo tersebut tidak otomatis berarti finalisasi/transkrip lokal sudah pernah dijalankan.

## Endpoint

Semua permintaan aplikasi di bawah ini ditujukan ke Gateway `http://127.0.0.1:3000`. `X-Device-ID` dan access token wajib untuk endpoint pengguna yang dilindungi.

| Method dan path | Akses |
|---|---|
| `POST /auth/login` | Email/password benar dan device terdaftar; mengembalikan access serta refresh token. |
| `POST /auth/refresh` | Refresh token aktif dan device yang sama; merotasi token. |
| `POST /auth/logout` | Mencabut refresh token. |
| `GET /auth/devices`, `POST /auth/devices`, `DELETE /auth/devices/:deviceId` | Pengguna terautentikasi mengelola device miliknya. |
| `POST /auth/service` | Kredensial internal Service Nilai; jangan dipakai oleh client. Token berlaku 5 menit. |
| `GET /nilai` | Mahasiswa membaca nilai sendiri; dosen membaca nilai kelas yang diajarnya. |
| `GET /nilai/saya` | Mahasiswa membaca nilai sendiri. |
| `GET /nilai/kelas/:kelasId` | Mahasiswa membaca nilainya di kelas; dosen membaca kelas yang diampu. |
| `PUT /nilai/:id` | Endpoint tugas; `id` opaque/base64url yang disediakan oleh `GET /nilai`. Hanya dosen pengampu, enrollment valid, kelas belum final, dan dalam jam akses. |
| `PATCH /nilai/kelas/:kelasId/mahasiswa/:mahasiswaId` | Bentuk resource yang eksplisit untuk memperbarui satu nilai dengan aturan sama seperti `PUT`. |
| `POST /kelas/:kelasId/finalisasi` | Dosen pengampu dalam jam akses. Sinkronisasi transkrip wajib dikonfirmasi lebih dahulu. |
| `POST /nilai/kelas/:kelasId/finalisasi` | Alias endpoint finalisasi dengan aturan yang sama. |
| `GET /transkrip/:nim` | Mahasiswa untuk NIM sendiri atau admin untuk NIM mahasiswa mana pun. Dosen ditolak. |
| `POST /transkrip/sinkron` | Internal Gateway; service token sah `service-nilai` saja. Tidak untuk panggilan client. |
| `GET /health` | Status Gateway, database, dan kedua upstream. |

Service Transkrip sendiri menerima `GET /transkrip/:nim` dan `POST /transkrip/sinkron` pada port 3002, tetapi menolak request tanpa `X-Gateway-Secret`. Koneksi service-to-service menggunakan endpoint Gateway, bukan koneksi langsung dari Service Nilai ke port 3002.

## Contoh alur demo PowerShell

Contoh ini memakai akun demo mahasiswa dan dosen 1. Menyimpan respons login dalam variabel mencegah token dicetak ke terminal.

```powershell
$base = 'http://127.0.0.1:3000'
$student = Invoke-RestMethod -Method Post -Uri "$base/auth/login" `
  -Headers @{ 'X-Device-ID' = 'demo-device-mhs1-001' } `
  -ContentType 'application/json' `
  -Body (@{ email = 'mahasiswa1.demo@zero-trust.local'; password = 'Mhs1Demo-Local-2026!' } | ConvertTo-Json)
$studentHeaders = @{ Authorization = "Bearer $($student.accessToken)"; 'X-Device-ID' = 'demo-device-mhs1-001' }
$myGrades = Invoke-RestMethod -Method Get -Uri "$base/nilai" -Headers $studentHeaders
$myTranscript = Invoke-RestMethod -Method Get -Uri "$base/transkrip/demo-student-001" -Headers $studentHeaders
```

Mahasiswa 1 mencoba mengubah nilai atau membaca NIM mahasiswa lain dan harus ditolak. Untuk perubahan nilai, login sebagai dosen 1, ambil `id` baris yang diajarnya dari `GET /nilai`, lalu gunakan PUT:

```powershell
$lecturer = Invoke-RestMethod -Method Post -Uri "$base/auth/login" `
  -Headers @{ 'X-Device-ID' = 'demo-device-dosen1-001' } `
  -ContentType 'application/json' `
  -Body (@{ email = 'dosen1.demo@zero-trust.local'; password = 'Dosen1Demo-Local-2026!' } | ConvertTo-Json)
$lecturerHeaders = @{ Authorization = "Bearer $($lecturer.accessToken)"; 'X-Device-ID' = 'demo-device-dosen1-001' }
$lecturerGrades = Invoke-RestMethod -Method Get -Uri "$base/nilai" -Headers $lecturerHeaders
$target = $lecturerGrades.grades | Where-Object { $_.classId -eq 'demo-class-algoritma-2026' -and $_.studentId -eq 'demo-student-001' } | Select-Object -First 1
Invoke-RestMethod -Method Put -Uri "$base/nilai/$($target.id)" -Headers $lecturerHeaders `
  -ContentType 'application/json' -Body (@{ score = 95 } | ConvertTo-Json)
Invoke-RestMethod -Method Post -Uri "$base/kelas/demo-class-algoritma-2026/finalisasi" -Headers $lecturerHeaders
Invoke-RestMethod -Method Get -Uri "$base/transkrip/demo-student-001" -Headers $studentHeaders
```

Finalisasi dapat tertahan di `FINALIZING` ketika Gateway atau Service Transkrip timeout. Setelah upstream pulih, ulangi request finalisasi sebagai dosen pengampu. Retry mengirim snapshot idempotent; kelas tidak dibuka kembali untuk perubahan nilai.

Untuk meninjau audit log terbaru setelah migrasi versi 4, jalankan:

```powershell
npm run audit:recent
```

Perintah itu hanya menampilkan waktu, correlation ID, aktor, action, endpoint, device, keputusan, dan reason code—bukan token atau secret.

## Kontrol Zero Trust

- **Access JWT** berlaku 10 menit; verifier membatasi algoritma ke HS256 dan memeriksa signature serta expiry. Token pengguna tidak diterima pada sinkronisasi service.
- **Refresh token** berlaku 1 hari, disimpan sebagai hash, dirotasi saat refresh, dan dapat dicabut saat logout.
- **Service token** berlaku 5 menit, ditandatangani dengan `SERVICE_TOKEN_SECRET`, serta memuat `token_use`, identitas service, role, dan audience transkrip.
- **Device verification** memeriksa `X-Device-ID` aktif yang terikat ke pengguna. Device ID bukan pengganti access token.
- **Policy Engine** menggunakan default deny dan memeriksa ownership, role, kelas/dosen, enrollment, state kelas, dan jam akses yang disimpan pada `access_policies` (default 07.00–21.00 `Asia/Jakarta`).
- **Gateway secret** adalah kontrol internal tambahan; setiap service tetap memvalidasi token/identity sendiri.
- **Audit log** disimpan pada SQLite bersama dengan waktu UTC, correlation ID, aktor, action, endpoint, device, keputusan, dan alasan. Nilai token, password, serta secret tidak ditulis ke audit.

## Tes dan pemeriksaan

```powershell
npm install
npm run typecheck
npm test
npm run db:migrate
```

Suite menguji aturan role/ownership/device/waktu, auth dan refresh, sinkronisasi service token, request HTTP Gateway–Nilai–Transkrip, timeout/retry finalisasi, dan race finalisasi bersamaan. Tes HTTP memakai listener lokal ephemeral; demo manual pada port 3000–3002 tetap perlu dijalankan untuk presentasi.

## Batasan

- Database bersama dan semua service berjalan pada satu host; secret internal melindungi hop lokal, bukan menyediakan transport encryption untuk deployment lintas host.
- Belum ada rate limiter atau worker recovery otomatis. Kelas yang tertahan `FINALIZING` dipulihkan dengan retry finalisasi oleh dosen pengampu setelah dependensi sehat.
- Access JWT tidak dicabut satu per satu; logout mencabut refresh token, sedangkan access token yang sudah diterbitkan kedaluwarsa paling lama dalam 10 menit.
- Endpoint audit viewer hanya tersedia lewat skrip lokal, bukan API publik.
- Proyek tidak mengklaim telah diaudit pihak ketiga atau aman untuk deployment produksi.
