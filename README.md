# PWF Auth for Node.js

Official client for [PWF Auth](https://pwfauth.com) — license keys, user accounts,
hardware-ID binding, encrypted sessions with a server-side kill switch, free trials,
remote content, and OTA update checks.

```bash
npm install pwfauth
```

Node 18+. Zero dependencies — built on the runtime's own `fetch` and `crypto`.
Ships TypeScript definitions.

> **Server-side only.** The app secret must never reach a browser. Anyone holding it can
> call the API as your application, so do not bundle this into front-end code. See
> [Security](#security) below.

## Quick start

```js
import { PwfClient } from 'pwfauth';

const client = new PwfClient(process.env.PWFAUTH_SECRET);

// The moment an admin bans, pauses, expires, resets or revokes the key — or the
// server becomes unreachable — this fires. Sign the user out here.
client.on('sessionEnded', ({ errorCode, message }) => {
    console.error(`Session ended (${errorCode}): ${message}`);
    process.exit(1);
});

const login = await client.login('XXXXX-XXXXX-XXXXX-XXXXX');
if (!login.success) {
    console.error(login.message);        // safe to show the user
    process.exit(1);
}

client.startHeartbeat();                 // keeps the session alive AND enforces the kill switch
```

## Why the heartbeat matters

`startHeartbeat()` is not optional bookkeeping — it is the enforcement point.

* The server drops a session that stops beating, so a client that never beats loses
  nothing but also never learns it was revoked.
* Every beat re-checks the license: ban, pause, expiry, HWID reset, deletion and
  maintenance mode all end the session on the very next beat.
* If the server is unreachable for `maxHeartbeatFailures` beats in a row (3 by default),
  the client ends the session itself with `NETWORK_LOST`. Without that, blocking the
  license domain in a firewall would keep the application running forever.

The timer is `unref()`d, so it never holds a process open on its own.

## What the login reply contains

`login.license` parses the licence block for you — including the case that trips most
integrations:

```js
const lic = login.license;

if (lic.isLifetime) {
    console.log(`${lic.licenseKey} — lifetime licence`);
} else {
    console.log(`Expires ${lic.expiresAt.toISOString()} — ${lic.daysRemaining} day(s) left`);
}

// Per-key feature flags you set in the dashboard
if (login.features.pro_tier) enableProExport();
```

| Property | Type | Notes |
| --- | --- | --- |
| `licenseKey` | string | The key that was activated |
| `keyType` / `duration` | string / number | `days`, `hours`, `lifetime`, … |
| `hwid` | string | The machine this session is bound to |
| `activatedAt` | `Date \| null` | First activation |
| `expiresAt` | `Date \| null` | **`null` for lifetime keys** |
| `daysRemaining` | `number \| null` | **`null` for lifetime keys** |
| `status` | string | `active` |
| `isLifetime` | boolean | Convenience for `expiresAt === null` |

Anything the API adds later stays reachable through `login.data` (the raw parsed JSON)
without waiting for a package update.

## What else it does

```js
const status = await client.checkKey(key);          // no session, no seat consumed
const info   = await client.getAppInfo();           // name, version, download URL, socials
const texts  = await client.getTexts();             // remote strings, per-key overrides
const slides = await client.getSlides();            // announcement slides
const update = await client.checkUpdate('1.4.2');   // OTA: version, sha256, download URL
const trial  = await client.createTrial();          // free trial for this machine
await client.requestHardwareReset(key, 'New laptop');

// User accounts (the username/password half of the platform)
await client.registerAccount('alice', 's3cret', 'alice@example.com');
await client.accountLogin('alice', 's3cret');

await client.logout();                               // frees the device seat
```

Endpoints this client does not wrap yet are still reachable — `postEnvelope`,
`getEnvelope` and `postPlain` are public, and so is `CryptoEnvelope`.

## Handling failures

An API answer that simply says "no" is a resolved promise with `success === false`.
Only transport and crypto problems reject:

```js
import { PwfHttpError, PwfCryptoError, PwfErrorCodes } from 'pwfauth';

try {
    const res = await client.login(key);
    if (!res.success) {
        if (res.errorCode === PwfErrorCodes.HWID_MISMATCH) showHardwareResetDialog();
        else console.error(res.message);
    }
} catch (e) {
    if (e instanceof PwfHttpError)   console.error(`Server unreachable (${e.status})`);
    if (e instanceof PwfCryptoError) console.error('Wrong app secret for this application.');
}
```

Every request accepts an `AbortSignal`:

```js
await client.login(key, { signal: AbortSignal.timeout(5000) });
```

## Configuration

```js
const client = new PwfClient({
    appSecret: process.env.PWFAUTH_SECRET,
    baseUrl: 'https://pwfauth.com',
    hardwareId: myOwnFingerprint,   // default: getHardwareId()
    timeoutMs: 15000,
    maxHeartbeatFailures: 3,
    maxClockDriftSeconds: 300,      // must match the server
    fetch: myFetch,                 // inject for proxies or tests
});
```

## Hardware ID

`getHardwareId()` reads the Windows cryptography MachineGuid, `/etc/machine-id` on
Linux, or the platform UUID on macOS, and falls back to the host name. It does not use
`wmic`, which Windows 11 24H2 removed. The same machine produces the same HWID under
this client and the [.NET client](https://www.nuget.org/packages/PWFAuth), so a user can
move between them without tripping the device limit.

## Security

The app secret is what the envelope protocol encrypts with, so whatever runs the client
must hold it. That means:

* **Keep it server-side.** Never ship it to a browser, a mobile app bundle, or any
  client you do not control.
* Read it from the environment (`process.env.PWFAUTH_SECRET`) or a secrets manager —
  never commit it.
* If it leaks, rotate it in the dashboard. Rotating invalidates every deployed copy, so
  plan the rollout.

## License

MIT © PWF Auth
