# PWF Auth for Node.js

## Server authentication update

All responses, including errors and clock-correction responses, must carry a valid
RSA-SHA256 signature from the pinned PWFAuth public key. The private signing key
stays on the server. Knowing the application secret is not enough to forge this
signature. A fresh random nonce binds each response to its request, method, path,
HTTP status and exact body bytes (PWF-REPLY-V1). Query strings are not part of the
V1 signed path; production HTTPS protects them in transit.

The SDK accepts only `https://pwfauth.com`. Its default transport validates TLS
certificates and refuses redirects. Missing/invalid signatures fail closed before
JSON parsing or envelope decryption; unsigned proxy/CDN errors are security errors.
There is no fallback to the old unsigned protocol. Update the server before clients.
Applications must never unlock functionality after a security or transport error.

This addresses server emulation. It does not prevent an attacker who controls the
client machine from modifying the application itself. Keep authoritative valuable
operations on the server and keep real app secrets out of public repositories.


Official client for [PWF Auth](https://pwfauth.com) — license keys, user accounts,
hardware-ID binding, encrypted sessions with a server-side kill switch, self-service
device moves, accounts that run on license keys, free trials, remote content, and OTA
update checks.

```bash
npm install pwfauth
```

Node 18+. Zero dependencies — built on the runtime's own `fetch` and `crypto`.
Ships TypeScript definitions.

> **Server-side only.** The app secret must never reach a browser. Anyone holding it can
> call the API as your application, so do not bundle this into front-end code. See
> [Security](#security) below.

## What's new in 1.1.0

* **The kill switch cannot be dodged.** Only an encrypted reply counts as the server's
  answer. A plain refusal no longer keeps the session alive forever: the commonest is
  the server rejecting a clock moved more than 5 minutes. A fake `{"success": true}`
  doesn't either.
* **A fake server is refused.** An unencrypted "success" from the login, heartbeat or
  app-content endpoints rejects with `PwfSecurityError` instead of signing the user in.
* **A wrong PC clock repairs itself.** The client shifts by the server's time and
  retries once. Opt out with `autoCorrectClock: false`.
* **Move a license to a new PC:** `resetHardwareId(key, reason)`.
* **Accounts that run on license keys:** `registerAccountWithKey()` and `redeemKey()`.
* Clearer errors when there is no connection, and a `User-Agent` header.

See [CHANGELOG.md](CHANGELOG.md).

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
* Only an encrypted reply counts as an answer. If `maxHeartbeatFailures` beats in a row
  (3 by default) get none, the client ends the session itself:
  * the causes are no reply, a plain refusal, or a forged plain "success";
  * the code is `NETWORK_LOST`, or `CLOCK_SKEW` when the server kept rejecting the clock;
  * HTTP 429 has its own budget, `maxRateLimitedBeats` (10).

  Without that, blocking the license domain in a firewall, or moving the system clock,
  would keep the application running forever.

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

// User accounts (the username/password half of the platform)
await client.registerAccount('alice', 's3cret', 'alice@example.com');
await client.registerAccountWithKey('alice', 's3cret', key);   // when the app wants a key at sign-up
await client.accountLogin('alice', 's3cret');                  // opens a session, like login()
await client.redeemKey(anotherKey);                            // adds the key's time to the account
await client.changeAccountPassword('alice', 's3cret', 'n3w!'); // signs the account out everywhere

await client.logout();                               // ends the session (the key stays bound here)
```

## Moving a license to a new PC

```js
let login = await client.login(key);
if (login.errorCode === PwfErrorCodes.HWID_MISMATCH || login.errorCode === PwfErrorCodes.DEVICE_LIMIT) {
    if (await askUser('This key is used on another computer. Move it here?')) {
        const moved = await client.resetHardwareId(key, 'New laptop');
        if (moved.success) login = await client.login(key);
        else console.error(moved.message);          // e.g. the cooldown: "try again in 11 hours"
    }
}
```

The move unbinds the key from every machine and ends its sessions. In App Settings you
decide whether customers may move keys themselves, and the cooldown between two moves
(12 hours by default).

Endpoints this client does not wrap yet are still reachable — `postEnvelope`,
`getEnvelope` and `postPlain` are public, and so is `CryptoEnvelope`.

## Handling failures

An API answer that simply says "no" is a resolved promise with `success === false`.
Only transport and crypto problems reject:

```js
import { PwfHttpError, PwfCryptoError, PwfSecurityError, PwfErrorCodes } from 'pwfauth';

try {
    const res = await client.login(key);
    if (!res.success) {
        if (res.errorCode === PwfErrorCodes.HWID_MISMATCH) showMoveLicenseDialog();
        else console.error(res.message);
    }
} catch (e) {
    if (e instanceof PwfSecurityError) console.error('Not the license server — never unlock on this.');
    if (e instanceof PwfHttpError)     console.error(`No usable reply (${e.status}): ${e.message}`);   // 401 = wrong app secret, 0 = no connection
    if (e instanceof PwfCryptoError)   console.error('Wrong app secret for this application.');
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
    maxHeartbeatFailures: 3,        // beats without an encrypted answer before NETWORK_LOST
    maxRateLimitedBeats: 10,        // separate budget for HTTP 429
    autoCorrectClock: true,         // repair a wrong system clock from the server's time
    maxClockDriftSeconds: 300,      // must match the server
    userAgent: 'MyApp/2.0',         // default: pwfauth-node/<version>
    fetch: myFetch,                 // inject for proxies or tests
});
```

## Hardware ID

`getHardwareId()` reads the Windows cryptography MachineGuid, `/etc/machine-id` on
Linux, or the platform UUID on macOS, and falls back to the host name. It does not use
`wmic`, which Windows 11 24H2 removed. The same machine produces the same HWID under
this client, the [.NET client](https://www.nuget.org/packages/PWFAuth) and the
[Python client](https://pypi.org/project/pwfauth/), so a user can move between them
without tripping the device limit.

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

Custom fetch instances are trusted application code: configure them to reject redirects and validate TLS certificates. The SDK cannot inspect an injected transport's internal handler. Independent response signature verification still applies.
