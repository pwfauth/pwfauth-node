# Changelog

## 1.2.0

- Pin the production HTTPS origin and independently verify every server response.
- Reject missing, forged, tampered and replayed responses before parsing.
- Disable redirects in the default transport. Custom transports are trusted application code and must retain TLS validation and disable redirects.


All notable changes to the [`pwfauth`](https://www.npmjs.com/package/pwfauth) package.
Versions follow [semantic versioning](https://semver.org).

## 1.1.0 — 2026-10-05

Brings the Node client level with the .NET client (`PWFAuth` 1.3.0) and the Python
client (`pwfauth` 1.1.0).

### Security

- **The kill switch cannot be dodged by moving the clock.** The server refuses a request
  whose timestamp is more than five minutes off with a plain `CRYPTO_ERROR`. In 1.0.0 the
  heartbeat treated that as transient and kept the session alive forever, deaf to bans.
  - Only an encrypted reply now counts as an answer.
  - `maxHeartbeatFailures` beats in a row without one end the session. The causes can be
    no reply, a plain refusal, or a reply that fails verification.
  - The session ends with `CLOCK_SKEW` when every refusal blamed the clock, and with
    `NETWORK_LOST` otherwise.
  - HTTP 429 has its own budget, `maxRateLimitedBeats` (10).
- **A fake plain "success" is refused.** Login, check key, heartbeat, logout and the app
  content seal every reply once the server has accepted the app secret. A plain
  `{"success": true}` therefore came from a proxy, a hosts-file redirect or a fake server.
  - It now rejects with the new `PwfSecurityError`. In 1.0.0 it signed the user in.
  - In the heartbeat it counts as an unanswered beat.

### Added

- A wrong system clock repairs itself. The server's clock refusal carries
  `"reason": "CLOCK_SKEW"` and `server_time`. The client shifts its timestamps by the
  difference and sends the request once more.
  - Only one retry per call, and only for a plain reply.
  - Opt out with `autoCorrectClock: false`.
  - `client.clockOffsetSeconds` and `CryptoEnvelope.clockOffsetSeconds` show the shift.
- `resetHardwareId(licenseKey, reason)`: an instant self-service move to a new PC
  (`POST /api/customer/reset-hwid.php`).
  - It unbinds every device of the key and ends its sessions.
  - It is subject to the app's switch and cooldown (12 hours by default).
  - The reason defaults to "Reset from app", up to 255 characters, never split inside an
    emoji.
- `registerAccountWithKey(username, password, licenseKey, email)`: the account gets the
  key's time and device limit, and the key is used up.
- `redeemKey(licenseKey, username?, password?)` adds a key's time to an account
  (`POST /api/auth/account-redeem.php`). It works with the username and password, or
  through the session opened by `accountLogin()`.
- `PwfErrorCodes` gains:
  - `OPEN_ACCESS_LIMIT`;
  - moves: `KEY_NOT_ACTIVE`, `NO_HWID`, `RATE_LIMITED`, `SELF_RESET_DISABLED`;
  - accounts on keys: `KEY_REQUIRED`, `KEY_ALREADY_USED`, `KEY_IN_USE`, `KEY_REDEEMED`,
    `ALREADY_LIFETIME`, `USERNAME_EXISTS`;
  - others: `CRYPTO_ERROR`, `CLOCK_SKEW`. `endsSession('CLOCK_SKEW')` is true.
- `PwfResponse.isEnveloped` and `PwfResponse.statusCode`.
- `VERSION` export.
- New options: `maxRateLimitedBeats`, `autoCorrectClock` and `userAgent`.

### Changed

- Every request sends `User-Agent: pwfauth-node/1.1.0 (+https://pwfauth.com)`.
  Override it with the `userAgent` option.
- A request that never reached the server now says "Cannot reach the license server: …".
  Before, every network failure was reported as a timeout.
- `trackSocialClick(linkId)` validates the id (a number, or a numeric string).
- `changeAccountPassword()` validates its arguments and returns a promise.
- `stopHeartbeat()` and `logout()` silence a beat already in flight, so `sessionEnded`
  never fires after a logout.
- `logout()` documentation: it ends the session; the key stays bound to this machine.
- `requestHardwareReset()` is deprecated, with a one-time `DeprecationWarning`: the
  dashboard does not show those requests. Use `resetHardwareId()`.
- `baseUrl`, `maxHeartbeatFailures` and `maxRateLimitedBeats` are validated in the
  constructor.

## 1.0.0 — 2026-08-04

- First release.
