# Upgrading existing applications

Existing installed, version-pinned SDKs are unchanged. This release does not modify
your source tree, app IDs, license keys, users or database. Floating dependency
ranges can select a new release during a future install/update; use a lockfile and
test the upgrade before distributing it to customers.

Preserve your own changes: upgrade the SDK dependency in your application, or merge
the SDK changes into your fork. Do not replace your entire customized application
with an example repository. Resolve source conflicts normally; no existing remote
history was rewritten for this release.

## Intentional compatibility changes

- Only https://pwfauth.com is accepted. Self-hosted/staging/custom origins are rejected.
- Every HTTP reply must be signed by the production response-signing key. Unsigned
  mock servers, proxies and CDN error pages fail closed with a security exception.
- Shared-secret encryption alone no longer authenticates a response.
- The default transport validates TLS certificates and refuses redirects. Injected
  custom HttpClient/fetch implementations are trusted application code and must
  preserve both properties themselves; signature verification still applies.
- The distributed example applications no longer read app-secret or server-URL
  environment overrides. Configure the documented source constant or App.config
  before building, and do not commit real secrets. Core SDK constructors still
  accept the application's configured app secret.

Login/heartbeat/logout calls remain available. Session handling, license identifiers
and application data are not migrated. Existing users do not need replacement keys.

## Upgrade checklist

1. Preserve a backup/commit of your application's custom changes and dependency lockfile.
2. Upgrade Python/Node pwfauth to 1.2.0 or NuGet PWFAuth to 1.4.0.
3. Remove alternate server URLs; review custom transports and exception handling.
4. Test a valid license, invalid license, heartbeat/logout, and offline behavior.
5. Confirm that a security/transport exception never unlocks protected features.
6. Rebuild and distribute your application. Old binaries do not update themselves.

The production signing service was deployed before these SDKs and keeps the legacy
protocol for older clients. Client authentication cannot prevent an attacker from
patching an executable/source they control; enforce valuable operations server-side.
