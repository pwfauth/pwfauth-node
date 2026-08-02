import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { hostname } from 'node:os';

let cached = null;

/**
 * A stable per-machine identifier, mirroring the .NET client so the same machine
 * produces the same HWID under either SDK.
 *
 * Windows reads the cryptography MachineGuid through `reg.exe` — deliberately not
 * `wmic`, which Windows 11 24H2 removed. Linux reads `/etc/machine-id`, macOS the
 * IOPlatformUUID. Anything that fails falls back to the host name.
 *
 * @returns {string}
 */
export function getHardwareId() {
    if (cached !== null) return cached;
    let value = '';
    try {
        value = resolve();
    } catch {
        // Any probe failure falls through to the host-name fallback.
    }
    cached = (value || safeHostname()).trim();
    return cached;
}

/** Clears the cache. Only useful in tests. */
export function resetHardwareIdCache() {
    cached = null;
}

function resolve() {
    if (process.platform === 'win32') return windowsMachineGuid();
    if (process.platform === 'darwin') return macPlatformUuid();
    if (existsSync('/etc/machine-id')) return readFileSync('/etc/machine-id', 'utf8').trim();
    if (existsSync('/var/lib/dbus/machine-id')) return readFileSync('/var/lib/dbus/machine-id', 'utf8').trim();
    return '';
}

function windowsMachineGuid() {
    const out = run('reg', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid']);
    // "    MachineGuid    REG_SZ    2f5a1c8e-..."
    const marker = out.toUpperCase().indexOf('REG_SZ');
    return marker < 0 ? '' : out.slice(marker + 'REG_SZ'.length).trim();
}

function macPlatformUuid() {
    const out = run('ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice']);
    const m = /"IOPlatformUUID"\s*=\s*"([^"]+)"/.exec(out);
    return m ? m[1] : '';
}

function run(file, args) {
    try {
        // windowsHide keeps a console window from flashing over a GUI app.
        return execFileSync(file, args, {
            encoding: 'utf8',
            timeout: 5000,
            windowsHide: true,
            stdio: ['ignore', 'pipe', 'ignore'],
        });
    } catch {
        return '';
    }
}

function safeHostname() {
    try {
        return hostname() || 'unknown-host';
    } catch {
        return 'unknown-host';
    }
}
