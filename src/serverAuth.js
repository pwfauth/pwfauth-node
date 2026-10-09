import { createHash, createPublicKey, randomBytes, verify, constants } from 'node:crypto';
import { PwfSecurityError } from './errors.js';
const key = createPublicKey(`-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAxF7ROKevJDFTnyfYq5S1
QkdwMkY8tMAFhMgi5cMIFdpdCO7xvEtirmVUW+sHvttanDPXMQDGgDKdkbspsHpf
Gbr7vs6ScCltjrGSMx0FansQSvmYp0DVwYVByB0YEhyaej4B+FmwATfHLdFr+XAX
N+C5BWGpVNYfnt0WknasAn/FTncVr01hk4win2iz3C6avZI/T+YgtsWFJioLRmfu
UcMSZ+Hs2zEfCawImh6UPQhsotD8ZHgje8IsYVQTosA7WGX0Cyt1OoT1PJbBxsTO
QaWd6DWqNo4R6GUZzdkb+9Vjj71lmz92Y3rZsff+OIjdbToQqB/sappj4y5tQVtk
lXnDDs/vW45QAWS6PmKjUFuMetkxOSguUO4BbU2Qk4+/Fp60w2y2WSQuCg4g1nrA
aJAwb2b/h009dIlxzTwSPk8nfSlnIRDNbUxQkIUQHs/PgNag1qKc75+kZ6/0VXoP
+2uky8of/4ldFy6FxzRl6FO8jEgrDl8jZpwfiNipz7+pAgMBAAE=
-----END PUBLIC KEY-----`);
export const newNonce = () => randomBytes(32).toString('hex');
export function validateOrigin(url) {
    if (typeof url !== 'string' || url.replace(/\/+$/, '') !== 'https://pwfauth.com') throw new PwfSecurityError('Only https://pwfauth.com is supported.');
}
export function validatePath(path) {
    if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[\\#\r\n]/.test(path)) throw new PwfSecurityError('Invalid API path.');
}
export function verifyReply(nonce, method, path, request, status, body, signature) {
    const hash = value => createHash('sha256').update(value).digest('hex');
    const material = ['PWF-REPLY-V1', nonce, method, new URL(path, 'https://pwfauth.com').pathname, hash(request ?? ''), String(status), hash(body)].join('\n');
    if (!signature || !/^[A-Za-z0-9+/]+={0,2}$/.test(signature) || !verify('sha256', Buffer.from(material), {key, padding: constants.RSA_PKCS1_PADDING}, Buffer.from(signature, 'base64'))) throw new PwfSecurityError('Missing or invalid server signature.');
}
