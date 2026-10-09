// Test-only copy: substitutes a generated public key and loopback origin policy.
// Production-pin security tests import ../src directly and never use this helper.
import {mkdtempSync, cpSync, readFileSync, writeFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {generateKeyPairSync, createHash, sign} from 'node:crypto';
const keys=generateKeyPairSync('rsa',{modulusLength:3072});
const directory=mkdtempSync(join(tmpdir(),'pwfauth-regression-'));
cpSync(new URL('../src/',import.meta.url),join(directory,'src'),{recursive:true});
writeFileSync(join(directory,'package.json'),' {"type":"module"}');
const file=join(directory,'src/serverAuth.js');
let source=readFileSync(file,'utf8').replace(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/, keys.publicKey.export({type:'spki',format:'pem'}).trim());
source=source.replace("url.replace(/\\/+$/, '') !== 'https://pwfauth.com'", "(url.replace(/\\/+$/, '') !== 'https://pwfauth.com' && !url.startsWith('http://127.0.0.1:'))");
writeFileSync(file,source);
process.on('exit',()=>{ if(!directory.startsWith(join(tmpdir(),'pwfauth-regression-'))) throw Error('Unexpected test directory'); rmSync(directory,{recursive:true,force:true}); });
const sdk=await import(pathToFileURL(join(directory,'src/index.js')));
export const {CryptoEnvelope,PwfClient,PwfError,PwfHttpError,PwfSecurityError,PwfResponse,endsSession,PwfErrorCodes,VERSION}=sdk;
export function signReply(req,request,status,body) {
    const hash=x=>createHash('sha256').update(x).digest('hex');
    const material=['PWF-REPLY-V1',req.headers['x-pwf-nonce'],req.method,req.url.split('?')[0],hash(request),String(status),hash(body)].join('\n');
    return sign('sha256',Buffer.from(material),keys.privateKey).toString('base64');
}
