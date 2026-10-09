import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {verifyReply} from '../src/serverAuth.js';
import {PwfClient, PwfSecurityError, CryptoEnvelope} from '../src/index.js';
test('real server signature binds nonce, method, path, request, status and response', () => {
    const v = JSON.parse(readFileSync(new URL('./signed-reply.json', import.meta.url)));
    const check = x => verifyReply(x.nonce,x.method,x.path,x.request,x.status,Buffer.from(x.body),x.signature);
    check(v);
    for (const [field,value] of [['nonce','b'.repeat(64)],['method','GET'],['path','/api/auth/heartbeat.php'],['request','{}'],['status',401],['body','{}'],['signature',''],['signature','AAAA'],['signature','!']]) assert.throws(() => check({...v,[field]:value}),PwfSecurityError);
});
test('forbidden production origins fail before network', () => {
    for(const baseUrl of ['http://pwfauth.com','http://127.0.0.1:8080','https://evil.test','https://pwfauth.com.evil.test','https://pwfauth.com@evil.test','https://pwfauth.com:444','https://pwfauth.com/api']) assert.throws(()=>new PwfClient({appSecret:'a'.repeat(64),baseUrl}),PwfSecurityError);
});
test('unsigned reply rejected, redirects disabled and fresh nonce on every attempt', async () => {
    const nonces = new Set();
    const client = new PwfClient({appSecret:'a'.repeat(64), fetch: async(url,init)=>{
        assert.equal(url,'https://pwfauth.com/api/auth/login.php');
        assert.equal(init.redirect,'error');
        const nonce=init.headers['X-PWF-Nonce']; assert.match(nonce,/^[a-f0-9]{64}$/); nonces.add(nonce);
        return new Response(new CryptoEnvelope("a".repeat(64)).encrypt('{"success":true,"session_id":"fake"}'));
    }});
    await assert.rejects(client.login('anything'),PwfSecurityError);
    await assert.rejects(client.login('anything'),PwfSecurityError);
    assert.equal(nonces.size,2); assert.equal(client.isSignedIn,false);
});
