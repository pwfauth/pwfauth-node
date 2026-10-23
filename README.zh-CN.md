<p align="center"><a href="README.md">English</a> · <b>简体中文</b> · <a href="README.tr.md">Türkçe</a> · <a href="README.ar.md">العربية</a></p>
<p align="center">视频教程：<a href="https://www.youtube.com/@pwfauth">youtube.com/@pwfauth</a></p>

# PWF Auth Node.js 客户端

## 立即安装此安全版本

1.2.0 版本尚未发布到 npm 仓库，直接执行 `npm install pwfauth` 可能仍会装上旧版本。请安装 GitHub 上的官方包，并保留生成的 lockfile：

```sh
npm install https://github.com/pwfauth/pwfauth-node/releases/download/v1.2.0/pwfauth-1.2.0.tgz
```

包的 SHA-256：`67c2500e1c2f06e198a72613f48b6229e9450b287d6f324efe6ceffb35574418`


## 服务器认证更新

所有响应（包括错误响应和时钟校正响应）都必须带有与内置固定（pinned）的 PWFAuth 公钥相匹配的有效 RSA-SHA256 签名。签名私钥只保存在服务器上，仅知道应用密钥（app secret）不足以伪造该签名。每个响应都通过一个全新的随机 nonce 与其请求、方法、路径、HTTP 状态码以及响应体的确切字节绑定（PWF-REPLY-V1）。查询字符串不属于 V1 签名路径的一部分，生产环境中由 HTTPS 保障其传输安全

SDK 只接受 `https://pwfauth.com`。默认传输层会校验 TLS 证书并拒绝重定向。签名缺失或无效时，会在解析 JSON 或解密信封之前直接失败（fail closed）；未签名的代理或 CDN 错误一律视为安全错误。不会回退到旧的未签名协议。请先更新服务器，再更新客户端。出现安全错误或传输错误后，应用绝不能解锁任何功能

这一机制用于防范伪造服务器，但无法阻止已控制客户端机器的攻击者修改应用本身。请把真正有价值的关键操作放在服务器端，也不要把真实的应用密钥放进公开仓库


[PWF Auth](https://pwfauth.com) 官方客户端：许可证密钥、用户账户、硬件 ID（HWID）绑定、带服务器端远程停用（kill switch）的加密会话、自助迁移设备、基于许可证密钥的账户、免费试用、远程内容以及 OTA 更新检查

```bash
npm install pwfauth
```

需要 Node 18+。零依赖，完全基于运行时自带的 `fetch` 和 `crypto`，并附带 TypeScript 类型定义

> **仅限服务器端使用。** 应用密钥绝不能出现在浏览器中。任何持有它的人都能以你的应用身份调用 API，所以不要把本包打包进前端代码。详见下文 [安全](#security)

## 1.1.0 新特性

* **远程停用无法绕过。** 只有加密的响应才算作服务器的答复。普通的拒绝响应不会再让会话永久保持有效，其中最常见的情况是服务器拒绝了被调整超过 5 分钟的系统时钟。伪造的 `{"success": true}` 同样不行
* **拒绝伪造的服务器。** 登录、心跳或应用内容接口返回未加密的 "success" 时，Promise 会以 `PwfSecurityError` 被 reject，而不是让用户登录
* **错误的电脑时钟会自动修正。** 客户端按服务器时间校准偏移后重试一次。可通过 `autoCorrectClock: false` 关闭
* **将许可证迁移到新电脑：** `resetHardwareId(key, reason)`
* **基于许可证密钥的账户：** `registerAccountWithKey()` 和 `redeemKey()`
* 无网络连接时的错误信息更清晰，并新增 `User-Agent` 请求头

详见 [CHANGELOG.md](CHANGELOG.md)

## 快速开始

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

## 为什么心跳很重要

`startHeartbeat()` 不是可有可无的例行操作，它正是强制执行授权的关键环节

* 服务器会丢弃停止心跳的会话，所以从不发送心跳的客户端虽然不会损失什么，却也永远不会得知自己已被吊销
* 每次心跳都会重新检查许可证：封禁、暂停、过期、HWID 重置、删除以及维护模式，都会在下一次心跳时立即结束会话
* 只有加密的响应才算作答复。如果连续 `maxHeartbeatFailures` 次心跳（默认 3 次）都没有得到加密答复，客户端会自行结束会话：
  * 原因包括没有响应、普通的拒绝响应，或伪造的普通 "success"；
  * 错误码为 `NETWORK_LOST`，如果服务器一直拒绝该时钟，则为 `CLOCK_SKEW`；
  * HTTP 429 有单独的额度：`maxRateLimitedBeats`（10）

  否则，只要在防火墙中屏蔽许可证域名，或者修改系统时钟，就能让应用永远运行下去

计时器已调用 `unref()`，因此它本身不会让进程保持运行

## 登录响应包含什么

`login.license` 会帮你解析许可证信息块，包括最容易让集成出错的那种情况：

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

| 属性 | 类型 | 说明 |
| --- | --- | --- |
| `licenseKey` | string | 已激活的密钥 |
| `keyType` / `duration` | string / number | `days`、`hours`、`lifetime` 等 |
| `hwid` | string | 此会话绑定的机器 |
| `activatedAt` | `Date \| null` | 首次激活时间 |
| `expiresAt` | `Date \| null` | **永久密钥为 `null`** |
| `daysRemaining` | `number \| null` | **永久密钥为 `null`** |
| `status` | string | `active` |
| `isLifetime` | boolean | 等价于 `expiresAt === null` 的便捷属性 |

API 日后新增的任何字段都可以通过 `login.data`（解析后的原始 JSON）直接访问，无需等待包更新

## 其他功能

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

## 将许可证迁移到新电脑

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

迁移会解除该密钥与所有机器的绑定，并结束它的所有会话。你可以在 App Settings 中决定是否允许客户自行迁移密钥，以及两次迁移之间的冷却时间（默认 12 小时）

本客户端尚未封装的接口仍然可以调用：`postEnvelope`、`getEnvelope` 和 `postPlain` 都是公开的，`CryptoEnvelope` 也是

## 处理失败

如果 API 只是简单地回答“不”，返回的是一个已 resolve 的 Promise，且 `success === false`。只有传输和加密问题才会 reject：

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

每个请求都接受 `AbortSignal`：

```js
await client.login(key, { signal: AbortSignal.timeout(5000) });
```

## 配置

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

## 硬件 ID

`getHardwareId()` 在 Windows 上读取加密子系统的 MachineGuid，在 Linux 上读取 `/etc/machine-id`，在 macOS 上读取平台 UUID，都不可用时回退到主机名。它不依赖 Windows 11 24H2 已移除的 `wmic`。同一台机器在本客户端、[.NET 客户端](https://www.nuget.org/packages/PWFAuth) 和 [Python 客户端](https://pypi.org/project/pwfauth/) 中生成的 HWID 完全相同，因此用户可以在它们之间切换，而不会触发设备数量限制

<a id="security"></a>
## 安全

信封协议使用应用密钥进行加密，因此运行客户端的一方必须持有它。这意味着：

* **只放在服务器端。** 绝不要把它发送到浏览器、移动应用安装包，或任何你无法控制的客户端
* 从环境变量（`process.env.PWFAUTH_SECRET`）或密钥管理服务中读取，绝不要提交到代码仓库
* 一旦泄露，请在后台轮换密钥。轮换会使所有已部署的副本失效，所以请提前规划发布

## 许可

MIT © PWF Auth

自定义的 fetch 实例属于受信任的应用代码：请将其配置为拒绝重定向并校验 TLS 证书。SDK 无法检查注入的传输层内部的处理逻辑。独立的响应签名校验依然有效
