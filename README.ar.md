<p align="center"><a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a> · <a href="README.tr.md">Türkçe</a> · <b>العربية</b></p>
<p align="center">شروحات بالفيديو: <a href="https://www.youtube.com/@pwfauth">youtube.com/@pwfauth</a></p>

# مكتبة PWF Auth لبيئة Node.js

## ثبّت هذا الإصدار الأمني الآن

لم يُنشر الإصدار 1.2.0 في سجل npm بعد، لذلك قد يثبّت الأمر `npm install pwfauth` الإصدار الأقدم. ثبّت الحزمة الرسمية من GitHub واحتفظ بملف القفل (lockfile) الذي يُنشأ أثناء التثبيت:

```sh
npm install https://github.com/pwfauth/pwfauth-node/releases/download/v1.2.0/pwfauth-1.2.0.tgz
```

بصمة الحزمة SHA-256: `67c2500e1c2f06e198a72613f48b6229e9450b287d6f324efe6ceffb35574418`


## تحديث مصادقة الخادم

يجب أن تحمل جميع الردود، بما فيها ردود الأخطاء وردود تصحيح الساعة، توقيعاً صالحاً من نوع RSA-SHA256 يطابق المفتاح العام المثبّت (pinned) لـ PWFAuth. يبقى مفتاح التوقيع الخاص على الخادم، ومعرفة سر التطبيق وحدها لا تكفي لتزوير هذا التوقيع. يربط رقم عشوائي جديد (nonce) كل رد بطلبه وطريقته ومساره وحالة HTTP والبايتات الدقيقة لمحتواه (PWF-REPLY-V1). لا تدخل سلاسل الاستعلام (query strings) ضمن المسار الموقّع في V1، ويحميها HTTPS أثناء النقل في بيئة الإنتاج

لا تقبل حزمة SDK إلا العنوان `https://pwfauth.com`. يتحقق النقل الافتراضي من شهادات TLS ويرفض عمليات إعادة التوجيه. عند غياب التوقيع أو عدم صلاحيته يفشل الطلب بأمان (fail closed) قبل تحليل JSON أو فك تشفير المغلّف، وتُعامَل أخطاء الوكيل أو شبكة CDN غير الموقّعة على أنها أخطاء أمنية. لا يوجد رجوع إلى البروتوكول القديم غير الموقّع. حدّث الخادم قبل العملاء. يجب ألا يفتح التطبيق أي ميزة بعد خطأ أمني أو خطأ في النقل

يعالج هذا انتحال الخادم، لكنه لا يمنع مهاجماً يسيطر على جهاز العميل من تعديل التطبيق نفسه. أبقِ العمليات المهمة ذات القيمة على الخادم، وأبعد أسرار التطبيقات الحقيقية عن المستودعات العامة


العميل الرسمي لـ [PWF Auth](https://pwfauth.com): مفاتيح الترخيص، وحسابات المستخدمين، وربط الترخيص بمعرّف الجهاز (HWID)، وجلسات مشفّرة مع الإيقاف عن بُعد من جهة الخادم، ونقل الجهاز ذاتياً، وحسابات تعمل بمفاتيح الترخيص، والنسخة التجريبية المجانية، والمحتوى البعيد، والتحقق من التحديثات عبر الشبكة (OTA)

```bash
npm install pwfauth
```

يتطلب Node 18 أو أحدث. لا يحتاج إلى أي اعتماديات، فهو مبني على `fetch` و`crypto` المدمجين في بيئة التشغيل، ويأتي مع تعريفات TypeScript

> **للاستخدام على الخادم فقط.** يجب ألا يصل سر التطبيق إلى المتصفح أبداً. من يملكه يستطيع استدعاء الواجهة البرمجية باسم تطبيقك، لذلك لا تضمّن هذه الحزمة في كود الواجهة الأمامية. راجع قسم [الأمان](#security) أدناه

## ما الجديد في الإصدار 1.1.0

* **لم يعد التهرّب من الإيقاف عن بُعد ممكناً.** لا يُحتسب جواباً من الخادم إلا الرد المشفّر. لم يعد الرفض العادي يُبقي الجلسة حية إلى الأبد، وأكثر حالاته شيوعاً رفض الخادم لساعة نظام جرى تغييرها بأكثر من 5 دقائق. ولا يُبقيها كذلك رد مزيّف مثل `{"success": true}`
* **يُرفض الخادم المزيّف.** أي "success" غير مشفّر من نقاط نهاية تسجيل الدخول أو التحقق الدوري (heartbeat) أو محتوى التطبيق يجعل الوعد يُرفض بالخطأ `PwfSecurityError` بدلاً من تسجيل دخول المستخدم
* **تُصحَّح ساعة الجهاز الخاطئة تلقائياً.** يضبط العميل وقته وفق وقت الخادم ثم يعيد المحاولة مرة واحدة. لإيقاف ذلك استخدم `autoCorrectClock: false`
* **نقل الترخيص إلى جهاز جديد:** `resetHardwareId(key, reason)`
* **حسابات تعمل بمفاتيح الترخيص:** `registerAccountWithKey()` و`redeemKey()`
* رسائل خطأ أوضح عند انقطاع الاتصال، وترويسة `User-Agent`

راجع [CHANGELOG.md](CHANGELOG.md)

## البدء السريع

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

## لماذا يهم التحقق الدوري

الدالة `startHeartbeat()` ليست إجراءً تنظيمياً اختيارياً، بل هي النقطة التي يُفرض فيها الترخيص فعلاً

* يُسقط الخادم الجلسة التي تتوقف عن إرسال نبضات التحقق، لذلك لا يخسر العميل الذي لا يرسلها شيئاً، لكنه لا يعلم أبداً أن ترخيصه أُلغي
* تعيد كل نبضة فحص الترخيص: الحظر والإيقاف المؤقت وانتهاء الصلاحية وإعادة تعيين HWID والحذف ووضع الصيانة، كلها تُنهي الجلسة عند النبضة التالية مباشرة
* لا يُحتسب جواباً إلا الرد المشفّر. إذا لم تحصل `maxHeartbeatFailures` نبضة متتالية (3 افتراضياً) على أي رد مشفّر، يُنهي العميل الجلسة بنفسه:
  * الأسباب هي غياب الرد، أو الرفض العادي، أو "success" عادي مزوّر؛
  * الرمز هو `NETWORK_LOST`، أو `CLOCK_SKEW` إذا ظل الخادم يرفض الساعة؛
  * لحالة HTTP 429 رصيد مستقل هو `maxRateLimitedBeats` (10)

  لولا ذلك، لكان حظر نطاق الترخيص في جدار الحماية، أو تغيير ساعة النظام، كافياً لإبقاء التطبيق يعمل إلى الأبد

يُستدعى `unref()` على المؤقّت، لذلك لا يُبقي العملية قيد التشغيل بمفرده

## محتوى رد تسجيل الدخول

تحلّل الخاصية `login.license` كتلة الترخيص نيابةً عنك، بما في ذلك الحالة التي يتعثر بها معظم من يدمجون المكتبة:

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

| الخاصية | النوع | ملاحظات |
| --- | --- | --- |
| `licenseKey` | string | المفتاح الذي جرى تفعيله |
| `keyType` / `duration` | string / number | مثل `days` و`hours` و`lifetime` وغيرها |
| `hwid` | string | الجهاز المرتبطة به هذه الجلسة |
| `activatedAt` | `Date \| null` | أول تفعيل |
| `expiresAt` | `Date \| null` | **القيمة `null` لمفاتيح مدى الحياة** |
| `daysRemaining` | `number \| null` | **القيمة `null` لمفاتيح مدى الحياة** |
| `status` | string | القيمة `active` |
| `isLifetime` | boolean | اختصار للشرط `expiresAt === null` |

أي حقل تضيفه الواجهة البرمجية لاحقاً يبقى متاحاً عبر `login.data` (كائن JSON الخام بعد تحليله) دون انتظار تحديث للحزمة

## ميزات أخرى

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

## نقل الترخيص إلى جهاز جديد

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

يفك النقل ارتباط المفتاح بكل الأجهزة ويُنهي جلساته. في صفحة App Settings تحدد ما إذا كان العملاء يستطيعون نقل مفاتيحهم بأنفسهم، ومدة الانتظار بين عمليتي نقل (12 ساعة افتراضياً)

ما زالت نقاط النهاية التي لا يغلّفها هذا العميل بعد متاحة للاستدعاء: الدوال `postEnvelope` و`getEnvelope` و`postPlain` عامة، وكذلك الصنف `CryptoEnvelope`

## التعامل مع حالات الفشل

جواب الواجهة البرمجية الذي يقول "لا" ببساطة هو وعد يُحَل (resolved promise) بقيمة `success === false`. لا يُرفض الوعد إلا عند مشكلات النقل والتشفير:

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

يقبل كل طلب إشارة `AbortSignal`:

```js
await client.login(key, { signal: AbortSignal.timeout(5000) });
```

## الإعدادات

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

## معرّف الجهاز

تقرأ الدالة `getHardwareId()` قيمة MachineGuid من إعدادات التشفير في Windows، أو الملف `/etc/machine-id` على Linux، أو معرّف UUID للمنصة على macOS، وتعود إلى اسم المضيف إذا تعذّر ذلك. لا تستخدم الأداة `wmic` التي أزالها Windows 11 24H2. يُنتج الجهاز نفسه معرّف HWID نفسه في هذا العميل وفي [عميل .NET](https://www.nuget.org/packages/PWFAuth) و[عميل Python](https://pypi.org/project/pwfauth/)، لذلك يستطيع المستخدم التنقل بينها دون أن يصطدم بحد الأجهزة

<a id="security"></a>
## الأمان

سر التطبيق هو ما يستخدمه بروتوكول المغلّف (envelope) في التشفير، لذا يجب أن يملكه أي شيء يشغّل العميل. وهذا يعني:

* **أبقِه على الخادم.** لا ترسله أبداً إلى متصفح أو حزمة تطبيق جوال أو أي عميل لا تتحكم به
* اقرأه من متغير البيئة (`process.env.PWFAUTH_SECRET`) أو من مدير أسرار، ولا تحفظه في المستودع أبداً
* إذا تسرّب، غيّره من لوحة التحكم. تغييره يُبطل كل النسخ المنشورة، لذا خطّط لطرح التحديث مسبقاً

## الرخصة

رخصة MIT © PWF Auth

دوال fetch المخصّصة تُعدّ كوداً موثوقاً من التطبيق نفسه: اضبطها لترفض عمليات إعادة التوجيه وتتحقق من شهادات TLS. لا تستطيع حزمة SDK فحص المعالج الداخلي لوسيلة نقل محقونة. ويبقى التحقق المستقل من توقيع الرد مطبّقاً في كل الأحوال
