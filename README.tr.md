<p align="center"><a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a> · <b>Türkçe</b> · <a href="README.ar.md">العربية</a></p>
<p align="center">Video eğitimleri: <a href="https://www.youtube.com/@pwfauth">youtube.com/@pwfauth</a></p>

# Node.js için PWF Auth

## Bu güvenlik sürümünü hemen yükleyin

1.2.0 sürümünün npm kayıt defterinde yayımlanması henüz bekliyor, bu yüzden düz bir `npm install pwfauth` komutu hâlâ eski sürümü yükleyebilir. Resmî GitHub paketini yükleyin ve oluşturulan lockfile dosyasını saklayın:

```sh
npm install https://github.com/pwfauth/pwfauth-node/releases/download/v1.2.0/pwfauth-1.2.0.tgz
```

Paketin SHA-256 değeri: `67c2500e1c2f06e198a72613f48b6229e9450b287d6f324efe6ceffb35574418`


## Sunucu kimlik doğrulama güncellemesi

Hata ve saat düzeltme yanıtları dahil tüm yanıtlar, sabitlenmiş (pinned) PWFAuth açık anahtarıyla doğrulanan geçerli bir RSA-SHA256 imzası taşımalıdır. İmzalama için kullanılan özel anahtar sunucuda kalır. Uygulama gizli anahtarını (app secret) bilmek bu imzayı taklit etmeye yetmez. Her seferinde yeni üretilen rastgele bir nonce, her yanıtı kendi isteğine, metoduna, yoluna, HTTP durum koduna ve gövdenin birebir baytlarına bağlar (PWF-REPLY-V1). Sorgu dizeleri (query string) V1 imzalı yolunun parçası değildir; üretim ortamında HTTPS bunları aktarım sırasında korur

SDK yalnızca `https://pwfauth.com` adresini kabul eder. Varsayılan aktarım katmanı TLS sertifikalarını doğrular ve yönlendirmeleri reddeder. Eksik veya geçersiz imzalar, JSON ayrıştırma ya da zarfın şifresini çözme adımından önce güvenli biçimde başarısız olur (fail closed); imzasız proxy/CDN hataları güvenlik hatası sayılır. Eski imzasız protokole geri dönüş yoktur. İstemcilerden önce sunucuyu güncelleyin. Uygulamalar bir güvenlik veya aktarım hatasından sonra hiçbir işlevin kilidini açmamalıdır

Bu önlem sunucu taklidine karşıdır. İstemci makinesini kontrol eden bir saldırganın uygulamanın kendisini değiştirmesini engellemez. Değerli işlemlerin asıl kararını sunucuda tutun ve gerçek uygulama gizli anahtarlarını herkese açık depolara koymayın


[PWF Auth](https://pwfauth.com) için resmî istemci: lisans anahtarları, kullanıcı hesapları, donanım kimliği (HWID) bağlama, sunucu tarafında uzaktan durdurma (kill switch) içeren şifreli oturumlar, cihazı kendi kendine taşıma, lisans anahtarlarıyla çalışan hesaplar, ücretsiz denemeler, uzak içerik ve OTA güncelleme kontrolleri

```bash
npm install pwfauth
```

Node 18+ gerekir. Hiçbir bağımlılığı yoktur: çalışma ortamının kendi `fetch` ve `crypto` modülleri üzerine kuruludur. TypeScript tanımlarıyla birlikte gelir

> **Yalnızca sunucu tarafında kullanın.** Uygulama gizli anahtarı asla bir tarayıcıya ulaşmamalıdır. Bu anahtara sahip olan herkes API'yi sizin uygulamanız adına çağırabilir; bu yüzden paketi ön yüz (front-end) koduna dahil etmeyin. Aşağıdaki [Güvenlik](#security) bölümüne bakın

## 1.1.0 sürümündeki yenilikler

* **Uzaktan durdurma atlatılamaz.** Yalnızca şifreli bir yanıt sunucunun cevabı sayılır. Düz bir ret artık oturumu sonsuza kadar açık tutmaz: en sık görülen örnek, sunucunun 5 dakikadan fazla oynanmış bir saati reddetmesidir. Sahte bir `{"success": true}` yanıtı da oturumu açık tutmaz
* **Sahte sunucu reddedilir.** Giriş, düzenli kontrol (heartbeat) veya uygulama içeriği uç noktalarından gelen şifresiz bir "success", kullanıcının oturumunu açmak yerine `PwfSecurityError` ile reddedilir
* **Yanlış bilgisayar saati kendini düzeltir.** İstemci, sunucunun saatine göre farkı uygular ve bir kez yeniden dener. Kapatmak için `autoCorrectClock: false` kullanın
* **Lisansı yeni bir bilgisayara taşıma:** `resetHardwareId(key, reason)`
* **Lisans anahtarlarıyla çalışan hesaplar:** `registerAccountWithKey()` ve `redeemKey()`
* Bağlantı olmadığında daha anlaşılır hatalar ve bir `User-Agent` başlığı

Ayrıntılar için [CHANGELOG.md](CHANGELOG.md) dosyasına bakın

## Hızlı başlangıç

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

## Heartbeat neden önemli

`startHeartbeat()` isteğe bağlı bir kayıt tutma işi değildir; lisans kurallarının uygulandığı noktanın ta kendisidir

* Sunucu, heartbeat göndermeyi bırakan oturumu düşürür. Hiç heartbeat göndermeyen bir istemci bir şey kaybetmez ama iptal edildiğini de asla öğrenmez
* Her heartbeat lisansı yeniden kontrol eder: yasaklama, duraklatma, süre dolması, HWID sıfırlama, silme ve bakım modu, oturumu hemen bir sonraki heartbeat'te sonlandırır
* Yalnızca şifreli bir yanıt cevap sayılır. Art arda `maxHeartbeatFailures` heartbeat (varsayılan 3) hiç şifreli cevap alamazsa istemci oturumu kendisi sonlandırır:
  * nedenler: yanıt gelmemesi, düz bir ret veya sahte bir düz "success";
  * kod `NETWORK_LOST` olur, sunucu saati reddetmeyi sürdürdüyse `CLOCK_SKEW` olur;
  * HTTP 429 için ayrı bir sınır vardır: `maxRateLimitedBeats` (10)

  Bu olmasaydı, lisans alan adını bir güvenlik duvarında engellemek ya da sistem saatini değiştirmek uygulamanın sonsuza kadar çalışmasını sağlardı

Zamanlayıcı için `unref()` çağrılmıştır; bu yüzden tek başına bir süreci açık tutmaz

## Giriş yanıtında neler var

`login.license`, lisans bloğunu sizin için ayrıştırır; entegrasyonların çoğunu tökezleten durum da buna dahildir:

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

| Özellik | Tür | Notlar |
| --- | --- | --- |
| `licenseKey` | string | Etkinleştirilen anahtar |
| `keyType` / `duration` | string / number | `days`, `hours`, `lifetime`, … |
| `hwid` | string | Bu oturumun bağlı olduğu makine |
| `activatedAt` | `Date \| null` | İlk etkinleştirme |
| `expiresAt` | `Date \| null` | **Ömür boyu anahtarlarda `null`** |
| `daysRemaining` | `number \| null` | **Ömür boyu anahtarlarda `null`** |
| `status` | string | `active` |
| `isLifetime` | boolean | `expiresAt === null` için kısayol |

API'nin ileride eklediği her alana, paket güncellemesi beklemeden `login.data` (ayrıştırılmış ham JSON) üzerinden erişmeye devam edebilirsiniz

## Başka neler yapar

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

## Lisansı yeni bir bilgisayara taşıma

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

Taşıma işlemi anahtarın tüm makinelerle bağını kaldırır ve oturumlarını sonlandırır. Müşterilerin anahtarlarını kendilerinin taşıyıp taşıyamayacağına ve iki taşıma arasındaki bekleme süresine (varsayılan 12 saat) App Settings bölümünde siz karar verirsiniz

Bu istemcinin henüz sarmalamadığı uç noktalara yine de erişilebilir: `postEnvelope`, `getEnvelope` ve `postPlain` herkese açıktır, `CryptoEnvelope` da öyle

## Hataları ele alma

API'nin yalnızca "hayır" diyen bir cevabı, `success === false` ile çözülen (resolved) bir promise'tir. Yalnızca aktarım ve şifreleme sorunlarında promise reddedilir (reject):

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

Her istek bir `AbortSignal` kabul eder:

```js
await client.login(key, { signal: AbortSignal.timeout(5000) });
```

## Yapılandırma

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

## Donanım kimliği

`getHardwareId()`, Windows'ta şifreleme altyapısının MachineGuid değerini, Linux'ta `/etc/machine-id` dosyasını, macOS'ta ise platform UUID'sini okur; bunlar yoksa ana bilgisayar adını kullanır. Windows 11 24H2'de kaldırılan `wmic` aracını kullanmaz. Aynı makine bu istemcide, [.NET istemcisinde](https://www.nuget.org/packages/PWFAuth) ve [Python istemcisinde](https://pypi.org/project/pwfauth/) aynı HWID'yi üretir; böylece kullanıcı cihaz sınırına takılmadan bunlar arasında geçiş yapabilir

<a id="security"></a>
## Güvenlik

Zarf protokolü şifrelemeyi uygulama gizli anahtarıyla yapar; bu nedenle istemciyi çalıştıran her ortamın bu anahtara sahip olması gerekir. Bu şu anlama gelir:

* **Sunucu tarafında tutun.** Asla bir tarayıcıya, mobil uygulama paketine veya kontrol etmediğiniz herhangi bir istemciye göndermeyin
* Ortam değişkeninden (`process.env.PWFAUTH_SECRET`) veya bir gizli anahtar yöneticisinden okuyun; asla commit etmeyin
* Sızarsa paneldeki anahtarı yenileyin (rotate). Yenileme, dağıtılmış tüm kopyaları geçersiz kılar; bu yüzden geçişi önceden planlayın

## Lisans

MIT © PWF Auth

Özel fetch örnekleri güvenilir uygulama kodu sayılır: bunları yönlendirmeleri reddedecek ve TLS sertifikalarını doğrulayacak şekilde yapılandırın. SDK, enjekte edilen bir aktarım katmanının iç işleyicisini inceleyemez. Bağımsız yanıt imzası doğrulaması yine de uygulanır
