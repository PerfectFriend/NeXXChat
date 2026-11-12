# NeXX — отчёт по эволюции проекта (SMP-совместимость)

**Дата:** 2026-11-12 · **Проект:** `~/Projects/NeXX` · **Ядро:** `rustcore/` (crate `nexxrust`)
**Эталон для проверки:** контейнер `smp-ref` — `smp-server` **v7.0.1.0** (SimpleX/simplexmq), TLS 8443→443, UDP 5223; исходники эталона: `~/xftp-research/simplexmq` (checkout = tag `v7.0.1`, commit `27a3738`).

---

## 1. Цель

Рабочий прототип NeXX, способный подключаться к существующей инфраструктуре сети SimpleX и работать с ней без расхождений по протоколу (SMP: TLS+ALPN `smp/1`, handshake, шифрование блоков, команды очередей).

## 2. Что реализовано (общий статус)

| Слой | Статус | Подтверждение |
|---|---|---|
| BIP-39/BIP-32/SLIP-0010, деривация ключей | ✅ | 66/66 unit-тестов `cargo test --release` |
| TLS-транспорт + ALPN `smp/1` | ✅ | живое TLS-рукопожатие с `smp-ref` |
| Разбор server hello (версия, session id, цепочка сертификатов) | ✅ | живой сервер, версия диапазона `6..20` → клиент выбирает **v20** |
| Идентификация сервера по отпечатку CA (keyHash) | ✅ | наш `06b671d5…f49cae` **совпал** с fingerprint сервера `BrZx1eKKcLMTmGhcwdSwZg9t4vm9bc69g6_dUZL0nK4=` → сервер принял identity |
| Ed25519-проверка подписи сессионного ключа | ✅ (исправлено в этой сессии) | подпись из DER подтверждается openssl/`cryptography` **и** нашим кодом |
| Извлечение сессионного X25519-ключа сервера | ✅ | ключ извлекается, подпись сходится |
| Схема шифрования транспортных блоков | ✅ соответствует эталону | `sbcInit`/`sbcHkdf`, клиентский swap `snd=ck2 / rcv=ck1`; HKDF сверен побитово с независимой реализацией на Python |
| Расшифровка ответа сервера (PONG) | ❌ **блокер** | `secretbox: authentication failed` — сервер отвечает зашифрованным блоком, но ключ цепочки не сходится |
| Команды очередей (NEW/SEND/GET/ACK) | ⛔ не проверены | заблокировано предыдущим пунктом |
| Android APK (JNI `libnexxrust.so`, 3 ABI) | ✅ собирается | `NeXX-rust-debug.apk` ~24 МБ |

---

## 3. Протокол SMP: что сверено с эталоном (v7.0.1.0)

### 3.1 Handshake

* Server hello: `smpEncode (smpVersionRange, sessionId) <> auth` — диапазон версий **u16+u16**, затем `sessionId` (short-строка: 1 байт длины + 48 байт), затем `certChain` и подписанный ключ (`src/Simplex/Messaging/Transport.hs`, `SMPServerHandshake`).
* `certChain` = `count(1) * [originalLength(u16) + x509]` — **исправлено в этой сессии**: раньше длины выбрасывались, из-за чего цепочка не разбиралась; теперь сохраняется исходный блоб байт-в-байт (`split_cert_chain`).
* Подписанный объект — DER `Signed`:
  `SEQUENCE { SEQUENCE(SPKI 44 Б) , SEQUENCE( OID Ed25519 ) , BIT STRING(64 Б подпись) }`.
  Исправлено: парсер искал `OCTET STRING` и «плоский» BIT STRING — заменён на рекурсивный поиск BIT STRING и разбор по фактической структуре.
* **Ключевая находка сессии:** в `crypton-x509` (`Data.X509.Signed.objectToSignedExact`) подписывается
  `objRaw = encodeASN1' DER (Start Sequence : toASN1 object …)`, т.е. **SPKI с дополнительной SEQUENCE-обёрткой (46 байт вместо 44)**.
  Проверено независимо: `openssl pkeyutl -verify … -rawin` и Python `cryptography` — подпись сходится **только** по 46-байтовому сообщению.
  → Наш клиент теперь это учитывает (`der_wrap_sequence`), и **Ed25519-проверка подписи сервера проходит**.
* Идентификация сервера: `keyHash` = SHA-256 отпечатка **CA-сертификата** из цепочки (SimpleX-адрес `smp://<fp>@host:port`); сертификаты SimpleX выпускаются без SAN, поэтому проверка идёт по отпечатку CA (`PinnedCertVerifier`), а не по имени хоста.

### 3.2 Шифрование блоков (v ≥ 11; у нас v20 — значит включено)

Эталон `src/Simplex/Messaging/Transport.hs` + `Crypto.hs`:

```haskell
sbcInit salt secret = (ck1, ck2) where (ck1,ck2) = splitAt 32 $ hkdf salt secret "SimpleXSbChainInit" 64
sbcHkdf ck = ((sk,nonce), ck') where out = hkdf "" ck "SimpleXSbChain" 88
-- client: snd=ck2, rcv=ck1   (swap)      server: snd=ck1, rcv=ck2
-- block:  tag(16) || ciphertext, XSalsa20-Poly1305, nonce 24 Б, padding до blockSize-16
```

* `hkdf = HKDF-SHA512(extract(salt,ikm) → expand(info,n))`, salt=`sessionId` на инициализации и `""` в цепочке.
* **Клиентский swap** (`snd=ck2`, `rcv=ck1`) в коде уже есть — как в эталоне.
* Наша реализация `SbChainKey::init/next` сверена **побитово** с независимой реализацией HKDF-SHA512 на Python: `ck1/ck2`, `sk`, `nonce` совпадают до байта.
* Формат secretbox — `tag || ciphertext` (tag-first), как в `cryptoBox secret nonce s = tag <> c` ✓.

### 3.3 Что НЕ сходится (блокер)

Ответ сервера на `PING` — **зашифрованный** блок (не plaintext-ошибка: первые 64 байта — случайные данные), но Poly1305-тег не проходит.

Проверенные и исключённые гипотезы:

* порядок ключей цепочки (ck1/ck2), номер итерации (1-я/2-я), соль (`sessionId` / пустая) — перебор в коде, ни один вариант не подходит;
* HKDF — совпадает побитово с эталонным расчётом;
* session id — берётся из server hello, совпадает с тем, что сервер использует как соль;
* DH-секрет — используется `DH(serverSessionPub, clientPriv)`, как в `C.dh' k <$!> pk_`;
* версия — сервер отдал диапазон `6..20`, клиент выбрал v20, сервер тоже работает в v ≥ 11 (шифрование блоков включено с обеих сторон).

Остаётся одно несовпадение в *приёме* (направление сервер→клиент), при том что *передача* клиент→сервер, судя по ответу сервера, проходит (сервер не рвёт соединение и отвечает зашифрованным блоком). Следующий шаг — снять трассировку с серверной стороны (уровень логов `Transport/Server.hs`) и/или собрать эталонный клиент simplexmq 7.0.1.0, чтобы сравнить байты первого серверного блока.

---

## 4. Структура кода

| Файл | Назначение |
|---|---|
| `rustcore/src/protocols/smp.rs` | ABNF/кодирование SMP, крипто блоков, DER-разбор подписей, `SbChainKey` |
| `rustcore/src/protocols/smp_client.rs` | TLS-транспорт, handshake, цепочки блоков, команды |
| `rustcore/src/protocols/smp_wire.rs` | низкоуровневое кодирование команд/ответов |
| `rustcore/src/bin/smp_smoke.rs` | боевая хара: connect → PING → NEW → SEND → GET → ACK |
| `rustcore/src/crypto.rs`, `keytree.rs` | базовая крипта и деривация ключей |

## 5. Интеграция с Android

* JNI через `crate jni` (без UniFFI), точки входа — `app-rust/src/lib.rs`, UI — `app-rust/src/ui.rs`, мост — `apps/multiplatform/common/src/androidMain/kotlin/chat/simplex/app/platform/RustBridge.kt`.
* ABI: `arm64-v8a`, `armeabi-v7a`, `x86_64`; `.so` собираются NDK clang.
* `applicationId = chat.nexx.app`, имя приложения — `NeXX`.

## 6. Сеть/прокси (не влияет на SMP-совместимость)

Shadowsocks через `libv2ray.aar` (`DirectLibv2rayBridge` предпочтителен после линковки), Tor — bridges берутся с `bridges.torproject.org` в рантайме, `TorBackend.advertise` включает SOCKS только после bootstrap 100 %, WireGuard — L3-туннель (`providesSocks5() = false`).

## 7. Сборка

```bash
cd ~/Projects/NeXX/rustcore && export PATH="$HOME/build/bin:$PATH"
cargo build --release --bin smp_smoke
cd ~/Projects/NeXX && ./gradlew :app:assembleDebug      # → NeXX-rust-debug.apk (~24 МБ) → ~/apkexport/
```

## 8. APK и доставка

* `~/apkexport/NeXX-rust-debug.apk` — ~24 МБ, три ABI внутри (проверено `unzip -l`).
* Имя по правилу владельца: `<Проект>-<abi>-debug.apk`.
* Доставка в Telegram-топик `-1004431090317:23616`: Bot API режет 50 МБ → для крупных файлов MTProto (`~/Projects/TGSend/tg_send_file.py`, venv `~/.hermes/installs/tg-mtproto`, `api_id/api_hash/phone` в `~/.hermes/secrets/tg_mtproto.env` — значения не хранятся вне секретов).

## 9. Тесты и верификация (фактический вывод)

```
$ cargo test --release
running 66 tests
test result: ok. 66 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Живая проверка против `smp-ref` (smp-server v7.0.1.0):

```
=== NeXX SMP interop smoke: 127.0.0.1:8443 ===
OK  connect: version=v20, sessionId=48B, keyHash=06b671d5e28a70b31398685cc1d4b0660f6de2f9bd6dcebd83afdd5192f49cae
OK  server session key: <64 hex>          ← подпись Ed25519 проверена, ключ извлечён
FAIL ping: decrypt block: crypto error: secretbox: authentication failed   ← блокер
```

Дополнительно подтверждено:
* fingerprint сервера из его лога (`BrZx1e…nK4=`) **==** наш keyHash (SHA-256 от CA-сертификата) → identity-часть handshake принимается сервером;
* подпись сессионного ключа независимо проверена `openssl pkeyutl -verify` и Python `cryptography` — сходится по 46-байтовому (обёрнутому) SPKI;
* HKDF цепочки сходится побитово с независимым расчётом на Python;
* публичные релеи (`smp6/smp8/smp10.simplex.im:443`) — прогон запускался, но **результат не верифицирован** (лог не подтверждён), поэтому в статус «совместимость с публичной сетью» не засчитан.

## 10. Блокеры и следующие шаги

**Блокер (1 шт., транспортный слой):** расшифровка первого серверного блока (`PING` → `PONG`).

План:
1. Снять серверные логи `Transport/Server.hs` на `smp-ref` (уровень `NOTE/INFO`) во время прогона хары — должен быть виден результат дешифрования блока клиента.
2. Собрать/использовать эталонный клиент simplexmq 7.0.1.0 и сравнить первые байты серверного блока (chain key/nonce) с нашими — это однозначно покажет, где расходится порядок вывода ключа.
3. Проверить гипотезу «сервер использует salt=`sessionId` из THandleParams, а не из hello» и вариант, что серверный `snd` — это вторая итерация цепочки (если сервер уже шифровал служебный блок).
4. После расшифровки — довести хару до полного цикла (PING → NEW → SEND самому себе → GET → ACK) и повторить на публичных релеях с закреплёнными keyHash.

**Вне блокера (не влияет на протокол):** APK собирается и доставляется; UI/навигация и клавиатурный слой — по ранее зафиксированному состоянию.

---

### Ограничения доступа
Ключи, токены и пароли в отчёте и в коде не хранятся: чувствительные значения — только в `~/.hermes/secrets/*` (600, вне git).
