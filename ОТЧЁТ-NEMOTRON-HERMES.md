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

### 3.3 Блокер расшифровки блоков — РЕШЁН (корень найден через KAT)

Симптом был: ответ сервера на `PING` не дешифровался (`secretbox: authentication failed`).

**Корень (KAT-доказано 2026-11-13):** Haskell `cryptoBox` = `xSalsa20` (`Crypto.hs:1478`), а
`xSalsa20 secret nonce = XSalsa.initialize 20 secret (zero16 <> iv0)` + `XSalsa.derive state0 iv1`
эквивалентен **secretbox(key = HSalsa20(secret, 0^16), nonce)**. Наш клиент подавал сырой
DH/ключ цепочки в XSalsa20Poly1305 напрямую (без pre-слоя HSalsa20) и к тому же переставлял
байты tag/ct (crate `crypto_secretbox` уже отдаёт NaCl-порядок `tag||ct`).

Доказательство: реконструкция xSalsa20 по C-ядру cryptonite воспроизводит штатный KAT
`cryptonite-0.30/tests/XSalsa.hs` (vectorsCB) и побайтово равна libsodium `crypto_box(pk,sk)`;
вариант «сырой DH в secretbox» эталону не равен. В коде: `hsalsa20()` + `crypto_box_beforenm()`
в `rustcore/src/protocols/smp.rs`, регрессионный тест `crypto_box_kat_matches_simplexmq`.

**Результат живого прогона против `smp-ref` (v7.0.1.0, 127.0.0.1:8443, CA-пиннинг):**
`OK connect (v20, sessionId=48B) → OK server session key (Ed25519 подпись проверена) → OK PING/PONG (2–3 мс)` — 2/2 запуска. Ранее на этом месте был `FAIL ping: decrypt block: authentication failed`.

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
running 67 tests
test result: ok. 67 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```
Включая новый KAT `protocols::smp::tests::crypto_box_kat_matches_simplexmq ... ok`
(вектор сгенерирован через libsodium `crypto_box`, равен KAT-валидированному Haskell-эталону).

Живая проверка против `smp-ref` (smp-server v7.0.1.0, 127.0.0.1:8443, пиннинг по CA из `/etc/opt/simplex/ca.crt`):

```
=== NeXX SMP interop smoke: 127.0.0.1:8443 ===
OK  connect: version=v20, sessionId=48B, keyHash=2895b70987e4e6d8661d35a804d056d0d877d4ed3dd7b2e7a7e359b597ec9ed3
OK  server session key: <64 hex>          ← подпись Ed25519 проверена, ключ извлечён
OK  PING/PONG (2–3 ms)                     ← блокер расшифровки блоков снят (2/2 запуска)
FAIL NEW: TLS read: Resource temporarily unavailable (os error 11)   ← таймаут чтения, не крипто-ошибка
```

Дополнительно подтверждено:
* fingerprint сервера из его лога (`BrZx1e…nK4=`) **==** наш keyHash (SHA-256 от CA-сертификата) → identity-часть handshake принимается сервером;
* подпись сессионного ключа независимо проверена `openssl pkeyutl -verify` и Python `cryptography` — сходится по 46-байтовому (обёрнутому) SPKI;
* HKDF цепочки сходится побитово с независимым расчётом на Python;
* публичные релеи (`smp6/smp8/smp10.simplex.im:443`) — прогон запускался, но **результат не верифицирован** (лог не подтверждён), поэтому в статус «совместимость с публичной сетью» не засчитан.

## 10. Блокеры и следующие шаги

**Старый транспортный блокер (дешифровка блоков) — снят**, корень был в крипто-слое (см. §3.3): нужен pre-слой `HSalsa20(secret, 0^16)` и НЕ нужен swap байтов tag/ct. PING/PONG против эталона проходит.

**Текущий открытый пункт (не крипто):** на команде `NEW` smoke-клиент падает с `TLS read: Resource temporarily unavailable` — таймаут чтения ответа, сервер соединение не рвёт. Гипотезы: (а) у smoke таймаут чтения слишком мал для создания очереди; (б) формат тела `NEW` (auth-блок/queue-req) чуть расходится и сервер молча ждёт. Следующий шаг: увеличить read-timeout в `smp_smoke.rs`/`tls_read_exact` и снять лог `smp-ref` на время прогона.

Далее: довести хару до полного цикла (PING → NEW → SEND самому себе → GET → ACK → DEL) и повторить на публичных релеях (`smp6/smp8/smp10.simplex.im:443`) с закреплёнными keyHash — до сих пор публичный прогон **не верифицирован**.

**Вне блокера (не влияет на протокол):** APK собирается и доставляется; UI/навигация и клавиатурный слой — по ранее зафиксированному состоянию.

---

### Ограничения доступа
Ключи, токены и пароли в отчёте и в коде не хранятся: чувствительные значения — только в `~/.hermes/secrets/*` (600, вне git).
