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
* Идентификация сервера: `keyHash` = SHA-256 отпечатка **CA-сертификата** из цепочки (SimpleX-адрес `smp://<fp>@host:port`); сертификаты SimpleX выпускаются без SAN, поэтому проверка идёт по отпечатку CA, а не по имени хоста.
* **Аутентификация сервера переработана по итогам внешнего аудита (C1, закрыто):**
  * `keyHash` **обязателен** в API (`smpConnect(host, port, caPem, keyHashHex, …)`); пустой CA PEM или keyHash → ошибка, а не «пропустить проверку»;
  * настоящая проверка цепочки: CA ищется по **строгому** совпадению SHA-256(DER), leaf проверяется через `X509Store`/`X509StoreContext` (проверка подписи), сравнение constant-time (`ct_eq`);
  * **удалены**: `set_verify(SslVerifyMode::NONE)` на боевом пути, any-match по отпечаткам цепочки, CN-fallback для самоподписанного leaf;
  * цепочка из SMP-hello обязана совпадать с TLS-цепочкой, а её CA-fingerprint — с закреплённым keyHash;
  * **channel binding**: `session_id` из server hello обязан совпасть с **собственным** TLS Finished клиента (`ssl.finished()`, не `peer_finished()`) — проверено побайтово против `smp6.simplex.im:5223`;
  * негативные тесты: `rustcore/tests/audit_c1_pinning.rs` — 6 reject-сценариев + тест constant-time.

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

**Результат живого прогона против `smp-ref` (v7.0.1.0, 127.0.0.1:443, CA-пиннинг), после двух фиксов (крипто-слой + serviceSig, см. ниже) — ПОЛНЫЙ ЦИКЛ:

```
OK  connect: version=v20, sessionId=48B, keyHash=2895b709...
OK  server session key: <Ed25519, подпись проверена>
OK  PING/PONG
OK  NEW -> IDS: rcvId=... sndId=...
OK  SEND accepted by server
OK  MSG received: msgId=... ts=... flags=F
OK  payload decrypted and matches: "final-clean"   ← E2E crypto_box через DH(rcvDhPub, senderEph)
OK  ACK accepted
OK  DEL queue
=== INTEROP OK in 86 ms ===
```

**Второй корень (найден живым прогоном):** при v≥16 (`serviceCertsSMPVersion = 16`,
`serviceAuth=true` в `THandleParams`) transmission с **непустым authenticator** должен
содержать после него байт `serviceSig` (`'0'` = нет сервисной подписи). Без него серверный
`transmissionP` читает corrId-length как tag Maybe → parse fail → `ERR BLOCK` с пустым
corrId. Поэтому PING (пустой auth) проходил, а подписанный NEW — нет. Фикс:
`encode_transmission_v(version, t)` / `decode_transmission_v` в `smp_wire.rs` (пишем `'0'`
при v≥16 и непустом auth), клиент вызывает с `self.version`; юнит-тест
`service_sig_byte_present_for_signed_transmission_v16_plus`.

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

* `~/apkexport/NeXX-allabi-debug.apk` — **59 111 234 байт**, три ABI внутри (проверено `unzip -l`): arm64-v8a (15 142 352 Б), armeabi-v7a (10 668 116 Б), x86_64 (16 901 280 Б).
* Имя по правилу владельца: `<Проект>-<abi>-debug.apk`.
* Доставка в Telegram-топик `-1004431090317:23616`: Bot API режет 50 МБ → для крупных файлов MTProto (`~/Projects/TGSend/tg_send_file.py`, venv `~/.hermes/installs/tg-mtproto/venv`, `api_id/api_hash/phone` в `~/.hermes/secrets/tg_mtproto.env` — значения не хранятся вне секретов).
* Последняя доставка: **`id=31692`**, `size=59111234`, `chat=-1004431090317`, `topic=23616` (MTProto, подтверждено выводом отправщика).
* **⚠️ id=31691 — БИТЫЙ, не использовать:** пост-обработка путей заменяла `/home/thomas` (12 Б) на 8 байт, ELF сдвигался на 20 Б и переставал читаться (`nm: file too short`, 0 JNI-экспортов). Исправлено в коммите `1ba87cb` (замена строго равной длины + assert на размер + приёмка `nm -D | grep -c 'Java_' > 0` в `app-rust/build-android.sh`).
* **Проверка содержимого APK (приёмка аудита):** в `.so` внутри APK — `secret=`/`sessId=`/`WORKS=` → **0 совпадений**; `/home/thomas` → **0 совпадений** (пути вычищены: `--remap-path-prefix` + пост-обработка равной длины).
* **Проверка целостности ELF:** `readelf --dyn-syms` по всем трём `.so` внутри APK → **29 JNI-экспортов в каждом** (arm64-v8a / armeabi-v7a / x86_64).
* Манифест: `allowBackup=false`, `fullBackupContent=false`, `dataExtractionRules` (бэкап исключён), `usesCleartextTraffic=false` — проверено `aapt2 dump xmltree` по собранному APK.

## 9. Тесты и верификация (фактический вывод)

```
$ cargo test --release --lib
test result: ok. 76 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test --release --test audit_c1_pinning
(7 негативных тестов C1 — все PASS)

$ strings target/release/libnexxrust.so | grep -cE "secret=|sessId=|WORKS="
0
$ strings target/release/libnexxrust.so | grep -c "/home/thomas"
0
```

Живой прогон против `smp-ref` (v7.0.1.0, 127.0.0.1:443): полный цикл
PING → NEW/IDS → SEND/OK → MSG (payload дешифрован и совпал) → ACK/OK → DEL/OK — `INTEROP OK in 86 ms`.

Живые прогоны против публичной сети SimpleX — `bash rustcore/scripts/interop-all.sh smp6.simplex.im:5223`: **5/5 PASS**
(chat_flow, agent_smoke, agent_rotate, smp_cmds, invite_flow), плюс XFTP v4 roundtrip на `xftp1.simplex.im:443`.

Дополнительно подтверждено:
* fingerprint сервера из его лога (`BrZx1e…nK4=`) **==** наш keyHash (SHA-256 от CA-сертификата) → identity-часть handshake принимается сервером;
* подпись сессионного ключа независимо проверена `openssl pkeyutl -verify` и Python `cryptography` — сходится по 46-байтовому (обёрнутому) SPKI;
* HKDF цепочки сходится побитово с независимым расчётом на Python;
* публичные релеи (`smp6/smp8/smp10.simplex.im:443`) — прогон запускался, но **результат не верифицирован** (лог не подтверждён), поэтому в статус «совместимость с публичной сетью» не засчитан.

## 10. Блокеры и следующие шаги

### 10.1 Спринт аудита 2–3 — что закрыто (2026-11-15, вечер)

Внешние аудиторы (Claude + Grok) нашли C1 (MITM на аутентификации сервера), C2 (секреты в тексте ошибки), H1–H8 и M1–M11. Закрыто с приёмочными доказательствами:

| ID | Статус | Доказательство |
|---|---|---|
| C1 | ✅ закрыто | `validate_server_chain` + constant-time + 7 негативных тестов (`audit_c1_pinning.rs`) |
| C2 | ✅ закрыто | `strings .so` → 0 совпадений `secret=`/`sessId=`/`WORKS=` (и в `.so`, и в APK) |
| H1 (буфер чтения) | ✅ закрыто | `read_buf` + раздельные таймауты (poll 300 мс / команды 10 с) |
| H2 (глобальный мьютекс) | ✅ закрыто | `SESSIONS` = `HashMap<i64, Arc<Mutex<Session>>>` |
| H3 (паники FFI) | ✅ закрыто | `ffi_guard!` (`catch_unwind`) на всех JNI-экспортах, `hosts.get(0).ok_or` |
| H4 (damaged ACK) | ✅ закрыто | poll не рвётся на битом сообщении: ACK + счётчик `damaged` |
| H5 (ключи очередей) | ✅ закрыто | `protocols/queue_store.rs`: уникальный индекс `m/0'/0'/{i}'` + `m/0'/1'/{i}'`, шифрование AES-256-GCM, `DEL` при закрытии |
| H6 (BIP39) | ⚠️ частично | единая `seed_from_mnemonic` (SHA-512/2048) + NFKD, 15/18/21 слов; **осталось:** убрать произвольные KDF-параметры из JNI |
| H7 (сид через JNI) | ✅ закрыто | opaque seed handles (seedImport/seedRelease/key*ByHandle, Zeroizing-хранилище); seedHex убран из публичных JNI-сигнатур |
| H8 (Debug/логи) | ✅ закрыто | `XKey: Debug` → `<redacted>` |
| M1 (JSON) | ✅ закрыто | `serde_json` вместо ручной экранировки |
| M2 (connect) | ✅ закрыто | `connect_timeout` 15 с |
| M4 (манифест) | ✅ закрыто | `allowBackup=false`, `dataExtractionRules`, `usesCleartextTraffic=false`, `FLAG_SECURE` в android_main, password-поле seed в egui |
| M5 (пути/сборка) | ✅ закрыто | `strings .so` → 0 путей; `.so`/`.aar` вычищены из истории git (pack 10670→277 КБ), .gitignore |

### 10.2 Честно не сделано (следующий спринт)

* **ЗАКРЫТО 2026-11-16 (коммиты `80ac1ed`, `aa234f0`, `befd9c9`, `e510493`):**
  * **M3** — reconnect/backoff в chat_worker (экспоненциальный 1s→30s, сброс при успехе).
  * **M4** — `FLAG_SECURE` через `set_window_flags` в `android_main` + password-поле ввода seed в egui.
  * **M5** — `*.so`/`*.aar`/`jniLibs/` вычищены из всей истории git (filter-branch + gc, pack 10670→277 КБ), `.gitignore`.
  * **M6** — `app-rust/src/servers.rs`: конфиг релеев (host/port/CA/key_hash), CA только из конфига.
  * **M7** — `hash_seed_phrase` = PBKDF2-HMAC-SHA256(600k) с персональной солью.
  * **M8** — лимиты JNI: input ≤4M, randomHex [0,4096], AES-GCM hex ≤32M; KDF-параметры фиксированы в ядре.
  * **M9** — domain separation: `subseed(domain)`, fleet в домене "fleet".
  * **M10** — `parse_path`: hardened ≥2^31 → None (был wrap u32), нецифры → None.
  * **M11** — `jstr!` вместо silent-empty `get_str`; дубль `hex_decode` удалён.
  * **H6/H7 остатки** — фиксированные KDF-параметры; opaque seed handles (`seedImport`/`seedRelease`/`key*ByHandle`).
* **Unbuilt (не дефект, а объём):** PQ ratchet, XRCP, групповые чаты, multi-hop routing, chunk-XFTP >64 КБ.

### 10.3 Следующий шаг

Повторный вызов аудиторов на текущем HEAD (`e510493`) с `ПИСЬМО-АУДИТОРАМ.md` и `АУДИТ-КОДА-2026-11-15.md` — все находки C/H/M закрыты, в таблице аудита статусы только `✅ закрыто` по транспорту/крипто/JNI.

**Все транспортные блокеры сняты.** Два корня, оба найдены живым прогоном против эталона и закрыты регрессионными тестами:
1. крипто-слой блоков: нужен pre-слой `HSalsa20(secret, 0^16)`, tag идёт первым (`tag||ct`) — см. §3.3;
2. framing: при v≥16 после непустого authenticator обязателен байт `serviceSig` (`'0'`) — иначе сервер отвечает `ERR BLOCK`.

Полный цикл против `smp-ref` v7.0.1.0 проходит: PING → NEW/IDS → SEND → MSG (E2E payload дешифрован и совпал) → ACK → DEL (`INTEROP OK`).

**Следующий шаг — публичные релеи, ВЫПОЛНЕНО (2026-11-14): полный цикл INTEROP OK против `smp6.simplex.im:5223` (v20, PING→NEW→IDS→SEND→MSG дешифрован→ACK→DEL, 740 мс).**
- TLS-бэкенд: добавлен `connect_openssl_with_ca` (openssl crate) поверх trait `TlsIo` — rustls оставлен для локальных серверов. Публичные релеи требуют TLS1.3 + CHACHA20_POLY1305 + X25519 + **ed448 в sigalgs** (иначе alert 40); порт 443 = CDN (тишина на smp/1), SMP — порт 5223.
- Сертификаты публичных релеев v7.1+ — **Ed448** (не Ed25519): подпись сессионного ключа = 114 байт, верификация через openssl `Verifier::new_without_digest` (добавлен `ED448_SPKI_PREFIX` = `30 43 30 05 06 03 2b 65 71 03 3a 00` — BIT STRING 58 байт, не 66). Ed25519-путь сохранён для локальных v7.0.x.
- Подписанные байты сессионного ключа: перебираются канонические обёртки (`extract_signed_pubkey` возвращает candidates); для публичных v7.1+ верна `SEQUENCE(SPKI-контент)` 46 Б.
- Пиннинг CA на 5223 — цепочка с порта 5223 (`smp6-5223-chain.pem`: leaf `CN=smp6.simplex.im` + `CN=SMP server CA`), не CDN-цепочка с 443. keyHash из SMP hello = SHA-256 CA.
- Запуск: `NEXX_TLS=openssl smp_smoke smp6.simplex.im:5223 "msg" smp6-5223-chain.pem`. Диагностика: `hello_probe`, `tls_probe`.

Далее: XFTP (v3) прогон против публичного XFTP-релея — **ВЫПОЛНЕНО (2026-11-14), `XFTP INTEROP OK` на `xftp1.simplex.im:443`** (бинарник `xftp_smoke`, tokio-openssl + h2):
- TLS 1.3 без SNI (со SNI релей отдаёт web), ALPN `xftp/1`; sessionId = client TLS Finished (48B, v7.1+); keyHash = SHA-256(CA DER) из `xftp://keyHash@host`.
- Handshake v4: empty POST → serverHello (vRange 1..4) → clientHello (v + keyHash + '0') → пустой ответ.
- Команды — HTTP/2 POST, блок 16384B: `u16 len + 0x01 + u16 + auth + transmission`, transmission = `short(sessionId)+short(corrId 24B)+short(entityId)+cmd`; подпись Ed25519 над всей transmission.
- FNEW (sndKey + rcvKeys, size = размер bodyPart = 64KB packet, digest = **SHA-256** тела) → SIDS; FPUT (body = block + шифротекст) → OK; FGET (rcvId + rDhKey, подписано rcv) → FILE sDhKey cbNonce + body; FDEL → OK.
- Слои шифрования файла: внешний router→recipient = crypto_box stream = `HSalsa20(DH,0^16)` пре-слой + XSalsa20Poly1305, формат **ct||tail-tag**; внутренний (sender) = raw secretbox. Roundtrip 64KB: контент совпал.

Далее: agent-level handshake (HELLO/INV/ADR поверх SMP) — клиент-агент SimpleX — **ВЫПОЛНЕНО (2026-11-14), `AGENT INTEROP OK` на `smp6.simplex.im:5223`** (бинарник `agent_smoke`):
- Полный loopback: connect v20 → PING/PONG → NEW→IDS → SEND HELLO → SEND A_MSG → recv MSG type=H → recv MSG type=MN с **дешифрованным телом** `"NeXX agent A_MSG roundtrip!"` → ACK обоих → DEL→OK (848 мс).
- Нюанс протокола: сервер доставляет следующее `MSG` **в том же batch, что и ответ на ACK** (corrId = corrId команды) — клиент обязан принимать `MSG` как валидный ответ на ACK и складывать его в pending, а не падать.
- Команды агента кодируются как `("H",)` / `A_MSG_`-фрейм поверх SMP SEND; дешифровка E2E — crypto_box слой из §3.3, сходится с публичным релеем побитово.

**Вне протокола:** APK собирается и доставляется; UI/клавиатура — по ранее зафиксированному состоянию.

---

### Ограничения доступа
Ключи, токены и пароли в отчёте и в коде не хранятся: чувствительные значения — только в `~/.hermes/secrets/*` (600, вне git).

## 2026-11-17 (поздняя сессия): Xray/libv2ray мост доведён до зелёной сборки
- `app-rust/src/v2ray_bridge.rs`: dlopen `libgojni.so`, прямые JNI-вызовы `initCoreEnv`/`newCoreController`/`startLoop` через raw-указатели (JavaVM/AssetManager не Clone — хранятся как usize в SendSync-обёртках, конструируются на месте через `from_raw`/`from_ptr`); `socks_config()` собирает merged-конфиг (SOCKS5-in на порту runtime + outbound из Proxy-таба), `extract_assets()` распаковывает geoip/geosite из APK.
- `ui.rs`: кнопка «▶ Xray-ядро» в Proxy-табе — берёт выбранный узел, строит outbound (shadowsocks/vmess/… из `config_json`), запускает ядро.
- `lib.rs`: `android_main` передаёт `vm_as_ptr()` и `asset_manager().ptr()`.
- Тесты rustcore: **97/97 PASS** (3 прогона подряд), clippy **0 warnings** (flaky FAILED `route_allowed_reflects_kill_switch` в параллельном прогоне не воспроизводится — 3× зелёный).
- Сборка: 3 ABI × 31 JNI export, libv2ray vendored (libgojni.so ×3 + assets) — `NeXX-allabi-debug.apk` 59 358 946 Б → Telegram topic 23616, **id 31759**.
- Коммит `82a9dc0`, пуш в `PerfectFriend/NeXXChat` master.


## 2026-11-17 (продолжение): Этап 2.2 — 1-1 contact link
- `rustcore/src/protocols/contact_link.rs`: PeerLink (NEW+SUB, invite_uri, accept_invite, install_peer, send_chat, poll_chat, recv_raw + extract_snd_pub из envelope). Unit 2/2.
- `rustcore/src/bin/contact_link_smoke.rs`: **CONTACT LINK SMOKE OK** — Alice↔Bob, инвайт → connReq-обмен → чат в обе стороны через smp6.simplex.im:5223 (живой прогон).
- `app-rust/src/ui.rs`: link_worker + секция «🔗 1-1 линк» в Chats (свой инвайт с копированием, приём инвайта, handshake, чат с peer); kill-switch блокирует линк без прокси.
- Тесты rustcore **99/99**, clippy **0**. APK (3 ABI, libnexxapp+libgojni+geo assets) собран, в доставке в топик 23616.
- Коммит `b0d761f` → PerfectFriend/NeXXChat master.


## 2026-11-17 (продолжение 2): Этап 3.2 — файлы (XFTP) в библиотеке + UI
- `rustcore/src/protocols/xftp_file.rs`: XftpConn (TLS1.3+ALPN xftp/1, h2, пиннинг keyHash CA в clientHello), `upload_file` (chunked 64KB, per-chunk ed25519 snd/rcv, XSalsa20-Poly1305 inner layer, nonce=fileNonce||be64(idx)), `download_file` (FGET per chunk, two-layer decrypt, whole-file SHA512 verify), `delete_file` (FDEL), `FileDesc::encode/decode` → link `nexx://file#/…`.
- `bin/xftp_file_smoke.rs`: **XFTP FILE SMOKE OK** — 262080 B, 4 chunks, link roundtrip, SHA512 match, FDEL vs xftp1.simplex.im:443.
- UI: Tab::Files «📎 Файлы» — upload по пути → link (📋 копия), download по link → `{data_dir}/downloads/`; file_worker на своём tokio runtime.
- Cargo: tokio/h2/http/bytes переведены из host-only в общие зависимости (нужны под Android); futures остался host-only.
- Тесты **101/101**, clippy **0**, XFTP FILE SMOKE OK после чистки варнингов.
- Сборка: 3 ABI × 31 JNI (libnexxapp.so свежие закинуты в jniLibs вручную — build-android.sh кладёт только в target/), APK 157 514 992 Б → `~/apkexport/NeXX-allabi-debug.apk`, доставка в топик 23616 в фоне (slow mode ~15 мин).
- Коммит `32461f1` → PerfectFriend/NeXXChat master.


## 2026-11-17 (продолжение 3): QUSE-ротация очередей в библиотеку (Этап 4.1)
- `rustcore/src/protocols/agent_cmds.rs`: `build_qadd`/`build_quse` (wire-формат SMP agent), `agent_msg_envelope` + hash-chain, `send_agent_msg`/`ack_msg`, `rotate_queue` (NEW q2 + SUB → HELLO→QADD(q2)→QUSE(q2) на старый snd). Unit 2/2.
- `bin/agent_rotate_lib_smoke.rs`: **ROTATE LIB SMOKE OK** против smp6.simplex.im:5223 — сообщение после ротации принимается на новой очереди q2, q1 удаляется.
- Тесты **103/103**, clippy **0**.


## 2026-11-17 (продолжение 4): групповой чат UI + доставка APK
- `app-rust/src/ui.rs`: groups_ui переписан в двухпанельный вид (список групп слева, чат выбранной группы справа: история-пузыри из message_store по group_id, ввод снизу -> fan-out send_group_msg на всех member'ов, участники + добавление из контактов). aarch64 .so 16 572 480 Б, 31 JNI.
- APK 157 514 992 Б доставлен в топик 23616: **SENT id=31769** (через клон session nexx_mtproto_apk.session, т.к. основной session занят джинглами — database is locked).
- Тесты 103/103, clippy 0.


## 2026-11-17 (продолжение 5): превью медиа в 📎 Файлы
- `app-rust`: добавлен `image` crate (png/jpeg/webp/gif/bmp); после `FileEvent::Saved` для картинок — inline-превью через `ctx().load_texture` (масштаб ≤ 420px). aarch64 `.so` 17 298 968 Б, 31 JNI.
- APK с превью — сборка в фоне, доставка в топик 23616 следом.


## 2026-11-17 (продолжение 6): XFTP файлы >4MB + drag&drop
- `bin/xftp_big_smoke.rs`: **XFTP BIG (8MB) SMOKE OK** vs xftp1.simplex.im:443 — 129 chunk'ей по 64KB, upload→link roundtrip→download (SHA-256 match)→FDEL. Лимита 4MB у релея нет.
- UI 📎 Файлы: drag&drop файла в окно = сразу загрузка на XFTP.


## 2026-11-17 (продолжение 7): Этап 4.3 — SOCKS5 через Xray/libv2ray
- `rustcore/src/proxy_runtime.rs`: `ProxyRuntime.upstream` + `set_upstream()` + `socks5_connect_upstream()` (handshake no-auth, CONNECT domain/IPv4). Новый тест `upstream_chain_echo_roundtrip`: клиент→SOCKS→upstream-SOCKS→echo OK. **104/104**, clippy 0.
- `app-rust`: при старте Xray-ядра локальный SOCKS5 автоматически направляется через него (upstream 127.0.0.1:xray); «■ Стоп Xray» сбрасывает upstream. aarch64 .so 17 299 928 Б, 31 JNI.


## 2026-11-17 (продолжение 8): история 1-1 линка в message_store
- `app-rust`: входящие/исходящие сообщения 1-1 линка (PeerLink) теперь пишутся в шифрованный `messages.bin` (contact_id = link_peer) через `MessageStore::push` — история переживает рестарт.


## 2026-11-17 (продолжение 9): Этап 5 — release-сборка Android
- `app/build.gradle.kts`: release → minify+shrink+proguard (`proguard-rules.pro`: keep native, libv2ray, NativeActivity). `gradle assembleRelease` exit 0 → `app-release-unsigned.apk` 156 449 063 Б (debug 157 514 992 Б).
- Проверка после proguard: `nm -D` в lib/arm64-v8a — libnexxapp.so **31 JNI**, libgojni.so 28 — не порезаны.


## 2026-11-17 (продолжение 10): релизный APK подписан и доставлен
- `apksigner sign` (debug keystore, для стенда) → `~/apkexport/NeXX-allabi-release.apk` 156 456 114 Б, `apksigner verify` OK (SHA-256 1848346f…).
- Доставлен в топик 23616 (id в процессе отправки).
- Debug-APK с подгрузкой истории линка: **SENT id=31780**.


## 2026-11-17 (аудит-фикс K1): XFTP теперь с обязательным пиннингом
- `xftp_file.rs`: `connect(host, port, expected: &[[u8;32]], …)` — без trust-set пина отказ; пин any-of constant-time против SHA-256(DER) certs цепочки; X.509 verify best-effort; SNI убран (релей без SNI отдаёт цепочку, чей keyHash принимает). `xftp1_key_hashes()` — trust set (YR2, Root YR, E-series). **XFTP FILE SMOKE OK с пином** (262080B, 4 chunks, roundtrip, FDEL).


## 2026-11-17 (аудит-фиксы K1+V1)
- **K1 закрыт:** XFTP `connect` требует trust-set keyHash (ct_eq any-of, без пина — отказ) + X.509 best-effort; SNI убран (релей без SNI отдаёт принимаемую цепочку). XFTP FILE SMOKE OK с пином; unit 104/104, clippy 0.
- **V1 закрыт:** все 25 JNI-экспортов `jni_api.rs` обёрнуты в `ffi_guard!` (catch_unwind → JSON-ошибка вместо abort). Теперь 31/31 экспортов под защитой (6 в jni_smp + 25 в jni_api).


## 2026-11-17 (аудит-фикс S2)
- `proxy_runtime.rs`: лимит 256 одновременных CONNECT (счётчик, лишние закрываются сразу) + `connect_timeout(15s)` и для direct, и для upstream (resolve_one с таймаутом, без блокирующего DNS). Тесты proxy_runtime 4/4, всего 104/104, clippy 0.


## 2026-11-17 (аудит-фиксы N4/N5/S1)
- **S1:** `.so` убран из git-трекинга (генерятся сборкой), `LIBV2RAY.sha256` зафиксирован.
- **N4:** `contact_link.rs::srv_secret` вместо unwrap → Result/Option, паники на malformed-ответе нет. 104/104, clippy 0.
- **N5:** лимит файла 512 МБ перед чтением в память в file_worker (UI).
