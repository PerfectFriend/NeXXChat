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

* `~/apkexport/NeXX-rust-debug.apk` — ~24 МБ, три ABI внутри (проверено `unzip -l`).
* Имя по правилу владельца: `<Проект>-<abi>-debug.apk`.
* Доставка в Telegram-топик `-1004431090317:23616`: Bot API режет 50 МБ → для крупных файлов MTProto (`~/Projects/TGSend/tg_send_file.py`, venv `~/.hermes/installs/tg-mtproto`, `api_id/api_hash/phone` в `~/.hermes/secrets/tg_mtproto.env` — значения не хранятся вне секретов).

## 9. Тесты и верификация (фактический вывод)

```
$ cargo test --release
test result: ok. 68 passed; 0 failed   (вкл. KAT crypto_box и serviceSig layout)
```

Живой прогон против `smp-ref` (v7.0.1.0, 127.0.0.1:443): полный цикл
PING → NEW/IDS → SEND/OK → MSG (payload дешифрован и совпал) → ACK/OK → DEL/OK — `INTEROP OK in 86 ms`.

Дополнительно подтверждено:
* fingerprint сервера из его лога (`BrZx1e…nK4=`) **==** наш keyHash (SHA-256 от CA-сертификата) → identity-часть handshake принимается сервером;
* подпись сессионного ключа независимо проверена `openssl pkeyutl -verify` и Python `cryptography` — сходится по 46-байтовому (обёрнутому) SPKI;
* HKDF цепочки сходится побитово с независимым расчётом на Python;
* публичные релеи (`smp6/smp8/smp10.simplex.im:443`) — прогон запускался, но **результат не верифицирован** (лог не подтверждён), поэтому в статус «совместимость с публичной сетью» не засчитан.

## 10. Блокеры и следующие шаги

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
