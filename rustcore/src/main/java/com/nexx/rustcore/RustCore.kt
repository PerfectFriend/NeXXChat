package com.nexx.rustcore

/**
 * JNI-мост к libnexxrust.so (Rust-ядро форка NeXX).
 * Все методы — нативные; вызывать только после [load] == true.
 */
object RustCore {
    @Volatile
    private var loaded = false

    @JvmStatic
    fun load(): Boolean {
        if (loaded) return true
        loaded = try {
            System.loadLibrary("nexxrust")
            true
        } catch (t: Throwable) {
            false
        }
        return loaded
    }

    @JvmStatic
    external fun version(): String

    /** JSON: {"ok":true,"kind":...,"id":...,"remarks":...,"config_json":...,"protocol":...} */
    @JvmStatic
    external fun parseProxyConfig(input: String, remarks: String): String

    @JvmStatic
    external fun sha256Hex(data: String): String

    /** PBKDF2-HMAC-SHA256 → hex ключа. Параметры фиксированы в ядре (аудит H6), из JNI не приходят. */
    @JvmStatic
    external fun pbkdf2Hex(password: String, saltHex: String): String

    /** AES-256-GCM: keyHex(32 байта) + dataHex → hex(iv12 + ct + tag16) или {"error":...} */
    @JvmStatic
    external fun aesGcmEncryptHex(keyHex: String, dataHex: String): String

    /** AES-256-GCM: keyHex + hex(iv+ct+tag) → hex(plaintext) или {"error":...} */
    @JvmStatic
    external fun aesGcmDecryptHex(keyHex: String, dataHex: String): String

    @JvmStatic
    external fun randomHex(nBytes: Int): String

    /** JSON {"ok":true,"words":[...]} для 16/32 байт энтропии */
    @JvmStatic
    external fun bip39Mnemonic(entropyBytes: Int): String

    @JvmStatic
    external fun bip39Validate(wordsSpaceSeparated: String): Boolean

    /** Legacy BIP39-вариант сидa (PBKDF2-HMAC-SHA256, фиксированные параметры, аудит H6). Для кошельков — bip39SeedStandardHex. */
    @JvmStatic
    external fun bip39SeedHex(mnemonic: String, passphrase: String): String

    // ---- Control plane (фаза 4) ----

    /** Порт из диапазона с flock + bind-проверкой; -1 если нет свободных. */
    @JvmStatic
    external fun portAllocAcquire(lockFile: String, start: Int, end: Int): Long

    @JvmStatic
    external fun portAllocRelease(lockFile: String, port: Int): Boolean

    /** JSON {"ok","latency_ms"/"error"} */
    @JvmStatic
    external fun healthCheckTcp(host: String, port: Int, timeoutMs: Int): String

    /** End-to-end через SOCKS5: handshake + CONNECT до target. JSON {"ok","latency_ms"/"error"} */
    @JvmStatic
    external fun healthCheckSocks5(proxyHost: String, proxyPort: Int, targetHost: String, targetPort: Int, timeoutMs: Int): String

    /** JSON {"ok","config"} — socks-inbound + outbounds merge. */
    @JvmStatic
    external fun buildXrayMergedConfig(userConfig: String, localPort: Int, protocolHint: String): String

    /** Tor control port: JSON {"ok","progress":0-100,"summary"?} */
    @JvmStatic
    external fun torControlBootstrapProgress(host: String, port: Int, timeoutMs: Int): String

    /** "direct" | "proxy" | "tor" | "block" */
    @JvmStatic
    external fun routeDecision(proxyUp: Boolean, torUp: Boolean, targetOnion: Boolean, onlyTor: Boolean, allowNonTor: Boolean): String

    @JvmStatic
    external fun buildSsLink(method: String, password: String, host: String, port: Int, tag: String): String

    /** JSON {"ok","method","password","host","port","tag"} */
    @JvmStatic
    external fun parseSsLink(link: String): String

    /** Стандартный BIP39-сид (PBKDF2-HMAC-SHA512), hex. */
    @JvmStatic
    external fun bip39SeedStandardHex(mnemonic: String, passphrase: String): String

    // ---- Opaque seed handles (аудит H7: сид не ходит через JNI строкой на каждый вызов) ----

    /** long seedImport(seedHex) → handle > 0 (сид в Zeroize-хранилище) или -1 при ошибке. */
    @JvmStatic
    external fun seedImport(seedHex: String): Long

    /** boolean seedRelease(handle) — удаляет и затирает сид. */
    @JvmStatic
    external fun seedRelease(handle: Long): Boolean

    /** 32-байтный ключ по метке: derive_label(seed[handle], label), hex. */
    @JvmStatic
    external fun keyDeriveLabelByHandle(handle: Long, label: String): String

    /** JSON {"ok","chain","index","path","address"} — адрес кошелька по handle сида. */
    @JvmStatic
    external fun keyWalletByHandle(handle: Long, chain: String, index: Int): String

    /** JSON {"ok","nodes":[...]} — план флота по handle сида. */
    @JvmStatic
    external fun keyFleetPlanByHandle(handle: Long, nodeCount: Int): String

    /**
     * JSON {"ok","session","version"} — TLS-подключение к SMP-релею.
     * caPem и keyHashHex (SHA-256 от CA, hex) ОБЯЗАТЕЛЬНЫ: сервер идентифицируется
     * отпечатком своего CA (модель SimpleX), а не именем хоста (аудит C1).
     * authSkHex/dhSkHex — 32-байтные ключи очереди (hex) из keytree.
     */
    @JvmStatic
    external fun smpConnect(host: String, port: Int, caPem: String, keyHashHex: String, authSkHex: String, dhSkHex: String): String

    /** JSON {"ok","rcvId","sndId"} (hex) — создать очередь на сессии. */
    @JvmStatic
    external fun smpNewQueue(session: Long): String

    /** JSON {"ok"} — отправить e2e-шифрованный текст в свою очередь. */
    @JvmStatic
    external fun smpSendText(session: Long, text: String): String

    /** JSON {"ok","messages":[{"msgId","body","hex"}]} — неблокирующий опрос входящих. */
    @JvmStatic
    external fun smpPoll(session: Long): String

    /** JSON {"ok"} — ACK сообщения по msgId (hex). */
    @JvmStatic
    external fun smpAck(session: Long, msgIdHex: String): String

    /** JSON {"ok"} — закрыть сессию. */
    @JvmStatic
    external fun smpClose(session: Long): String
}
