//! JNI-обёртки: Java_com_nexx_rustcore_RustCore_* — мост в Kotlin.
//! Все функции возвращают String (JSON или plain), ошибки — в поле "ok":false / "error".

use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;

use crate::{bip39, crypto, keytree, proxy_parse};

/// Аудит M8: верхние границы входов через JNI — защита от OOM/DoS
/// (гигантский nBytes в randomHex, неограниченные строки/KDF-параметры).
pub const MAX_INPUT_CHARS: usize = 4 << 20; // 4M chars на одну входную строку
pub const MAX_RANDOM_BYTES: jni::sys::jint = 4096;
pub const MAX_DATA_HEX_CHARS: usize = 32 << 20; // hex-вход AES-GCM (16 МБ данных)
/// Аудит H6: KDF-параметры фиксированы в коде и НЕ приходят через JNI.
pub const PBKDF2_ITERATIONS: u32 = 600_000;
pub const PBKDF2_DKLEN: usize = 32;
pub const BIP39_LEGACY_ITERATIONS: u32 = 2048;
pub const BIP39_LEGACY_DKLEN: usize = 64;

fn to_jstring(env: &mut JNIEnv, s: String) -> jstring {
    match env.new_string(s) {
        Ok(j) => j.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn err_json(e: &str) -> String {
    format!(
        r#"{{"ok":false,"error":{}}}"#,
        serde_json::to_string(e).unwrap_or_else(|_| "\"err\"".into())
    )
}

/// Аудит M11: ошибка JNI get_string НЕ должна становиться silent empty string —
/// она уходит наружу как JSON-ошибка. Также режем слишком длинные входы (M8).
fn get_str(env: &mut JNIEnv, s: JString) -> Result<String, String> {
    let out: String = env
        .get_string(&s)
        .map(|j| j.into())
        .map_err(|e| format!("JNI get_string: {e}"))?;
    if out.len() > MAX_INPUT_CHARS {
        return Err(format!(
            "input too large: {} chars (max {MAX_INPUT_CHARS})",
            out.len()
        ));
    }
    Ok(out)
}

/// jstr! — для функций, возвращающих jstring: ошибка уезжает как JSON-ошибка.
macro_rules! jstr {
    ($env:expr, $s:expr) => {
        match get_str($env, $s) {
            Ok(v) => v,
            Err(e) => return to_jstring($env, err_json(&e)),
        }
    };
}

/// String parseProxyConfig(String input, String remarks) — JSON-результат парсера.
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_parseProxyConfig(
    mut env: JNIEnv,
    _class: JClass,
    input: JString,
    remarks: JString,
) -> jstring {
    let input = jstr!(&mut env, input);
    let remarks = jstr!(&mut env, remarks);
    to_jstring(&mut env, proxy_parse::parse_proxy_config(&input, &remarks))
}

/// String sha256Hex(String data)
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_sha256Hex(
    mut env: JNIEnv,
    _class: JClass,
    data: JString,
) -> jstring {
    let s = jstr!(&mut env, data);
    to_jstring(&mut env, crypto::sha256_hex(s.as_bytes()))
}

/// String pbkdf2Hex(String password, String saltHex)
/// Аудит H6: iterations/dkLen более НЕ принимаются из JNI — фиксированы константами.
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_pbkdf2Hex(
    mut env: JNIEnv,
    _class: JClass,
    password: JString,
    salt_hex: JString,
) -> jstring {
    let pw = jstr!(&mut env, password);
    let salt_hex = jstr!(&mut env, salt_hex);
    let salt = match crypto::hex_decode(&salt_hex) {
        Some(s) if !s.is_empty() => s,
        _ => return to_jstring(&mut env, err_json("saltHex: bad or empty hex")),
    };
    let dk = crypto::pbkdf2_hmac_sha256(pw.as_bytes(), &salt, PBKDF2_ITERATIONS, PBKDF2_DKLEN);
    to_jstring(&mut env, crypto::hex_encode(&dk))
}

/// String aesGcmEncryptHex(String keyHex, String dataHex) → hex(iv+ct+tag) или {"error":...}
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_aesGcmEncryptHex(
    mut env: JNIEnv,
    _class: JClass,
    key_hex: JString,
    data_hex: JString,
) -> jstring {
    let key_hex = jstr!(&mut env, key_hex);
    let data_hex = jstr!(&mut env, data_hex);
    if data_hex.len() > MAX_DATA_HEX_CHARS {
        return to_jstring(&mut env, err_json("data too large for AES-GCM input"));
    }
    let key = match crypto::hex_decode(&key_hex) {
        Some(k) if k.len() == 32 => k,
        _ => return to_jstring(&mut env, r#"{"error":"key must be 32 bytes hex"}"#.into()),
    };
    let pt = match crypto::hex_decode(&data_hex) {
        Some(d) => d,
        None => return to_jstring(&mut env, r#"{"error":"bad hex data"}"#.into()),
    };
    match crypto::aes256_gcm_encrypt(&key, &pt) {
        Ok(ct) => to_jstring(&mut env, crypto::hex_encode(&ct)),
        Err(e) => to_jstring(&mut env, format!(r#"{{"error":{}}}"#, serde_json::to_string(&e).unwrap())),
    }
}

/// String aesGcmDecryptHex(String keyHex, String dataHex) → hex(plaintext) или {"error":...}
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_aesGcmDecryptHex(
    mut env: JNIEnv,
    _class: JClass,
    key_hex: JString,
    data_hex: JString,
) -> jstring {
    let key_hex = jstr!(&mut env, key_hex);
    let data_hex = jstr!(&mut env, data_hex);
    let key = match crypto::hex_decode(&key_hex) {
        Some(k) if k.len() == 32 => k,
        _ => return to_jstring(&mut env, r#"{"error":"key must be 32 bytes hex"}"#.into()),
    };
    let data = match crypto::hex_decode(&data_hex) {
        Some(d) => d,
        None => return to_jstring(&mut env, r#"{"error":"bad hex data"}"#.into()),
    };
    match crypto::aes256_gcm_decrypt(&key, &data) {
        Ok(pt) => to_jstring(&mut env, crypto::hex_encode(&pt)),
        Err(e) => to_jstring(&mut env, format!(r#"{{"error":{}}}"#, serde_json::to_string(&e).unwrap())),
    }
}

/// String randomHex(int nBytes) — nBytes кlampeруется в [0, MAX_RANDOM_BYTES] (аудит M8: без upper bound → OOM).
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_randomHex(
    mut env: JNIEnv,
    _class: JClass,
    n: jni::sys::jint,
) -> jstring {
    let bytes = crypto::random_bytes(n.clamp(0, MAX_RANDOM_BYTES) as usize);
    to_jstring(&mut env, crypto::hex_encode(&bytes))
}

/// String bip39Mnemonic(int entropyBytes) → JSON {"ok":true,"words":[...]}
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_bip39Mnemonic(
    mut env: JNIEnv,
    _class: JClass,
    entropy_bytes: jni::sys::jint,
) -> jstring {
    let n = entropy_bytes as usize;
    if n != 16 && n != 32 {
        return to_jstring(&mut env, r#"{"ok":false,"error":"entropy must be 16 or 32"}"#.into());
    }
    let ent = crypto::random_bytes(n);
    match bip39::mnemonic_from_entropy(&ent) {
        Ok(words) => to_jstring(&mut env, serde_json::json!({"ok":true,"words":words}).to_string()),
        Err(e) => to_jstring(&mut env, format!(r#"{{"ok":false,"error":{}}}"#, serde_json::to_string(&e).unwrap())),
    }
}

/// boolean bip39Validate(String wordsSpaceSeparated)
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_bip39Validate(
    mut env: JNIEnv,
    _class: JClass,
    words: JString,
) -> jni::sys::jboolean {
    let s = match get_str(&mut env, words) {
        Ok(v) => v,
        Err(_) => return 0, // ошибка чтения → false, не silent-empty
    };
    let w: Vec<String> = s.split_whitespace().map(|x| x.to_string()).collect();
    if bip39::validate_mnemonic(&w) {
        1
    } else {
        0
    }
}

/// String bip39SeedHex(String mnemonic, String passphrase)
/// Legacy-вариант (PBKDF2-HMAC-SHA256); параметры фиксированы (аудит H6).
/// Для переносимых кошельков — bip39SeedStandardHex (SHA512/2048).
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_bip39SeedHex(
    mut env: JNIEnv,
    _class: JClass,
    mnemonic: JString,
    passphrase: JString,
) -> jstring {
    let m = jstr!(&mut env, mnemonic);
    let p = jstr!(&mut env, passphrase);
    let salt = format!("mnemonic{p}");
    let dk = crypto::pbkdf2_hmac_sha256(
        m.as_bytes(),
        salt.as_bytes(),
        BIP39_LEGACY_ITERATIONS,
        BIP39_LEGACY_DKLEN,
    );
    to_jstring(&mut env, crypto::hex_encode(&dk))
}

/// String bip39SeedStandardHex(String mnemonic, String passphrase)
/// **Стандартный** BIP39-сид (PBKDF2-HMAC-SHA512) — переносимый между кошельками.
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_bip39SeedStandardHex(
    mut env: JNIEnv,
    _class: JClass,
    mnemonic: JString,
    passphrase: JString,
) -> jstring {
    let m = jstr!(&mut env, mnemonic);
    let p = jstr!(&mut env, passphrase);
    let seed = bip39::seed_from_mnemonic_standard(&m, &p);
    to_jstring(&mut env, crypto::hex_encode(&seed))
}

/// String version() — диагностика: версия библиотеки.
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_version(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    to_jstring(&mut env, format!("nexxrust {}", env!("CARGO_PKG_VERSION")))
}

// ---------- Opaque seed handles (аудит H7: сид не должен ходить через JNI строкой) ----------

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{LazyLock, Mutex};
use zeroize::Zeroizing;

static SEED_STORE: LazyLock<Mutex<HashMap<i64, Zeroizing<Vec<u8>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_SEED_HANDLE: AtomicI64 = AtomicI64::new(1);

fn seed_store_insert(seed: Vec<u8>) -> i64 {
    let h = NEXT_SEED_HANDLE.fetch_add(1, Ordering::Relaxed);
    SEED_STORE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(h, Zeroizing::new(seed));
    h
}

fn seed_store_get(handle: i64) -> Option<Vec<u8>> {
    SEED_STORE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&handle)
        .map(|z| (**z).clone())
}

fn seed_store_remove(handle: i64) -> bool {
    SEED_STORE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&handle)
        .is_some()
}

/// long seedImport(String seedHex) → handle (>0) или -1 при ошибке.
/// Сид попадает в процесс один раз и далее живёт только под handle (Zeroize при release).
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_seedImport(
    mut env: JNIEnv,
    _class: JClass,
    seed_hex: JString,
) -> jni::sys::jlong {
    let s = match get_str(&mut env, seed_hex) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    match crypto::hex_decode(&s) {
        Some(seed) if (16..=128).contains(&seed.len()) => seed_store_insert(seed) as jni::sys::jlong,
        _ => -1,
    }
}

/// boolean seedRelease(long handle) — удаляет сид из памяти (ZeroizeOnDrop у Zeroizing).
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_seedRelease(
    _env: JNIEnv,
    _class: JClass,
    handle: jni::sys::jlong,
) -> jni::sys::jboolean {
    if seed_store_remove(handle) { 1 } else { 0 }
}

fn seed_or_err(env: &mut JNIEnv, handle: jni::sys::jlong) -> Result<Vec<u8>, jstring> {
    match seed_store_get(handle) {
        Some(s) => Ok(s),
        None => Err(to_jstring(env, err_json("unknown seed handle"))),
    }
}

/// String keyDeriveLabelByHandle(long handle, String label) → 32-байтный ключ (hex).
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_keyDeriveLabelByHandle(
    mut env: JNIEnv,
    _class: JClass,
    handle: jni::sys::jlong,
    label: JString,
) -> jstring {
    let label = jstr!(&mut env, label);
    let seed = match seed_or_err(&mut env, handle) {
        Ok(s) => s,
        Err(j) => return j,
    };
    let key = keytree::derive_label(&seed, &label);
    to_jstring(&mut env, crypto::hex_encode(&key))
}

/// String keyWalletByHandle(long handle, String chain, int index) → JSON.
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_keyWalletByHandle(
    mut env: JNIEnv,
    _class: JClass,
    handle: jni::sys::jlong,
    chain: JString,
    index: jni::sys::jint,
) -> jstring {
    let chain = jstr!(&mut env, chain);
    let seed = match seed_or_err(&mut env, handle) {
        Ok(s) => s,
        Err(j) => return j,
    };
    let idx = index.max(0) as u32;
    let (path, address) = match chain.as_str() {
        "eth" => {
            let p = format!("m/44'/60'/0'/0/{idx}");
            match keytree::derive_path_secp256k1(&seed, &p) {
                Some(k) => (p, keytree::eth_address(&k.private)),
                None => (p, None),
            }
        }
        "btc" => {
            let p = format!("m/84'/0'/0'/0/{idx}");
            match keytree::derive_path_secp256k1(&seed, &p) {
                Some(k) => (p, keytree::btc_bech32_address(&k.private)),
                None => (p, None),
            }
        }
        "sol" => {
            let p = format!("m/44'/501'/0'/0'/{idx}'");
            let addr = keytree::sol_address(&seed, &p);
            (p, addr)
        }
        "smp" => {
            let p = format!("m/0'/0'/{idx}'");
            match keytree::derive_path_ed25519(&seed, &p) {
                Some(k) => {
                    let sk = ed25519_dalek::SigningKey::from_bytes(&k.private);
                    let pub_b64 = {
                        use base64::Engine as _;
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(sk.verifying_key().to_bytes())
                    };
                    (p, Some(format!("ed25519:{pub_b64}")))
                }
                None => (p, None),
            }
        }
        _ => (String::new(), None),
    };
    let json = serde_json::json!({
        "ok": address.is_some(),
        "chain": chain,
        "index": idx,
        "path": path,
        "address": address,
    });
    to_jstring(&mut env, json.to_string())
}

/// String keyFleetPlanByHandle(long handle, int nodeCount) → JSON.
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_keyFleetPlanByHandle(
    mut env: JNIEnv,
    _class: JClass,
    handle: jni::sys::jlong,
    node_count: jni::sys::jint,
) -> jstring {
    let seed = match seed_or_err(&mut env, handle) {
        Ok(s) => s,
        Err(j) => return j,
    };
    let count = node_count.clamp(0, 1000) as u32;
    let plan = keytree::plan_fleet(&seed, count);
    let nodes: Vec<serde_json::Value> = plan
        .iter()
        .map(|n| {
            serde_json::json!({
                "index": n.index,
                "id": n.id,
                "identityKey": n.identity_key,
                "storageKey": n.storage_key,
                "chatKey": n.chat_key,
            })
        })
        .collect();
    let json = serde_json::json!({"ok": true, "nodes": nodes});
    to_jstring(&mut env, json.to_string())
}

// ---------- Control plane (фаза 4) ----------

/// long portAllocAcquire(String lockFile, int start, int end) → порт или -1
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_portAllocAcquire(
    mut env: JNIEnv,
    _class: JClass,
    lock_file: JString,
    start: jni::sys::jint,
    end: jni::sys::jint,
) -> jni::sys::jlong {
    let lf = match get_str(&mut env, lock_file) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    crate::control::port_alloc_acquire(&lf, start.max(1) as u16, end.min(65535) as u16) as jni::sys::jlong
}

/// boolean portAllocRelease(String lockFile, int port)
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_portAllocRelease(
    mut env: JNIEnv,
    _class: JClass,
    lock_file: JString,
    port: jni::sys::jint,
) -> jni::sys::jboolean {
    let lf = match get_str(&mut env, lock_file) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if crate::control::port_alloc_release(&lf, port.max(0) as u16) { 1 } else { 0 }
}

/// String healthCheckTcp(String host, int port, int timeoutMs) → JSON
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_healthCheckTcp(
    mut env: JNIEnv,
    _class: JClass,
    host: JString,
    port: jni::sys::jint,
    timeout_ms: jni::sys::jint,
) -> jstring {
    let h = jstr!(&mut env, host);
    to_jstring(&mut env, crate::control::health_check_tcp(&h, port.max(1) as u16, timeout_ms.max(1) as u32).to_string())
}

/// String healthCheckSocks5(String proxyHost, int proxyPort, String targetHost, int targetPort, int timeoutMs) → JSON
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_healthCheckSocks5(
    mut env: JNIEnv,
    _class: JClass,
    proxy_host: JString,
    proxy_port: jni::sys::jint,
    target_host: JString,
    target_port: jni::sys::jint,
    timeout_ms: jni::sys::jint,
) -> jstring {
    let ph = jstr!(&mut env, proxy_host);
    let th = jstr!(&mut env, target_host);
    to_jstring(&mut env, crate::control::health_check_socks5(
        &ph,
        proxy_port.max(1) as u16,
        &th,
        target_port.max(1) as u16,
        timeout_ms.max(1) as u32,
    ).to_string())
}

/// String buildXrayMergedConfig(String userConfig, int localPort, String protocolHint) → JSON {"ok","config"}
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_buildXrayMergedConfig(
    mut env: JNIEnv,
    _class: JClass,
    user_config: JString,
    local_port: jni::sys::jint,
    protocol_hint: JString,
) -> jstring {
    let uc = jstr!(&mut env, user_config);
    let ph = jstr!(&mut env, protocol_hint);
    to_jstring(&mut env, crate::control::build_xray_merged_config(&uc, local_port.max(1) as u16, &ph).to_string())
}

/// String torControlBootstrapProgress(String host, int port, int timeoutMs) → JSON {"ok","progress"}
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_torControlBootstrapProgress(
    mut env: JNIEnv,
    _class: JClass,
    host: JString,
    port: jni::sys::jint,
    timeout_ms: jni::sys::jint,
) -> jstring {
    let h = jstr!(&mut env, host);
    to_jstring(&mut env, crate::control::tor_control_bootstrap_progress(&h, port.max(1) as u16, timeout_ms.max(1) as u32).to_string())
}

/// String routeDecision(boolean proxyUp, boolean torUp, boolean targetOnion, boolean onlyTor, boolean allowNonTor)
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_routeDecision(
    mut env: JNIEnv,
    _class: JClass,
    proxy_up: jni::sys::jboolean,
    tor_up: jni::sys::jboolean,
    target_onion: jni::sys::jboolean,
    only_tor: jni::sys::jboolean,
    allow_non_tor: jni::sys::jboolean,
) -> jstring {
    to_jstring(&mut env, crate::control::route_decision(
        proxy_up != 0,
        tor_up != 0,
        target_onion != 0,
        only_tor != 0,
        allow_non_tor != 0,
    ).to_string())
}

/// String buildSsLink(String method, String password, String host, int port, String tag)
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_buildSsLink(
    mut env: JNIEnv,
    _class: JClass,
    method: JString,
    password: JString,
    host: JString,
    port: jni::sys::jint,
    tag: JString,
) -> jstring {
    let m = jstr!(&mut env, method);
    let p = jstr!(&mut env, password);
    let h = jstr!(&mut env, host);
    let t = jstr!(&mut env, tag);
    to_jstring(&mut env, crate::control::build_ss_link(&m, &p, &h, port.max(1) as u16, &t))
}

/// String parseSsLink(String link) → JSON
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_parseSsLink(
    mut env: JNIEnv,
    _class: JClass,
    link: JString,
) -> jstring {
    let l = jstr!(&mut env, link);
    to_jstring(&mut env, crate::control::parse_ss_link(&l).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_handle_roundtrip_and_release() {
        let h = seed_store_insert(vec![0xAB; 64]);
        assert!(h > 0);
        assert_eq!(seed_store_get(h), Some(vec![0xAB; 64]));
        assert!(seed_store_remove(h));
        assert!(seed_store_get(h).is_none());
        assert!(!seed_store_remove(h)); // повторный release → false
    }

    #[test]
    fn seed_handles_are_unique_and_isolated() {
        let a = seed_store_insert(vec![1; 32]);
        let b = seed_store_insert(vec![2; 32]);
        assert_ne!(a, b);
        assert_eq!(seed_store_get(a), Some(vec![1; 32]));
        assert_eq!(seed_store_get(b), Some(vec![2; 32]));
        seed_store_remove(a);
        seed_store_remove(b);
    }

    #[test]
    fn random_hex_upper_bound() {
        assert_eq!(MAX_RANDOM_BYTES, 4096);
        assert_eq!(i32::MAX.clamp(0, MAX_RANDOM_BYTES), 4096);
        assert_eq!((-5).clamp(0, MAX_RANDOM_BYTES), 0);
    }
}
