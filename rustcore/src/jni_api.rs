//! JNI-обёртки: Java_com_nexx_rustcore_RustCore_* — мост в Kotlin.
//! Все функции возвращают String (JSON или plain), ошибки — в поле "ok":false / "error".

use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;

use crate::{bip39, crypto, keytree, proxy_parse};

fn to_jstring(env: &mut JNIEnv, s: String) -> jstring {
    match env.new_string(s) {
        Ok(j) => j.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn get_str(env: &mut JNIEnv, s: JString) -> String {
    env.get_string(&s).map(|j| j.into()).unwrap_or_default()
}

/// String parseProxyConfig(String input, String remarks) — JSON-результат парсера.
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_parseProxyConfig(
    mut env: JNIEnv,
    _class: JClass,
    input: JString,
    remarks: JString,
) -> jstring {
    let input = get_str(&mut env, input);
    let remarks = get_str(&mut env, remarks);
    to_jstring(&mut env, proxy_parse::parse_proxy_config(&input, &remarks))
}

/// String sha256Hex(String data)
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_sha256Hex(
    mut env: JNIEnv,
    _class: JClass,
    data: JString,
) -> jstring {
    let s = get_str(&mut env, data);
    to_jstring(&mut env, crypto::sha256_hex(s.as_bytes()))
}

/// String pbkdf2Hex(String password, String saltHex, int iterations, int dkLen)
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_pbkdf2Hex(
    mut env: JNIEnv,
    _class: JClass,
    password: JString,
    salt_hex: JString,
    iterations: jni::sys::jint,
    dk_len: jni::sys::jint,
) -> jstring {
    let pw = get_str(&mut env, password);
    let salt_hex = get_str(&mut env, salt_hex);
    let salt = hex_decode(&salt_hex).unwrap_or_default();
    let dk = crypto::pbkdf2_hmac_sha256(pw.as_bytes(), &salt, iterations.max(1) as u32, dk_len.max(1) as usize);
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
    let key_hex = get_str(&mut env, key_hex);
    let data_hex = get_str(&mut env, data_hex);
    let key = match hex_decode(&key_hex) {
        Some(k) if k.len() == 32 => k,
        _ => return to_jstring(&mut env, r#"{"error":"key must be 32 bytes hex"}"#.into()),
    };
    let pt = match hex_decode(&data_hex) {
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
    let key_hex = get_str(&mut env, key_hex);
    let data_hex = get_str(&mut env, data_hex);
    let key = match hex_decode(&key_hex) {
        Some(k) if k.len() == 32 => k,
        _ => return to_jstring(&mut env, r#"{"error":"key must be 32 bytes hex"}"#.into()),
    };
    let data = match hex_decode(&data_hex) {
        Some(d) => d,
        None => return to_jstring(&mut env, r#"{"error":"bad hex data"}"#.into()),
    };
    match crypto::aes256_gcm_decrypt(&key, &data) {
        Ok(pt) => to_jstring(&mut env, crypto::hex_encode(&pt)),
        Err(e) => to_jstring(&mut env, format!(r#"{{"error":{}}}"#, serde_json::to_string(&e).unwrap())),
    }
}

/// String randomHex(int nBytes)
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_randomHex(
    mut env: JNIEnv,
    _class: JClass,
    n: jni::sys::jint,
) -> jstring {
    let bytes = crypto::random_bytes(n.max(0) as usize);
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
    let s = get_str(&mut env, words);
    let w: Vec<String> = s.split_whitespace().map(|x| x.to_string()).collect();
    if bip39::validate_mnemonic(&w) {
        1
    } else {
        0
    }
}

/// String bip39SeedHex(String mnemonic, String passphrase, int iterations, int dkLen)
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_bip39SeedHex(
    mut env: JNIEnv,
    _class: JClass,
    mnemonic: JString,
    passphrase: JString,
    iterations: jni::sys::jint,
    dk_len: jni::sys::jint,
) -> jstring {
    let m = get_str(&mut env, mnemonic);
    let p = get_str(&mut env, passphrase);
    let salt = format!("mnemonic{p}");
    let dk = crypto::pbkdf2_hmac_sha256(m.as_bytes(), salt.as_bytes(), iterations.max(1) as u32, dk_len.max(1) as usize);
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
    let m = get_str(&mut env, mnemonic);
    let p = get_str(&mut env, passphrase);
    let seed = bip39::seed_from_mnemonic_standard(&m, &p);
    to_jstring(&mut env, crypto::hex_encode(&seed))
}

/// String keyDeriveLabel(String seedHex, String label) → 32-байтный ключ (hex).
/// Универсальный источник ключей: одна метка — один ключ, разные метки независимы.
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_keyDeriveLabel(
    mut env: JNIEnv,
    _class: JClass,
    seed_hex: JString,
    label: JString,
) -> jstring {
    let seed_hex = get_str(&mut env, seed_hex);
    let label = get_str(&mut env, label);
    let seed = match crypto::hex_decode(&seed_hex) {
        Some(s) => s,
        None => return to_jstring(&mut env, String::new()),
    };
    let key = keytree::derive_label(&seed, &label);
    to_jstring(&mut env, crypto::hex_encode(&key))
}

/// String keyWallet(String seedHex, String chain, int index) → JSON.
/// chain: "eth" | "btc" | "sol" | "smp".
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_keyWallet(
    mut env: JNIEnv,
    _class: JClass,
    seed_hex: JString,
    chain: JString,
    index: jni::sys::jint,
) -> jstring {
    let seed_hex = get_str(&mut env, seed_hex);
    let chain = get_str(&mut env, chain);
    let seed = match crypto::hex_decode(&seed_hex) {
        Some(s) => s,
        None => return to_jstring(&mut env, r#"{"ok":false,"error":"bad seed hex"}"#.into()),
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
            // SIMPLEX-идентичность: Ed25519 по SLIP-0010
            let p = format!("m/0'/0'/{idx}'");
            match keytree::derive_path_ed25519(&seed, &p) {
                Some(k) => {
                    let sk = ed25519_dalek::SigningKey::from_bytes(&k.private);
                    let pub_b64 = {
                        use base64::Engine as _;
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes())
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

/// String keyFleetPlan(String seedHex, int nodeCount) → JSON.
/// План флота нод из одного мастер-сида: id, ключи идентичности/хранилища/чата.
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_keyFleetPlan(
    mut env: JNIEnv,
    _class: JClass,
    seed_hex: JString,
    node_count: jni::sys::jint,
) -> jstring {
    let seed_hex = get_str(&mut env, seed_hex);
    let seed = match crypto::hex_decode(&seed_hex) {
        Some(s) => s,
        None => return to_jstring(&mut env, r#"{"ok":false,"error":"bad seed hex"}"#.into()),
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

/// String version() — диагностика: версия библиотеки.
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_version(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    to_jstring(&mut env, format!("nexxrust {}", env!("CARGO_PKG_VERSION")))
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    (0..b.len())
        .step_by(2)
        .map(|i| {
            let hi = (b[i] as char).to_digit(16)?;
            let lo = (b[i + 1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
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
    let lf = get_str(&mut env, lock_file);
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
    let lf = get_str(&mut env, lock_file);
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
    let h = get_str(&mut env, host);
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
    let ph = get_str(&mut env, proxy_host);
    let th = get_str(&mut env, target_host);
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
    let uc = get_str(&mut env, user_config);
    let ph = get_str(&mut env, protocol_hint);
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
    let h = get_str(&mut env, host);
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
    let m = get_str(&mut env, method);
    let p = get_str(&mut env, password);
    let h = get_str(&mut env, host);
    let t = get_str(&mut env, tag);
    to_jstring(&mut env, crate::control::build_ss_link(&m, &p, &h, port.max(1) as u16, &t))
}

/// String parseSsLink(String link) → JSON
#[no_mangle]
pub extern "system" fn Java_com_nexx_rustcore_RustCore_parseSsLink(
    mut env: JNIEnv,
    _class: JClass,
    link: JString,
) -> jstring {
    let l = get_str(&mut env, link);
    to_jstring(&mut env, crate::control::parse_ss_link(&l).to_string())
}
