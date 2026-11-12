//! Парсеры прокси-конфигов (порт ProxyConfigParser.kt на Rust).
//! Результат — JSON-строка вида:
//! {"ok":true,"kind":"vless|vmess|trojan|shadowsocks|wireguard|xray_json",
//!  "id":"...","remarks":"...","config_json":"...","protocol":"..."}
//! или {"ok":false,"error":"..."}

use crate::crypto::{base64_decode, base64url_decode, base64url_encode, parse_query_string, percent_decode};
use serde_json::{json, Value};

fn ok(kind: &str, id: &str, remarks: &str, config_json: &str, protocol: &str) -> String {
    json!({
        "ok": true,
        "kind": kind,
        "id": id,
        "remarks": remarks,
        "config_json": config_json,
        "protocol": protocol,
    })
    .to_string()
}

fn err(msg: &str) -> String {
    json!({"ok": false, "error": msg}).to_string()
}

/// Главная точка входа: автоопределение формата (как ProxyConfigParser.parseFromString).
pub fn parse_proxy_config(input: &str, remarks: &str) -> String {
    let input = input.trim();
    let remarks = if remarks.is_empty() { "Untitled" } else { remarks };
    if input.starts_with("vless://") {
        parse_vless(input, remarks)
    } else if input.starts_with("vmess://") {
        parse_vmess(input, remarks)
    } else if input.starts_with("trojan://") {
        parse_trojan(input, remarks)
    } else if input.starts_with("ss://") {
        parse_shadowsocks(input, remarks)
    } else if input.starts_with("[Interface]") {
        parse_wireguard(input, remarks)
    } else if input.starts_with('{') {
        parse_xray_json(input, remarks)
    } else {
        err("Unknown config format")
    }
}

/// Разбор authority+path части URI без стандартного url-крейта:
/// scheme://[userinfo@]host[:port][/path][?query][#fragment]
struct UriParts {
    userinfo: String,
    host: String,
    port: i64,
    query: String,
    fragment: String,
}

fn split_uri(input: &str) -> Result<UriParts, String> {
    let after_scheme = input
        .split_once("://")
        .map(|x| x.1)
        .ok_or("no scheme")?;
    let (authority, rest) = match after_scheme.find(['/', '?', '#']) {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, ""),
    };
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(idx) => (
            percent_decode(&authority[..idx]),
            &authority[idx + 1..],
        ),
        None => (String::new(), authority),
    };
    // host:port (учитываем [ipv6])
    let (host, port) = if hostport.starts_with('[') {
        let close = hostport.find(']').ok_or("bad ipv6 host")?;
        let h = &hostport[1..close];
        let p = hostport[close + 1..]
            .strip_prefix(':')
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(-1);
        (h.to_string(), p)
    } else {
        match hostport.rfind(':') {
            Some(idx) => {
                let p = hostport[idx + 1..].parse::<i64>().unwrap_or(-1);
                (hostport[..idx].to_string(), p)
            }
            None => (hostport.to_string(), -1),
        }
    };
    let mut query = String::new();
    let mut fragment = String::new();
    let mut rest = rest;
    if let Some(hidx) = rest.find('#') {
        fragment = percent_decode(&rest[hidx + 1..]);
        rest = &rest[..hidx];
    }
    if let Some(qidx) = rest.find('?') {
        query = rest[qidx + 1..].to_string();
    }
    if host.is_empty() {
        return Err("no host".into());
    }
    Ok(UriParts {
        userinfo,
        host,
        port,
        query,
        fragment,
    })
}

fn parse_vless(uri: &str, remarks: &str) -> String {
    match split_uri(uri) {
        Ok(u) => {
            if u.userinfo.is_empty() {
                return err("No UUID in VLESS URI");
            }
            let port = if u.port == -1 { 443 } else { u.port };
            let params: Vec<(String, String)> = parse_query_string(&u.query);
            let get = |k: &str| params.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
            let security = get("security").unwrap_or_default();
            let tls = security == "tls" || security == "reality" || params.iter().any(|(k, _)| k == "tls");
            let config = json!({
                "type": "vless",
                "id": u.userinfo,
                "host": u.host,
                "port": port,
                "encryption": get("encryption").unwrap_or_else(|| "none".into()),
                "flow": get("flow").unwrap_or_default(),
                "tls": tls,
                "sni": get("sni").unwrap_or_else(|| u.host.clone()),
            });
            let id8: String = u.userinfo.chars().take(8).collect();
            let remark = if u.fragment.is_empty() { remarks } else { &u.fragment };
            ok("vless", &id8, remark, &config.to_string(), "VLESS")
        }
        Err(e) => err(&format!("VLESS parse: {e}")),
    }
}

fn parse_trojan(uri: &str, remarks: &str) -> String {
    match split_uri(uri) {
        Ok(u) => {
            if u.userinfo.is_empty() {
                return err("No password in Trojan URI");
            }
            let port = if u.port == -1 { 443 } else { u.port };
            let config = json!({
                "type": "trojan",
                "password": u.userinfo,
                "host": u.host,
                "port": port,
                "sni": u.host,
            });
            let id8: String = u.userinfo.chars().take(8).collect();
            let remark = if u.fragment.is_empty() { remarks } else { &u.fragment };
            ok("trojan", &id8, remark, &config.to_string(), "Trojan")
        }
        Err(e) => err(&format!("Trojan parse: {e}")),
    }
}

fn parse_vmess(uri: &str, remarks: &str) -> String {
    let encoded = &uri["vmess://".len()..];
    match base64_decode(encoded) {
        Ok(raw) => {
            let decoded = String::from_utf8_lossy(&raw).into_owned();
            // валидируем JSON если похоже на JSON
            let parsed: Option<Value> = serde_json::from_str(&decoded).ok();
            let id = parsed
                .as_ref()
                .and_then(|v| v.get("id").and_then(|x| x.as_str()))
                .map(|s| s.chars().take(8).collect::<String>())
                .unwrap_or_else(|| "vmess00".into());
            let remark = parsed
                .as_ref()
                .and_then(|v| v.get("ps").and_then(|x| x.as_str()))
                .filter(|s| !s.is_empty())
                .unwrap_or(remarks)
                .to_string();
            ok("vmess", &id, &remark, &decoded, "VMess")
        }
        Err(e) => err(&format!("VMess base64: {e}")),
    }
}

/// ss:// — SIP002: base64url(method:password)@host:port/?plugin=...#tag
/// или legacy: ss://base64url(method:password@host:port)#tag
fn parse_shadowsocks(uri: &str, remarks: &str) -> String {
    let body = &uri["ss://".len()..];
    let (main, fragment) = match body.find('#') {
        Some(i) => (&body[..i], percent_decode(&body[i + 1..])),
        None => (body, String::new()),
    };
    let remark = if fragment.is_empty() { remarks.to_string() } else { fragment };
    // Вариант 1: userinfo@host:port (SIP002)
    if let Some(at) = main.find('@') {
        let userinfo_b64 = &main[..at];
        let hostport = &main[at + 1..];
        let (host, port) = match hostport.rfind(':') {
            Some(i) => (
                hostport[..i].trim_matches(|c| c == '/' ).to_string(),
                hostport[i + 1..].split('/').next().unwrap_or("").parse::<i64>().unwrap_or(-1),
            ),
            None => (hostport.trim_matches('/').to_string(), -1),
        };
        match base64url_decode(userinfo_b64) {
            Ok(raw) => {
                let s = String::from_utf8_lossy(&raw).into_owned();
                let method = s.split(':').next().unwrap_or("").to_string();
                let id = base64url_encode(&crate::crypto::sha256_raw(&raw));
                let config = json!({
                    "type": "shadowsocks",
                    "method": method,
                    "host": host,
                    "port": if port == -1 { 8388 } else { port },
                });
                ok("shadowsocks", &id[..8.min(id.len())], &remark, &config.to_string(), "Shadowsocks")
            }
            Err(e) => err(&format!("SS userinfo decode: {e}")),
        }
    } else {
        // Вариант 2: весь main — base64url(method:password@host:port)
        match base64url_decode(main) {
            Ok(raw) => {
                let s = String::from_utf8_lossy(&raw).into_owned();
                let (mp, hostport) = match s.rfind('@') {
                    Some(i) => (&s[..i], &s[i + 1..]),
                    None => return err("SS legacy: no @ in decoded"),
                };
                let method = mp.split(':').next().unwrap_or("").to_string();
                let (host, port) = match hostport.rfind(':') {
                    Some(i) => (hostport[..i].to_string(), hostport[i + 1..].parse::<i64>().unwrap_or(8388)),
                    None => (hostport.to_string(), 8388),
                };
                let id = base64url_encode(&crate::crypto::sha256_raw(s.as_bytes()));
                let config = json!({
                    "type": "shadowsocks",
                    "method": method,
                    "host": host,
                    "port": port,
                });
                ok("shadowsocks", &id[..8.min(id.len())], &remark, &config.to_string(), "Shadowsocks")
            }
            Err(e) => err(&format!("SS legacy decode: {e}")),
        }
    }
}

fn parse_wireguard(text: &str, remarks: &str) -> String {
    let id: String = remarks.chars().take(8).collect();
    let id = if id.is_empty() { "wg00000".to_string() } else { id };
    let iface: String = remarks.chars().filter(|c| !c.is_whitespace()).take(10).collect();
    let config = json!({
        "type": "wireguard",
        "interface": iface,
        "config": text,
    });
    ok("wireguard", &id, remarks, &config.to_string(), "WireGuard")
}

fn parse_xray_json(json_str: &str, remarks: &str) -> String {
    match serde_json::from_str::<Value>(json_str) {
        Ok(v) => {
            let id_raw = format!("{}", v.to_string().len());
            let id: String = id_raw.chars().take(8).collect();
            ok("xray_json", &id, remarks, json_str, "Custom")
        }
        Err(e) => err(&format!("Xray JSON: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_json(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn vless_golden() {
        let r = parse_proxy_config(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=none&security=tls&sni=cdn.example.com&flow=xtls-rprx-vision#My%20Server",
            "fallback",
        );
        let v = parse_json(&r);
        assert_eq!(v["ok"], true);
        assert_eq!(v["kind"], "vless");
        assert_eq!(v["id"], "b831381d");
        assert_eq!(v["remarks"], "My Server");
        let cfg: Value = serde_json::from_str(v["config_json"].as_str().unwrap()).unwrap();
        assert_eq!(cfg["host"], "example.com");
        assert_eq!(cfg["port"], 443);
        assert_eq!(cfg["sni"], "cdn.example.com");
        assert_eq!(cfg["flow"], "xtls-rprx-vision");
        assert_eq!(cfg["tls"], true);
    }

    #[test]
    fn ss_sip002_golden() {
        // base64url("aes-256-gcm:testpass") = YWVzLTI1Ni1nY206dGVzdHBhc3M
        let r = parse_proxy_config("ss://YWVzLTI1Ni1nY206dGVzdHBhc3M@192.168.1.10:8388#Home", "x");
        let v = parse_json(&r);
        assert_eq!(v["ok"], true);
        assert_eq!(v["kind"], "shadowsocks");
        assert_eq!(v["remarks"], "Home");
        let cfg: Value = serde_json::from_str(v["config_json"].as_str().unwrap()).unwrap();
        assert_eq!(cfg["method"], "aes-256-gcm");
        assert_eq!(cfg["host"], "192.168.1.10");
        assert_eq!(cfg["port"], 8388);
    }

    #[test]
    fn ss_legacy_golden() {
        // base64url("aes-128-gcm:pw@10.0.0.2:1234")
        let raw = "aes-128-gcm:pw@10.0.0.2:1234";
        let enc = base64url_encode(raw.as_bytes());
        let r = parse_proxy_config(&format!("ss://{enc}"), "legacy");
        let v = parse_json(&r);
        assert_eq!(v["ok"], true);
        let cfg: Value = serde_json::from_str(v["config_json"].as_str().unwrap()).unwrap();
        assert_eq!(cfg["method"], "aes-128-gcm");
        assert_eq!(cfg["host"], "10.0.0.2");
        assert_eq!(cfg["port"], 1234);
    }

    #[test]
    fn vmess_roundtrip() {
        let inner = r#"{"v":"2","ps":"TestVM","add":"1.2.3.4","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","net":"tcp"}"#;
        let enc = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, inner.as_bytes());
        let r = parse_proxy_config(&format!("vmess://{enc}"), "fb");
        let v = parse_json(&r);
        assert_eq!(v["ok"], true);
        assert_eq!(v["kind"], "vmess");
        assert_eq!(v["id"], "b831381d");
        assert_eq!(v["remarks"], "TestVM");
    }

    #[test]
    fn trojan_golden() {
        let r = parse_proxy_config("trojan://s3cretP4ss@trojan.example.org:443#TG", "fb");
        let v = parse_json(&r);
        assert_eq!(v["ok"], true);
        assert_eq!(v["kind"], "trojan");
        assert_eq!(v["remarks"], "TG");
        let cfg: Value = serde_json::from_str(v["config_json"].as_str().unwrap()).unwrap();
        assert_eq!(cfg["password"], "s3cretP4ss");
        assert_eq!(cfg["host"], "trojan.example.org");
    }

    #[test]
    fn unknown_format() {
        let v = parse_json(&parse_proxy_config("hello world", "x"));
        assert_eq!(v["ok"], false);
    }

    #[test]
    fn wireguard_text() {
        let v = parse_json(&parse_proxy_config("[Interface]\nPrivateKey = abc\n", "My WG"));
        assert_eq!(v["ok"], true);
        assert_eq!(v["kind"], "wireguard");
        assert_eq!(v["id"], "My WG".chars().take(8).collect::<String>());
    }
}
