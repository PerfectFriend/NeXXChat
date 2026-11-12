//! Control plane форка NeXX (фаза 4 плана миграции):
//! - PortAllocator с межпроцессным flock + проверкой bindable
//! - health-check: прямой TCP и end-to-end через SOCKS5
//! - merge Xray-конфига (socks inbound + outbounds) — порт XrayBackend.buildMergedConfig
//! - Tor control-port: bootstrap progress
//! - kill-switch / routing policy — чистая функция
//! - share links (ss://)
//!
//! Всё — std + libc, тестируется на host.

use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

use crate::crypto::base64url_encode;

// ---------- PortAllocator ----------

fn read_used(mut f: &File) -> std::collections::BTreeSet<u16> {
    let mut s = String::new();
    let _ = f.seek(SeekFrom::Start(0));
    let _ = f.read_to_string(&mut s);
    s.split(|c: char| c == ',' || c.is_whitespace())
        .filter_map(|x| x.parse::<u16>().ok())
        .collect()
}

fn write_used(f: &mut File, used: &std::collections::BTreeSet<u16>) -> std::io::Result<()> {
    f.seek(SeekFrom::Start(0))?;
    f.set_len(0)?;
    let s = used
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    f.write_all(s.as_bytes())?;
    f.flush()
}

fn port_bindable(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}

/// Acquire порт из диапазона [start,end]: flock lock-файла, порт должен быть
/// не занят в файле И реально bindable. Возвращает порт или -1.
pub fn port_alloc_acquire(lock_path: &str, start: u16, end: u16) -> i64 {
    let mut lock = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
    {
        Ok(f) => f,
        Err(_) => return -1,
    };
    unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
    let mut used = read_used(&lock);
    let mut chosen: i64 = -1;
    for p in start..=end {
        if used.contains(&p) {
            continue;
        }
        if port_bindable(p) {
            chosen = p as i64;
            used.insert(p);
            break;
        }
    }
    if chosen >= 0 {
        let _ = write_used(&mut lock, &used);
    }
    unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };
    chosen
}

/// Освободить порт (записать в lock-файл). true если порт был занят.
pub fn port_alloc_release(lock_path: &str, port: u16) -> bool {
    let mut lock = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
    {
        Ok(f) => f,
        Err(_) => return false,
    };
    unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
    let mut used = read_used(&lock);
    let removed = used.remove(&port);
    if removed {
        let _ = write_used(&mut lock, &used);
    }
    unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };
    removed
}

// ---------- Health check ----------

fn resolve(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    (host, port).to_socket_addrs().ok()?.next()
}

/// Прямой TCP health-check. JSON: {"ok":bool,"latency_ms":u64,"error"?:str}
pub fn health_check_tcp(host: &str, port: u16, timeout_ms: u32) -> Value {
    let start = Instant::now();
    let addr = match resolve(host, port) {
        Some(a) => a,
        None => {
            return json!({"ok":false,"error":format!("dns resolve failed: {host}"),"latency_ms":0})
        }
    };
    match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms.max(1) as u64)) {
        Ok(_) => json!({"ok":true,"latency_ms":start.elapsed().as_millis() as u64}),
        Err(e) => json!({"ok":false,"error":e.to_string(),"latency_ms":start.elapsed().as_millis() as u64}),
    }
}

/// End-to-end health-check через SOCKS5 (handshake + CONNECT до target).
pub fn health_check_socks5(
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    timeout_ms: u32,
) -> Value {
    let start = Instant::now();
    let fail = |e: String| json!({"ok":false,"error":e,"latency_ms":start.elapsed().as_millis() as u64});
    let proxy = match resolve(proxy_host, proxy_port) {
        Some(a) => a,
        None => return fail(format!("dns resolve failed: {proxy_host}")),
    };
    let mut s = match TcpStream::connect_timeout(&proxy, Duration::from_millis(timeout_ms.max(1) as u64)) {
        Ok(s) => s,
        Err(e) => return fail(format!("connect proxy: {e}")),
    };
    let t = Duration::from_millis(timeout_ms.max(1) as u64);
    let _ = s.set_read_timeout(Some(t));
    let _ = s.set_write_timeout(Some(t));

    // greeting: VER=5, NMETHODS=1, NO-AUTH
    if s.write_all(&[0x05, 0x01, 0x00]).is_err() {
        return fail("write greeting".into());
    }
    let mut resp = [0u8; 2];
    if s.read_exact(&mut resp).is_err() {
        return fail("read greeting reply".into());
    }
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return fail(format!("proxy refused no-auth: {:02x?}", resp));
    }

    // CONNECT request
    let mut req = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = target_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        req.push(0x03);
        req.push(target_host.len().min(255) as u8);
        req.extend_from_slice(&target_host.as_bytes()[..target_host.len().min(255)]);
    }
    req.extend_from_slice(&target_port.to_be_bytes());
    if s.write_all(&req).is_err() {
        return fail("write connect".into());
    }

    let mut head = [0u8; 4];
    if s.read_exact(&mut head).is_err() {
        return fail("read connect reply".into());
    }
    if head[1] != 0x00 {
        return fail(format!("socks connect rep={} (target unreachable via proxy)", head[1]));
    }
    // дочитать адрес+порт в reply
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            if s.read_exact(&mut l).is_err() {
                return fail("read domain len".into());
            }
            l[0] as usize
        }
        _ => return fail(format!("bad atyp {}", head[3])),
    };
    let mut rest = vec![0u8; addr_len + 2];
    if s.read_exact(&mut rest).is_err() {
        return fail("read connect addr".into());
    }
    json!({"ok":true,"latency_ms":start.elapsed().as_millis() as u64})
}

// ---------- Xray config merge (порт buildMergedConfig) ----------

/// Prepend socks-inbound на 127.0.0.1:local_port; гарантирует outbounds и log.
/// Невалидный userConfig трактуется как {} (как в Kotlin).
pub fn build_xray_merged_config(user_config: &str, local_port: u16, protocol_hint: &str) -> Value {
    let mut root: Value = serde_json::from_str(user_config.trim()).unwrap_or(json!({}));
    if !root.is_object() {
        root = json!({});
    }
    let socks_inbound = json!({
        "tag": "socks-in",
        "port": local_port,
        "listen": "127.0.0.1",
        "protocol": "socks",
        "settings": {"udp": true, "auth": "noauth"}
    });
    let mut inbounds = root
        .get("inbounds")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let mut new_inbounds = vec![socks_inbound];
    new_inbounds.append(&mut inbounds);
    root["inbounds"] = Value::Array(new_inbounds);

    let has_outbounds = root
        .get("outbounds")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    if !has_outbounds {
        let proto = protocol_hint.to_lowercase();
        let proto = if proto.is_empty() { "vless".to_string() } else { proto };
        root["outbounds"] = json!([{"tag":"proxy","protocol":proto,"settings":{}}]);
    }
    if root.get("log").is_none() {
        root["log"] = json!({"loglevel":"warning"});
    }
    json!({"ok":true,"config":root.to_string()})
}

// ---------- Tor control port ----------

/// Подключиться к Tor control port, спросить bootstrap progress.
/// CookieAuthentication 0 → AUTHENTICATE без пароля. Возвращает {"ok","progress":0-100,"phase"?}.
pub fn tor_control_bootstrap_progress(control_host: &str, control_port: u16, timeout_ms: u32) -> Value {
    let addr = match resolve(control_host, control_port) {
        Some(a) => a,
        None => return json!({"ok":false,"error":format!("dns: {control_host}")}),
    };
    let mut s = match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms.max(1) as u64)) {
        Ok(s) => s,
        Err(e) => return json!({"ok":false,"error":format!("connect: {e}")}),
    };
    let t = Duration::from_millis(timeout_ms.max(1) as u64);
    let _ = s.set_read_timeout(Some(t));
    let _ = s.set_write_timeout(Some(t));
    use std::io::BufRead;
    let mut reader = s.try_clone().ok().map(std::io::BufReader::new);
    let mut send = |cmd: &str| -> Result<(), String> {
        s.write_all(cmd.as_bytes()).map_err(|e| e.to_string())?;
        s.flush().map_err(|e| e.to_string())
    };
    let read_reply = |r: &mut Option<std::io::BufReader<TcpStream>>| -> Result<String, String> {
        let mut out = String::new();
        loop {
            let mut line = String::new();
            match r {
                Some(rd) => {
                    let n = rd.read_line(&mut line).map_err(|e| e.to_string())?;
                    if n == 0 {
                        return Err("eof".into());
                    }
                }
                None => return Err("no reader".into()),
            }
            out.push_str(&line);
            // multi-line reply заканчивается "250 " (пробел) на последней строке
            if line.starts_with("250 ") || (!line.starts_with("250-") && line.len() >= 4) {
                break;
            }
            if !line.contains('-') {
                break;
            }
        }
        Ok(out)
    };
    // AUTHENTICATE (пустой — при CookieAuthentication 0 / без пароля)
    if send("AUTHENTICATE\r\n").is_err() {
        return json!({"ok":false,"error":"write AUTHENTICATE"});
    }
    match read_reply(&mut reader) {
        Ok(r) if r.starts_with("250") => {}
        Ok(r) => return json!({"ok":false,"error":format!("auth refused: {}", r.trim())}),
        Err(e) => return json!({"ok":false,"error":format!("auth read: {e}")}),
    }
    if send("GETINFO status/bootstrap-phase\r\n").is_err() {
        return json!({"ok":false,"error":"write GETINFO"});
    }
    match read_reply(&mut reader) {
        Ok(r) => {
            // 250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=42 TAG=...
            let mut progress = -1i64;
            let mut summary = String::new();
            for part in r.split_whitespace() {
                if let Some(v) = part.strip_prefix("PROGRESS=") {
                    progress = v.parse().unwrap_or(-1);
                }
                if let Some(v) = part.strip_prefix("SUMMARY=") {
                    summary = v.to_string();
                }
            }
            json!({"ok":true,"progress":progress,"summary":summary})
        }
        Err(e) => json!({"ok":false,"error":format!("getinfo read: {e}")}),
    }
}

// ---------- Routing / kill-switch policy ----------

/// Решение куда пускать трафик. Возвращает "direct" | "proxy" | "tor" | "block".
/// - .onion цель всегда через Tor; без Tor — block.
/// - only_tor=true: clearnet тоже через Tor; без Tor — block.
/// - clearnet с proxy up — через proxy; иначе direct если allow_non_tor, иначе block.
pub fn route_decision(
    proxy_up: bool,
    tor_up: bool,
    target_onion: bool,
    only_tor: bool,
    allow_non_tor: bool,
) -> &'static str {
    if target_onion {
        return if tor_up { "tor" } else { "block" };
    }
    if only_tor {
        return if tor_up { "tor" } else { "block" };
    }
    if proxy_up {
        "proxy"
    } else if allow_non_tor {
        "direct"
    } else {
        "block"
    }
}

// ---------- Share links ----------

/// ss:// share link (SIP002): ss://base64url(method:password)@host:port#tag
pub fn build_ss_link(method: &str, password: &str, host: &str, port: u16, tag: &str) -> String {
    let userinfo = base64url_encode(format!("{method}:{password}").as_bytes());
    let frag = if tag.is_empty() {
        String::new()
    } else {
        format!("#{}", crate::crypto::percent_decode(tag)) // tag как есть, если уже plain
    };
    format!("ss://{userinfo}@{host}:{port}{frag}")
}

/// Парсинг ss-link обратно в поля (для импорта/валидации): JSON {ok, method, password, host, port, tag}
pub fn parse_ss_link(link: &str) -> Value {
    let body = link.strip_prefix("ss://").unwrap_or(link);
    let (main, tag) = match body.find('#') {
        Some(i) => (&body[..i], crate::crypto::percent_decode(&body[i + 1..])),
        None => (body, String::new()),
    };
    let fail = |e: &str| json!({"ok":false,"error":e});
    if let Some(at) = main.find('@') {
        let raw = match crate::crypto::base64url_decode(&main[..at]) {
            Ok(r) => r,
            Err(e) => return fail(&e),
        };
        let s = String::from_utf8_lossy(&raw).into_owned();
        let (method, password) = match s.find(':') {
            Some(i) => (s[..i].to_string(), s[i + 1..].to_string()),
            None => return fail("no ':' in userinfo"),
        };
        let hostport = &main[at + 1..];
        let (host, port) = match hostport.rfind(':') {
            Some(i) => (
                hostport[..i].to_string(),
                hostport[i + 1..].parse::<u16>().unwrap_or(0),
            ),
            None => return fail("no port"),
        };
        json!({"ok":true,"method":method,"password":password,"host":host,"port":port,"tag":tag})
    } else {
        let raw = match crate::crypto::base64url_decode(main) {
            Ok(r) => r,
            Err(e) => return fail(&e),
        };
        let s = String::from_utf8_lossy(&raw).into_owned();
        let at = match s.rfind('@') {
            Some(i) => i,
            None => return fail("no '@' in decoded"),
        };
        let (mp, hostport) = (&s[..at], &s[at + 1..]);
        let (method, password) = match mp.find(':') {
            Some(i) => (mp[..i].to_string(), mp[i + 1..].to_string()),
            None => return fail("no ':' in method:password"),
        };
        let (host, port) = match hostport.rfind(':') {
            Some(i) => (hostport[..i].to_string(), hostport[i + 1..].parse::<u16>().unwrap_or(0)),
            None => return fail("no port"),
        };
        json!({"ok":true,"method":method,"password":password,"host":host,"port":port,"tag":tag})
    }
}
