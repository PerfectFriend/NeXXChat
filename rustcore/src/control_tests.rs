//! Тесты control plane: порты, SOCKS5 health (mock-сервер), Tor control (mock), Xray merge, routing, ss-links.

use crate::control::*;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

fn tmp_lock(name: &str) -> String {
    let dir = std::env::temp_dir().join("nexxrust_test");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name).to_string_lossy().into_owned()
}

#[test]
fn port_alloc_acquire_release() {
    let lf = tmp_lock("ports1.lock");
    let _ = std::fs::remove_file(&lf);
    let p1 = port_alloc_acquire(&lf, 20000, 20010);
    assert!((20000..=20010).contains(&p1), "p1={p1}");
    // тот же порт не выдадут повторно
    let p2 = port_alloc_acquire(&lf, 20000, 20010);
    assert!(p2 >= 0 && p2 != p1, "p2={p2} p1={p1}");
    assert!(port_alloc_release(&lf, p1 as u16));
    let p3 = port_alloc_acquire(&lf, 20000, 20010);
    assert_eq!(p3, p1, "после release порт снова доступен");
    assert!(!port_alloc_release(&lf, 65000)); // чужой порт
}

#[test]
fn port_alloc_exhaustion() {
    let lf = tmp_lock("ports2.lock");
    let _ = std::fs::remove_file(&lf);
    assert_eq!(port_alloc_acquire(&lf, 20100, 20100), 20100);
    assert_eq!(port_alloc_acquire(&lf, 20100, 20100), -1, "диапазон исчерпан");
}

/// Mock SOCKS5 сервер: greeting → no-auth, CONNECT → success.
fn mock_socks5() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = stream.unwrap();
            thread::spawn(move || {
                let mut buf = [0u8; 262];
                let _ = s.read(&mut buf).unwrap(); // greeting
                s.write_all(&[0x05, 0x00]).unwrap();
                let n = s.read(&mut buf).unwrap(); // connect req
                let atyp = buf[3];
                let _ = n;
                let _ = atyp;
                // reply: success, IPv4 0.0.0.0:0
                s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).unwrap();
            });
        }
    });
    port
}

#[test]
fn socks5_health_ok() {
    let port = mock_socks5();
    let r = health_check_socks5("127.0.0.1", port, "example.com", 443, 3000);
    assert_eq!(r["ok"], true, "r={r}");
    assert!(r["latency_ms"].as_u64().unwrap() < 3000);
}

#[test]
fn socks5_health_refused() {
    // порт закрыт
    let r = health_check_socks5("127.0.0.1", 1, "example.com", 443, 500);
    assert_eq!(r["ok"], false);
}

#[test]
fn tcp_health_localhost() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let r = health_check_tcp("127.0.0.1", port, 1000);
    assert_eq!(r["ok"], true);
    drop(listener);
    let r2 = health_check_tcp("127.0.0.1", port, 300);
    assert_eq!(r2["ok"], false, "после drop listener — fail");
}

/// Mock Tor control port: отвечает на AUTHENTICATE и GETINFO.
fn mock_tor_control(progress: u32) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = stream.unwrap();
            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                loop {
                    let n = match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    if req.contains("AUTHENTICATE") {
                        s.write_all(b"250 OK\r\n").unwrap();
                    } else if req.contains("GETINFO status/bootstrap-phase") {
                        let reply = format!(
                            "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS={progress} TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n"
                        );
                        s.write_all(reply.as_bytes()).unwrap();
                    } else {
                        s.write_all(b"250 OK\r\n").unwrap();
                    }
                }
            });
        }
    });
    port
}

#[test]
fn tor_control_progress_100() {
    let port = mock_tor_control(100);
    let r = tor_control_bootstrap_progress("127.0.0.1", port, 2000);
    assert_eq!(r["ok"], true, "r={r}");
    assert_eq!(r["progress"], 100);
}

#[test]
fn tor_control_progress_42() {
    let port = mock_tor_control(42);
    let r = tor_control_bootstrap_progress("127.0.0.1", port, 2000);
    assert_eq!(r["progress"], 42);
}

#[test]
fn xray_merge_golden() {
    let r = build_xray_merged_config(r#"{"outbounds":[{"protocol":"vless"}]}"#, 10801, "VLESS");
    assert_eq!(r["ok"], true);
    let cfg: Value = serde_json::from_str(r["config"].as_str().unwrap()).unwrap();
    let inbounds = cfg["inbounds"].as_array().unwrap();
    assert_eq!(inbounds[0]["protocol"], "socks");
    assert_eq!(inbounds[0]["port"], 10801);
    assert_eq!(inbounds[0]["listen"], "127.0.0.1");
    // user outbounds сохранены
    assert_eq!(cfg["outbounds"][0]["protocol"], "vless");
    assert_eq!(cfg["log"]["loglevel"], "warning");
}

#[test]
fn xray_merge_empty_and_bad() {
    let r = build_xray_merged_config("not json", 10802, "");
    let cfg: Value = serde_json::from_str(r["config"].as_str().unwrap()).unwrap();
    assert_eq!(cfg["inbounds"][0]["port"], 10802);
    // без outbounds → дефолтный proxy/vless
    assert_eq!(cfg["outbounds"][0]["protocol"], "vless");
    let r2 = build_xray_merged_config("{}", 10803, "trojan");
    let cfg2: Value = serde_json::from_str(r2["config"].as_str().unwrap()).unwrap();
    assert_eq!(cfg2["outbounds"][0]["protocol"], "trojan");
}

#[test]
fn route_decision_table() {
    // (proxy_up, tor_up, onion, only_tor, allow_non_tor) → expected
    assert_eq!(route_decision(true, true, true, false, false), "tor");
    assert_eq!(route_decision(true, false, true, false, true), "block"); // onion без tor — block
    assert_eq!(route_decision(true, true, false, true, false), "tor"); // only_tor
    assert_eq!(route_decision(false, false, false, true, true), "block"); // only_tor без tor — block
    assert_eq!(route_decision(true, false, false, false, false), "proxy");
    assert_eq!(route_decision(false, false, false, false, true), "direct");
    assert_eq!(route_decision(false, false, false, false, false), "block"); // kill-switch
}

#[test]
fn ss_link_roundtrip() {
    let link = build_ss_link("aes-256-gcm", "pw123", "1.2.3.4", 8388, "MyServer");
    assert!(link.starts_with("ss://"), "{link}");
    assert!(link.contains("@1.2.3.4:8388"), "{link}");
    let v = parse_ss_link(&link);
    assert_eq!(v["ok"], true, "v={v}");
    assert_eq!(v["method"], "aes-256-gcm");
    assert_eq!(v["password"], "pw123");
    assert_eq!(v["host"], "1.2.3.4");
    assert_eq!(v["port"], 8388);
    assert_eq!(v["tag"], "MyServer");
}
