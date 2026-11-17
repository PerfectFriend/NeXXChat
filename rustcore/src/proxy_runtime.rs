//! Прокси-рантайм NeXX (Этап 4.3): локальный SOCKS5-сервер на 127.0.0.1.
//!
//! Чистый std (работает и на Android): accept → SOCKS5 handshake (no-auth)
//! → CONNECT → bidirectional pipe до цели. Kill-switch: если route_decision
//! для данного вызова = "block", CONNECT отклоняется (reply 0x02) — трафика нет.
//!
//! Outbound «direct» здесь; outbound через Xray/libv2ray — отдельным мостом
//! (нужен libv2ray.aar, см. план). Порт выделяется через control::port_alloc_acquire.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Общее состояние рантайма: allow = kill-switch пропускает, running — сервер жив.
#[derive(Clone)]
pub struct ProxyRuntime {
    pub allow: Arc<AtomicBool>,
    pub running: Arc<AtomicBool>,
    pub port: Arc<std::sync::Mutex<Option<u16>>>,
    /// Upstream SOCKS5 (напр. Xray-ядро libv2ray на 127.0.0.1): если задан — весь CONNECT идёт через него.
    pub upstream: Arc<std::sync::Mutex<Option<(String, u16)>>>,
}

impl ProxyRuntime {
    pub fn new(kill_switch_on: bool) -> Self {
        ProxyRuntime {
            allow: Arc::new(AtomicBool::new(!kill_switch_on)),
            running: Arc::new(AtomicBool::new(false)),
            port: Arc::new(std::sync::Mutex::new(None)),
            upstream: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Устанавливает upstream-SOCKS5 (host, port). None — прямой CONNECT.
    pub fn set_upstream(&self, addr: Option<(String, u16)>) {
        *self.upstream.lock().unwrap() = addr;
    }

    /// Запускает SOCKS5 на порту из диапазона [start,end] через port_alloc_acquire.
    /// Возвращает выделенный порт или -1.
    pub fn start(&self, lock_path: &str, start: u16, end: u16) -> i64 {
        let port = crate::control::port_alloc_acquire(lock_path, start, end);
        if port < 0 {
            return -1;
        }
        let port = port as u16;
        let listener = match TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), port)) {
            Ok(l) => l,
            Err(_) => {
                crate::control::port_alloc_release(lock_path, port);
                return -1;
            }
        };
        self.allow.store(true, Ordering::SeqCst); // сам факт запуска прокси = proxy_up
        self.running.store(true, Ordering::SeqCst);
        *self.port.lock().unwrap() = Some(port);
        let allow = self.allow.clone();
        let running = self.running.clone();
        let upstream = self.upstream.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                match stream {
                    Ok(s) => {
                        let allow = allow.clone();
                        let upstream = upstream.clone();
                        thread::spawn(move || {
                            let _ = handle_socks5(s, allow, upstream);
                        });
                    }
                    Err(_) => break,
                }
            }
        });
        port as i64
    }

    pub fn stop(&self, lock_path: &str) {
        self.running.store(false, Ordering::SeqCst);
        self.allow.store(false, Ordering::SeqCst);
        if let Some(p) = self.port.lock().unwrap().take() {
            crate::control::port_alloc_release(lock_path, p);
        }
    }

    pub fn port(&self) -> Option<u16> {
        *self.port.lock().unwrap()
    }

    /// Kill-switch решение для UI/воркеров: можно ли сейчас выпускать трафик.
    /// allow == "прокси поднят"; kill-switch включён конструктором — тогда без allow = block.
    pub fn route_allowed(&self) -> bool {
        self.allow.load(Ordering::SeqCst)
    }
}

fn read_exact(s: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    s.read_exact(buf)
}

/// Одно SOCKS5-соединение: handshake → CONNECT → pipe.
fn handle_socks5(mut client: TcpStream, allow: Arc<AtomicBool>, upstream: Arc<std::sync::Mutex<Option<(String, u16)>>>) -> std::io::Result<()> {
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    // greeting: VER NMETHODS METHODS
    let mut head = [0u8; 2];
    read_exact(&mut client, &mut head)?;
    if head[0] != 0x05 {
        return Ok(()); // не SOCKS5
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    read_exact(&mut client, &mut methods)?;
    if !methods.contains(&0x00) {
        client.write_all(&[0x05, 0xFF])?; // no acceptable methods
        return Ok(());
    }
    client.write_all(&[0x05, 0x00])?; // no auth

    // request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut req = [0u8; 4];
    read_exact(&mut client, &mut req)?;
    if req[1] != 0x01 {
        client.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?; // command not supported
        return Ok(());
    }
    let host = match req[3] {
        0x01 => {
            let mut b = [0u8; 4];
            read_exact(&mut client, &mut b)?;
            Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()
        }
        0x03 => {
            let mut l = [0u8; 1];
            read_exact(&mut client, &mut l)?;
            let mut b = vec![0u8; l[0] as usize];
            read_exact(&mut client, &mut b)?;
            String::from_utf8_lossy(&b).into_owned()
        }
        0x04 => {
            let mut b = [0u8; 16];
            read_exact(&mut client, &mut b)?;
            format!("{}", std::net::Ipv6Addr::from(b))
        }
        _ => {
            client.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?; // addr type not supported
            return Ok(());
        }
    };
    let mut pb = [0u8; 2];
    read_exact(&mut client, &mut pb)?;
    let port = u16::from_be_bytes(pb);

    // kill-switch: без allow — refuse (reply 0x02 "connection not allowed by ruleset")
    if !allow.load(Ordering::SeqCst) {
        client.write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
        return Ok(());
    }

    // если задан upstream (Xray/libv2ray) — CONNECT через него, иначе прямой
    let up = upstream.lock().unwrap().clone();
    let target = match up {
        Some((uh, up_port)) => match socks5_connect_upstream(&uh, up_port, &host, port) {
            Ok(t) => t,
            Err(_) => {
                client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
                return Ok(());
            }
        },
        None => match TcpStream::connect((host.as_str(), port)) {
            Ok(t) => t,
            Err(_) => {
                client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
                return Ok(());
            }
        },
    };
    // success reply: VER REP RSV ATYP BND.ADDR BND.PORT (0.0.0.0:0)
    client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
    let _ = client.set_read_timeout(None);
    let _ = target.set_read_timeout(None);
    pipe(client, target)
}

/// SOCKS5-клиент к upstream (Xray): handshake no-auth + CONNECT host:port.
/// host может быть доменом (ATYP 0x03) или IPv4 (0x01).
pub fn socks5_connect_upstream(up_host: &str, up_port: u16, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect((up_host, up_port))?;
    s.set_read_timeout(Some(Duration::from_secs(15)))?;
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    if r != [0x05, 0x00] {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "upstream auth required"));
    }
    let mut req = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ip.octets());
    } else {
        req.push(0x03);
        req.push(host.len().min(255) as u8);
        req.extend_from_slice(&host.as_bytes()[..host.len().min(255)]);
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, format!("upstream reply 0x{:02x}", head[1])));
    }
    match head[3] {
        0x01 => { let mut b = [0u8; 6]; s.read_exact(&mut b)?; }
        0x03 => { let mut l = [0u8; 1]; s.read_exact(&mut l)?; let mut b = vec![0u8; l[0] as usize + 2]; s.read_exact(&mut b)?; }
        0x04 => { let mut b = [0u8; 18]; s.read_exact(&mut b)?; }
        _ => {}
    }
    s.set_read_timeout(None)?;
    Ok(s)
}

/// Bidirectional pipe между клиентом и целью до закрытия любой стороны.
fn pipe(a: TcpStream, b: TcpStream) -> std::io::Result<()> {
    let a2 = a.try_clone()?;
    let b2 = b.try_clone()?;
    // нить: цель → клиент
    let t = thread::spawn(move || {
        let _ = io_copy(&mut &b2, &mut &a2);
        let _ = a2.shutdown(Shutdown::Both);
    });
    // основная: клиент → цель
    let _ = io_copy(&mut &a, &mut &b);
    let _ = b.shutdown(Shutdown::Both);
    let _ = t.join();
    Ok(())
}

fn io_copy(r: &mut impl Read, w: &mut impl Write) -> std::io::Result<()> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => w.write_all(&buf[..n])?,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// локальный echo-сервер как "целевой хост"
    fn echo_server() -> u16 {
        let l = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        if s.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    /// минимальный SOCKS5-клиент: handshake + CONNECT(host,port), возвращает stream после success
    fn socks_connect(socks_port: u16, host: &str, port: u16) -> Result<TcpStream, u8> {
        let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, socks_port)).unwrap();
        s.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut r = [0u8; 2];
        s.read_exact(&mut r).unwrap();
        assert_eq!(r, [0x05, 0x00]);
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req).unwrap();
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).unwrap();
        if rep[1] != 0x00 {
            return Err(rep[1]);
        }
        Ok(s)
    }

    fn lock_path(name: &str) -> String {
        let p = std::env::temp_dir().join(format!("nexx_proxy_runtime_{name}.lock"));
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn socks5_echo_roundtrip_when_allowed() {
        let echo_port = echo_server();
        let rt = ProxyRuntime::new(false); // kill-switch выключен → allow
        let port = rt.start(&lock_path("t1"), 21000, 21100);
        assert!(port > 0, "порт не выделен");
        let mut s = socks_connect(port as u16, "127.0.0.1", echo_port).expect("connect ok");
        s.write_all(b"nexx-ping").unwrap();
        let mut buf = [0u8; 9];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"nexx-ping");
        rt.stop(&lock_path("t1"));
        assert!(!rt.running.load(Ordering::SeqCst));
    }

    #[test]
    fn socks5_blocked_by_kill_switch() {
        let echo_port = echo_server();
        let rt = ProxyRuntime::new(true); // kill-switch ВКЛ → allow=false до start? start включает allow
        // явно выключим allow, имитируя "прокси упал"
        rt.allow.store(false, Ordering::SeqCst);
        let port = rt.start(&lock_path("t2"), 21101, 21200);
        assert!(port > 0);
        rt.allow.store(false, Ordering::SeqCst); // после start снова блок
        let r = socks_connect(port as u16, "127.0.0.1", echo_port);
        assert_eq!(r.err(), Some(0x02), "kill-switch должен дать reply 0x02");
        rt.stop(&lock_path("t2"));
    }

    #[test]
    fn route_allowed_reflects_kill_switch() {
        let rt = ProxyRuntime::new(true);
        assert!(!rt.route_allowed(), "kill-switch on + прокси не поднят → block");
        rt.allow.store(true, Ordering::SeqCst);
        assert!(rt.route_allowed(), "прокси поднят → allow");
    }

    /// upstream-цепочка: клиент → наш SOCKS (upstream=Xray-порт) → echo. Данные идут через оба.
    #[test]
    fn upstream_chain_echo_roundtrip() {
        let echo_port = echo_server();
        // «Xray»: обычный SOCKS без upstream
        let up = ProxyRuntime::new(false);
        let up_port = up.start("/tmp/nexx_test_up.lock", 21500, 21599);
        assert!(up_port > 0);
        // основной прокси с upstream на «Xray»
        let rt = ProxyRuntime::new(false);
        rt.set_upstream(Some(("127.0.0.1".into(), up_port as u16)));
        let p = rt.start("/tmp/nexx_test_main.lock", 21600, 21699);
        assert!(p > 0);
        let mut s = socks_connect(p as u16, "127.0.0.1", echo_port).expect("connect via chain");
        s.write_all(b"via-upstream").unwrap();
        let mut buf = [0u8; 12];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"via-upstream");
        rt.stop("/tmp/nexx_test_main.lock");
        up.stop("/tmp/nexx_test_up.lock");
    }
}
