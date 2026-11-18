//! Встроенный Tor-транспорт (arti, in-process — без Orbot/внешнего демона).
//!
//! Сценарий: своя серверная нода живёт в онионе (hidden service) и слушает
//! SMP/XFTP. Клиент с хоста `.onion` ходит через локальный SOCKS5, который
//! поднимает этот модуль внутри процесса: arti bootstrap'ится сам, а dial идёт
//! через `TorClient::connect((host, port))`. Несколько `isolated_client` дадут
//! multi-circuit ("каждая сессия своим маршрутом") — см. `tor_circuits`.

use std::io;
use std::net::TcpStream;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Куда arti кладёт state/cache: $NEXX_ARTI_DIR или <temp>/nexx-arti.
pub fn default_state_dir() -> String {
    std::env::var("NEXX_ARTI_DIR").unwrap_or_else(|_| {
        std::env::temp_dir().join("nexx-arti").to_string_lossy().into_owned()
    })
}

pub fn is_onion(host: &str) -> bool {
    host.trim().to_lowercase().ends_with(".onion")
}

struct TorState {
    socks_port: u16,
    /// Пул изолированных Tor-клиентов: каждое новое SOCKS-соединение берёт
    /// следующий клиент round-robin → у каждого своя circuit-изоляция
    /// ("каждая сессия своим маршрутом" в тумане).
    /// Пул клиентов держим живым в TorState (drop = закрытие Tor-соединений).
    _clients: Vec<Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>,
    _rt: tokio::runtime::Runtime,
}

static TOR: OnceLock<Result<Arc<TorState>, String>> = OnceLock::new();

/// Поднять in-process Tor + SOCKS5 на 127.0.0.1 (один раз на процесс).
/// `state_dir` — куда arti кладёт кэш консенсуса (ускоряет повторный старт).
pub fn ensure_tor(state_dir: &str) -> Result<u16, String> {
    TOR.get_or_init(|| start_tor(state_dir)).as_ref().map(|s| s.socks_port).map_err(|e| e.clone())
}

fn start_tor(state_dir: &str) -> Result<Arc<TorState>, String> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("nexx-arti")
        .build()
        .map_err(|e| format!("arti runtime: {e}"))?;
    let (port, clients) = rt.block_on(async move {
        use arti_client::TorClient;
        let sd = format!("{state_dir}/state");
        let cd = format!("{state_dir}/cache");
        let _ = std::fs::create_dir_all(&sd);
        let _ = std::fs::create_dir_all(&cd);
        let cfg = arti_client::config::TorClientConfigBuilder::from_directories(&sd, &cd).build().map_err(|e| format!("arti cfg: {e}"))?;
        let client = TorClient::create_bootstrapped(cfg)
            .await
            .map_err(|e| format!("tor bootstrap: {e}"))?;
        // create_bootstrapped уже возвращает Arc<TorClient>.
        // N изолированных клиентов = N независимых наборов circuits.
        const CIRCUIT_POOLS: usize = 3;
        let mut clients = vec![client.clone()];
        for _ in 1..CIRCUIT_POOLS {
            clients.push(client.isolated_client());
        }
        // Локальный SOCKS5: клиенты (sync и async dial) ходят на него.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.map_err(|e| format!("socks bind: {e}"))?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let clients2 = clients.clone();
        tokio::spawn(async move { socks_serve(listener, clients2).await });
        Ok::<(u16, Vec<Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>), String>((port, clients))
    })?;
    Ok(Arc::new(TorState { socks_port: port, _clients: clients, _rt: rt }))
}

/// SOCKS5 (no-auth) listener: CONNECT host:port → если .onion — через arti,
/// иначе прямой TCP. Обе стороны — boxed async streams, дальше copy_bidirectional.
async fn socks_serve(listener: tokio::net::TcpListener, clients: Vec<Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>>) {
    let rr = std::sync::atomic::AtomicUsize::new(0);
    loop {
        let (mut inbound, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        // multi-circuit: каждое новое соединение — следующий изолированный клиент
        // (свои circuits), round-robin по пулу.
        let idx = rr.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % clients.len();
        let tor = clients[idx].clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // handshake: VER NMETHODS METHODS...
            let mut hdr = [0u8; 2];
            if inbound.read_exact(&mut hdr).await.is_err() { return; }
            let nmethods = hdr[1] as usize;
            let mut methods = vec![0u8; nmethods];
            if inbound.read_exact(&mut methods).await.is_err() { return; }
            if inbound.write_all(&[0x05, 0x00]).await.is_err() { return; } // no-auth
            // request: VER CMD RSV ATYP ...
            let mut req = [0u8; 4];
            if inbound.read_exact(&mut req).await.is_err() { return; }
            if req[1] != 0x01 { let _ = inbound.write_all(&[0x05, 0x07, 0, 1, 0,0,0,0, 0,0]).await; return; } // CONNECT only
            let host = match req[3] {
                0x01 => { let mut b = [0u8; 4]; if inbound.read_exact(&mut b).await.is_err() { return; }
                    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]) }
                0x03 => { let mut l = [0u8; 1]; if inbound.read_exact(&mut l).await.is_err() { return; }
                    let mut b = vec![0u8; l[0] as usize]; if inbound.read_exact(&mut b).await.is_err() { return; }
                    String::from_utf8_lossy(&b).into_owned() }
                0x04 => { let mut b = [0u8; 16]; if inbound.read_exact(&mut b).await.is_err() { return; }
                    format!("{:x}", b.iter().fold(0u128, |a, x| (a << 8) | *x as u128)) }
                _ => return,
            };
            let mut pb = [0u8; 2];
            if inbound.read_exact(&mut pb).await.is_err() { return; }
            let port = u16::from_be_bytes(pb);
            enum Up { Tor(Box<arti_client::DataStream>), Tcp(tokio::net::TcpStream) }
            impl tokio::io::AsyncRead for Up {
                fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
                    match &mut *self { Up::Tor(s) => std::pin::Pin::new(s).poll_read(cx, buf), Up::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf) }
                }
            }
            impl tokio::io::AsyncWrite for Up {
                fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
                    match &mut *self { Up::Tor(s) => std::pin::Pin::new(s).poll_write(cx, buf), Up::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf) }
                }
                fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
                    match &mut *self { Up::Tor(s) => std::pin::Pin::new(s).poll_flush(cx), Up::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx) }
                }
                fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
                    match &mut *self { Up::Tor(s) => std::pin::Pin::new(s).poll_shutdown(cx), Up::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx) }
                }
            }
            let upstream: Up = if is_onion(&host) {
                match tor.connect((host.as_str(), port)).await {
                    Ok(s) => Up::Tor(Box::new(s)),
                    Err(_) => { let _ = inbound.write_all(&[0x05, 0x04, 0, 1, 0,0,0,0, 0,0]).await; return; }
                }
            } else {
                match tokio::net::TcpStream::connect((host.as_str(), port)).await {
                    Ok(s) => Up::Tcp(s),
                    Err(_) => { let _ = inbound.write_all(&[0x05, 0x04, 0, 1, 0,0,0,0, 0,0]).await; return; }
                }
            };
            // reply: success, BND.ADDR 0.0.0.0:0
            if inbound.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.is_err() { return; }
            let mut up = upstream;
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut up).await;
        });
    }
}

/// Синхронный dial: .onion идёт через in-process Tor SOCKS, остальное — прямой TCP.
pub fn dial(host: &str, port: u16, state_dir: &str) -> io::Result<TcpStream> {
    if is_onion(host) {
        let sp = ensure_tor(state_dir).map_err(io::Error::other)?;
        let s = TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], sp)),
            Duration::from_secs(15),
        )?;
        socks_connect(&s, host, port)?;
        return Ok(s);
    }
    let addr = format!("{host}:{port}");
    let sa: std::net::SocketAddr = addr.to_socket_addrs()?.next().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addr"))?;
    TcpStream::connect_timeout(&sa, Duration::from_secs(15))
}

/// SOCKS5 CONNECT через уже подключённый сокет (no-auth).
fn socks_connect(s: &TcpStream, host: &str, port: u16) -> io::Result<()> {
    use std::io::{Read, Write};
    let mut s = s.try_clone()?;
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    if r != [0x05, 0x00] { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "socks auth rejected")); }
    let hb = host.as_bytes();
    if hb.len() > 255 { return Err(io::Error::new(io::ErrorKind::InvalidInput, "host too long")); }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, hb.len() as u8];
    req.extend_from_slice(hb);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut h = [0u8; 4];
    s.read_exact(&mut h)?;
    if h[1] != 0x00 { return Err(io::Error::other(format!("socks err {}", h[1]))); }
    let skip = match h[3] { 0x01 => 4, 0x03 => { let mut l = [0u8;1]; s.read_exact(&mut l)?; l[0] as usize }, 0x04 => 16, _ => 0 };
    let mut b = vec![0u8; skip + 2];
    s.read_exact(&mut b)?;
    Ok(())
}

/// Асинхронный dial для tokio-кода (xftp): .onion — через тот же SOCKS.
pub async fn dial_async(host: &str, port: u16, state_dir: &str) -> io::Result<tokio::net::TcpStream> {
    if is_onion(host) {
        let sp = ensure_tor(state_dir).map_err(io::Error::other)?;
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", sp)).await?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        s.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await?;
        let hb = host.as_bytes();
        let mut req = vec![0x05, 0x01, 0x00, 0x03, hb.len() as u8];
        req.extend_from_slice(hb);
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req).await?;
        let mut h = [0u8; 4];
        s.read_exact(&mut h).await?;
        if h[1] != 0x00 { return Err(io::Error::other(format!("socks err {}", h[1]))); }
        let skip = match h[3] { 0x01 => 4, 0x03 => { let mut l = [0u8;1]; s.read_exact(&mut l).await?; l[0] as usize }, 0x04 => 16, _ => 0 };
        let mut b = vec![0u8; skip + 2];
        s.read_exact(&mut b).await?;
        return Ok(s);
    }
    tokio::net::TcpStream::connect((host, port)).await
}

use std::net::ToSocketAddrs;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn onion_detect() {
        assert!(is_onion("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion"));
        assert!(!is_onion("smp6.simplex.im"));
    }
}
