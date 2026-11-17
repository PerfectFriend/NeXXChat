//! XFTP big-file smoke: файл 8 МБ chunked (64KB) через библиотеку против xftp1.simplex.im:443.
//! Проверяем лимит релея на общий размер и whole-file SHA-512 после roundtrip.
//! Запуск: cargo run --release --bin xftp_big_smoke [host port]
use nexxrust::crypto;
use nexxrust::protocols::xftp_file::{self, CHUNK_PLAIN};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let host = args.first().cloned().unwrap_or_else(|| "xftp1.simplex.im".into());
    let port: u16 = args.get(1).cloned().unwrap_or_else(|| "443".into()).parse().unwrap();

    let size: usize = 8 * 1024 * 1024;
    let file: Vec<u8> = (0..size as u32).map(|i| ((i * 2654435761) >> 13) as u8).collect();
    let digest = crypto::sha256_raw(&file);
    println!("upload {size}B ({} chunks)…", size.div_ceil(CHUNK_PLAIN));

    let desc = xftp_file::upload_file(&host, port, &file).await.expect("upload 8MB");
    println!("OK upload: {} chunks", desc.chunks.len());
    let link = desc.encode();
    let desc2 = xftp_file::FileDesc::decode(&link).expect("decode link");

    let got = xftp_file::download_file(&desc2).await.expect("download 8MB");
    assert_eq!(got.len(), size, "size mismatch");
    assert_eq!(crypto::sha256_raw(&got), digest, "SHA-256 mismatch");
    println!("OK download: {size}B, SHA-256 match");

    xftp_file::delete_file(&desc2).await.expect("FDEL");
    println!("=== XFTP BIG (8MB) SMOKE OK: {} chunks, link roundtrip, FDEL ===", desc.chunks.len());
}
