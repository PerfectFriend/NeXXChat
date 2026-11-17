//! XFTP file smoke через библиотеку: upload 256KB -> FileDesc encode/decode -> download -> SHA512.
//! Запуск: cargo run --release --bin xftp_file_smoke [host port]
use nexxrust::protocols::xftp_file::{self, CHUNK_PLAIN};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let host = args.first().cloned().unwrap_or_else(|| "xftp1.simplex.im".into());
    let port: u16 = args.get(1).cloned().unwrap_or_else(|| "443".into()).parse().unwrap();

    let file: Vec<u8> = (0..4 * CHUNK_PLAIN as u32).map(|i| (i % 251) as u8).collect();
    println!("upload {}B…", file.len());
    let desc = xftp_file::upload_file(&host, port, &file).await.expect("upload");
    println!("OK upload: {} chunks", desc.chunks.len());

    let link = desc.encode();
    println!("OK link {} байт", link.len());
    let desc2 = xftp_file::FileDesc::decode(&link).expect("decode link");
    assert_eq!(desc2.size, file.len());

    println!("download…");
    let got = xftp_file::download_file(&desc2).await.expect("download");
    assert_eq!(got, file, "content mismatch");
    println!("OK download: {}B, SHA512 match", got.len());

    xftp_file::delete_file(&desc2).await.expect("FDEL");
    println!("OK FDEL all chunks");
    println!("=== XFTP FILE SMOKE OK ({}B, {} chunks, link roundtrip) ===", file.len(), desc.chunks.len());
}
