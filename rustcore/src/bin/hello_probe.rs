//! Диагностика server hello от публичного релея: TLS(openssl) -> чтение блока -> дамп полей.
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

use nexxrust::protocols::smp::parse_server_hello;
use nexxrust::protocols::smp_wire::{decode_block, BLOCK_SIZE};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let host = args.first().cloned().unwrap_or_else(|| "smp6.simplex.im".into());
    let port: u16 = args.get(1).cloned().unwrap_or_else(|| "5223".into()).parse().unwrap();

    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
    let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
    b.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    b.set_ciphersuites("TLS_CHACHA20_POLY1305_SHA256").unwrap();
    b.set_sigalgs_list("ed448:ed25519:ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512")
        .unwrap();
    b.set_groups_list("X25519").unwrap();
    b.set_alpn_protos(b"\x05smp/1").unwrap();
    b.set_verify(SslVerifyMode::NONE);
    let connector = b.build();
    let sock = TcpStream::connect((host.as_str(), port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut tls = connector.connect(&host, sock).unwrap();
    println!("TLS ok: {:?} alpn={:?}", tls.ssl().version_str(), tls.ssl().selected_alpn_protocol());
    let chain = tls.ssl().peer_cert_chain().unwrap();
    for c in chain.iter() {
        println!("cert: subj={:?} issuer={:?}", c.subject_name(), c.issuer_name());
    }

    let mut block = vec![0u8; BLOCK_SIZE];
    tls.read_exact(&mut block).unwrap();
    let hello_bytes = decode_block(&block).unwrap();
    println!("hello bytes: {} (first 16: {:02x?})", hello_bytes.len(), &hello_bytes[..16.min(hello_bytes.len())]);
    match parse_server_hello(&hello_bytes) {
        Ok(h) => {
            println!("min={} max={} sessionId={}B", h.min_version, h.max_version, h.session_id.len());
            println!("cert_chain blob={}B signed_object={}B", h.cert_chain.len(), h.signed_object.len());
            println!("signed first 24: {:02x?}", &h.signed_object[..24.min(h.signed_object.len())]);
            println!("chain first 24: {:02x?}", &h.cert_chain[..24.min(h.cert_chain.len())]);
        }
        Err(e) => println!("parse FAIL: {e:?} raw len={}", hello_bytes.len()),
    }
    // Диагностика подписи сессионного ключа
    if let Ok(h) = parse_server_hello(&hello_bytes) {
        if let Some((pk, cands, sig)) = nexxrust::protocols::smp::extract_signed_pubkey(&h.signed_object) {
            println!("server x25519 pub: {:02x?}", &pk[..8]);
            println!("sig len={} cands={}", sig.len(), cands.len());
            println!("signed_object hex: {:02x?}", &h.signed_object);
            let leaf = tls.ssl().peer_certificate().unwrap();
            println!("leaf pubkey alg: {:?}", leaf.public_key().unwrap().id());
            let leaf_der = leaf.to_der().unwrap();
            // прямой Ed448 verify с диагностикой
            if let Some(k) = nexxrust::protocols::smp::parse_ed448_x509(&leaf_der) {
                let mut spki = nexxrust::protocols::smp::ED448_SPKI_PREFIX.to_vec();
                spki.extend_from_slice(&k);
                let pkey = openssl::pkey::PKey::public_key_from_der(&spki).unwrap();
                let mut v = openssl::sign::Verifier::new_without_digest(&pkey).unwrap();
                let mut all = cands.clone();
                all.push(h.signed_object.clone());
                all.push(vec![0x30, 0x81, 0xaa]); // заголовок внешнего SEQUENCE
                for (i, c) in all.iter().enumerate() {
                    let r = v.verify_oneshot(&sig, c);
                    println!("ed448 cand[{i}] len={} -> {:?}", c.len(), r);
                }
            } else {
                println!("ed448 key NOT parsed from leaf");
                let mut positions = Vec::new();
                for i in 0..leaf_der.len().saturating_sub(3) {
                    if leaf_der[i..i + 3] == [0x2b, 0x65, 0x71] {
                        positions.push(i);
                    }
                }
                for pos in &positions {
                    println!("OID@{pos}: {:02x?}", &leaf_der[pos.saturating_sub(6)..(pos + 64).min(leaf_der.len())]);
                }
                // raw key напрямую из openssl
                let raw = leaf.public_key().unwrap().raw_public_key().unwrap();
                println!("raw pubkey len={} {:02x?}", raw.len(), &raw[..8]);
            }
            for (i, c) in cands.iter().enumerate() {
                let ok = nexxrust::protocols::smp::verify_server_signed_key(&leaf_der, c, &sig);
                println!("cand[{i}] len={} verify={ok}", c.len());
            }
            // попробуем также ключ из SMP-цепочки сертификатов hello
            let chain_certs = nexxrust::protocols::smp_client::split_cert_chain(&h.cert_chain);
            println!("smp chain certs: {}", chain_certs.len());
            for (i, der) in chain_certs.iter().enumerate() {
                for (j, c) in cands.iter().enumerate() {
                    if nexxrust::protocols::smp::verify_server_signed_key(der, c, &sig) {
                        println!("VERIFY OK: smp-chain cert[{i}] cand[{j}]");
                    }
                }
            }
        } else {
            println!("extract_signed_pubkey: None");
        }
    }
    // сырой хвост после sessionId для ручного разбора
    if hello_bytes.len() > 6 {
        let sid_len = hello_bytes[4] as usize;
        let after = 5 + sid_len;
        println!("after sessionId (off={}): {:02x?}", after, &hello_bytes[after..(after + 40).min(hello_bytes.len())]);
    }
}
