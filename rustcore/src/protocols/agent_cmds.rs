//! Agent-команды SMP (HELLO/QADD/QUSE) — библиотечная версия bin/agent_rotate.rs.
//! Нужна для ротации очередей (Этап 4.1: QUSE-ротация групповых очередей) из UI.
use ed25519_dalek::SigningKey;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::crypto;
use crate::protocols::smp::{
    encrypt_client_msg, x25519_x509, ServerResponse,
};
use crate::protocols::smp_client::SmpClient;
use crate::protocols::smp_wire::{encode_batch, encode_transmission_v, new_corr_id, Transmission};

pub fn put_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_be_bytes());
}
pub fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
pub fn put_str(out: &mut Vec<u8>, s: &str) {
    out.push(s.len() as u8);
    out.extend_from_slice(s.as_bytes());
}
/// smpRouter: 1 хост + port + keyHash (base64url от 32B).
pub fn smp_router(out: &mut Vec<u8>, host: &str, port: u16, key_hash: &[u8; 32]) {
    out.push(1);
    put_str(out, host);
    put_str(out, &port.to_string());
    put_str(out, &crypto::base64url_encode(key_hash));
}
pub fn snd_queue_addr(out: &mut Vec<u8>, host: &str, port: u16, key_hash: &[u8; 32], sender_id: &[u8]) {
    smp_router(out, host, port, key_hash);
    out.push(sender_id.len() as u8);
    out.extend_from_slice(sender_id);
}
/// newQueue: SMP v6..20, smpRouter, senderId, rcvDhKey x509, queueMode 'M'.
pub fn new_queue_uri(out: &mut Vec<u8>, host: &str, port: u16, key_hash: &[u8; 32], sender_id: &[u8], dh_x509: &[u8]) {
    put_u16(out, 6);
    put_u16(out, 20);
    smp_router(out, host, port, key_hash);
    out.push(sender_id.len() as u8);
    out.extend_from_slice(sender_id);
    out.push(dh_x509.len() as u8);
    out.extend_from_slice(dh_x509);
    out.push(b'M');
}

/// Agent message envelope: 'M' + privHeader(sndMsgId, prevHash) + body.
pub fn agent_msg_envelope(snd_msg_id: i64, prev_hash: &[u8; 32], a_msg: &[u8]) -> Vec<u8> {
    let mut v = vec![b'M'];
    put_i64(&mut v, snd_msg_id);
    v.push(prev_hash.len() as u8);
    v.extend_from_slice(prev_hash);
    v.extend_from_slice(a_msg);
    v
}
pub fn next_prev_hash(envelope: &[u8]) -> [u8; 32] {
    crypto::sha256_raw(envelope).try_into().unwrap()
}

/// QADD: "QA" + n(1) + newQueue + '0' + old sndQueueAddr.
pub fn build_qadd(host: &str, port: u16, key_hash: &[u8; 32], new_snd_id: &[u8], new_dh_x509: &[u8], old_snd_id: &[u8]) -> Vec<u8> {
    let mut qa = b"QA".to_vec();
    qa.push(1);
    new_queue_uri(&mut qa, host, port, key_hash, new_snd_id, new_dh_x509);
    qa.push(b'0');
    snd_queue_addr(&mut qa, host, port, key_hash, old_snd_id);
    qa
}
/// QUSE: "QU" + n(1) + sndQueueAddr(new) + 'T' (primary).
pub fn build_quse(host: &str, port: u16, key_hash: &[u8; 32], new_snd_id: &[u8]) -> Vec<u8> {
    let mut qu = b"QU".to_vec();
    qu.push(1);
    snd_queue_addr(&mut qu, host, port, key_hash, new_snd_id);
    qu.push(b'T');
    qu
}

/// Шлёт agent-сообщение на свою snd-очередь (e2e secret + эфемерный pub отправителя).
pub fn send_agent_msg(
    client: &mut SmpClient,
    snd_id: &[u8],
    e2e_secret: &[u8; 32],
    sender_eph_pub: &[u8; 32],
    agent_body: &[u8],
) -> Result<(), String> {
    let mut body = vec![b'_'];
    body.extend_from_slice(agent_body);
    let envelope = encrypt_client_msg(e2e_secret, client.version, Some(&x25519_x509(sender_eph_pub)), &body)
        .map_err(|e| format!("encrypt: {e}"))?;
    let cmd = crate::protocols::smp::cmd_send(false, &envelope);
    let corr_id = new_corr_id();
    let t = Transmission { authenticator: b"", corr_id: &corr_id, entity_id: snd_id, command: &cmd };
    let enc = encode_transmission_v(client.version, &t).map_err(|e| e.to_string())?;
    let batch = encode_batch(&[enc]).map_err(|e| e.to_string())?;
    client.send_raw_batch(&batch).map_err(|e| e.to_string())?;
    match client.wait_response(&corr_id) {
        Ok(ServerResponse::Ok) => Ok(()),
        Ok(o) => Err(format!("SEND response: {o:?}")),
        Err(e) => Err(format!("SEND wait: {e}")),
    }
}

/// ACK входящего сообщения.
pub fn ack_msg(client: &mut SmpClient, rcv_id: &[u8], auth: &SigningKey, msg_id: &[u8]) -> Result<(), String> {
    let cmd_ack = crate::protocols::smp::cmd_ack(msg_id).map_err(|e| e.to_string())?;
    let corr_id = new_corr_id();
    let a = crate::protocols::smp::sign_command(auth, &client.session_id, &corr_id, rcv_id, &cmd_ack);
    let t = Transmission { authenticator: &a, corr_id: &corr_id, entity_id: rcv_id, command: &cmd_ack };
    let enc = encode_transmission_v(client.version, &t).map_err(|e| e.to_string())?;
    let batch = encode_batch(&[enc]).map_err(|e| e.to_string())?;
    client.send_raw_batch(&batch).map_err(|e| e.to_string())?;
    Ok(())
}

/// Ротация: создаёт новую очередь (NEW+SUB) и шлёт на старую snd HELLO→QADD(new)→QUSE(new).
/// Возвращает (новые QueueIds, новый dh secret) — старая очередь остаётся до OFF/DEL.
/// Параметры старой очереди для ротации.
pub struct OldQueue {
    pub snd_id: Vec<u8>,
    pub auth: SigningKey,
}

#[allow(clippy::too_many_arguments)]
pub fn rotate_queue(
    client: &mut SmpClient,
    host: &str,
    port: u16,
    key_hash: &[u8; 32],
    old: &OldQueue,
    e2e_secret: &[u8; 32],
    eph_pub: &[u8; 32],
) -> Result<(crate::protocols::smp::QueueIds, StaticSecret), String> {
    let old_snd_id = &old.snd_id;
    let _ = &old.auth;
    // новая очередь
    let new_auth = SigningKey::from_bytes(&crypto::random_bytes(32).try_into().map_err(|_| "rng")?);
    let new_dh = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let ids2 = client
        .create_queue(&crate::protocols::smp::RecipientKeys { auth_signing: new_auth.clone(), dh_secret: new_dh.clone() })
        .map_err(|e| format!("NEW q2: {e}"))?;
    client.subscribe(&ids2.rcv_id, &new_auth).map_err(|e| format!("SUB q2: {e}"))?;

    let zero = [0u8; 32];
    let mut prev = zero;
    let hello = agent_msg_envelope(1, &prev, b"H");
    prev = next_prev_hash(&hello);
    send_agent_msg(client, old_snd_id, e2e_secret, eph_pub, &hello)?;

    let dh2_x509 = x25519_x509(X25519Public::from(&new_dh).as_bytes());
    let qa = build_qadd(host, port, key_hash, &ids2.snd_id, &dh2_x509, old_snd_id);
    let qa_env = agent_msg_envelope(2, &prev, &qa);
    prev = next_prev_hash(&qa_env);
    send_agent_msg(client, old_snd_id, e2e_secret, eph_pub, &qa_env)?;

    let qu = build_quse(host, port, key_hash, &ids2.snd_id);
    let qu_env = agent_msg_envelope(3, &prev, &qu);
    send_agent_msg(client, old_snd_id, e2e_secret, eph_pub, &qu_env)?;
    Ok((ids2, new_dh))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qadd_quse_encoding_shape() {
        let kh = [0xAB; 32];
        let qa = build_qadd("smp6.simplex.im", 5223, &kh, &[1u8; 16], &[2u8; 44], &[3u8; 16]);
        assert!(qa.starts_with(b"QA"));
        assert_eq!(qa[2], 1); // одна newQueue
        assert!(qa.windows(2).any(|w| w == b"\x00M") || qa.contains(&b'M'));
        let qu = build_quse("smp6.simplex.im", 5223, &kh, &[1u8; 16]);
        assert!(qu.starts_with(b"QU"));
        assert_eq!(*qu.last().unwrap(), b'T');
    }

    #[test]
    fn envelope_chain_hash() {
        let z = [0u8; 32];
        let e1 = agent_msg_envelope(1, &z, b"H");
        let p = next_prev_hash(&e1);
        let e2 = agent_msg_envelope(2, &p, b"QA");
        assert_ne!(e1, e2);
        assert_eq!(e1[0], b'M');
    }
}
