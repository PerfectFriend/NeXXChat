//! Connection request (`connReqData`) — поля и кодирование по спецификации
//! SimpleX agent protocol (simplexmq/protocol/agent-protocol.md, § connection links).
//!
//! connReqData = agentVersionRange smpQueueUris clientData
//! smpQueueUri = smpClientVersionRange smpServer senderId smpDhPublicKey [queueMode]
//!
//! Полная подписанная ссылка (signedFixedData + Ed25519 + PQ-ratchet X448/sntrup761)
//! — следующий этап; здесь transport-формат NeXX-to-NeXX: base64url(connReqData)
//! в URI вида `nexx://link#/<b64url>`. Поля бинарные — совместимы по структуре со spec.

/// agentVersionRange: min/max версии агент-протокола.
pub const AGENT_V_MIN: u16 = 7;
pub const AGENT_V_MAX: u16 = 7;

/// Одна SMP-очередь в connReq.
#[derive(Debug, Clone, PartialEq)]
pub struct SmpQueueUri {
    /// min/max SMP client version (берём из живой сессии).
    pub smp_v_min: u16,
    pub smp_v_max: u16,
    pub host: String,
    pub port: u16,
    /// SHA-256 CA-сертификата сервера (keyHash); пусто = не пинним (dev).
    pub server_key_hash: Vec<u8>,
    /// senderId очереди (сырые байты).
    pub sender_id: Vec<u8>,
    /// X.509 SPKI X25519 публичный DH-ключ получателя очереди.
    pub dh_x509: Vec<u8>,
    /// 'M' (messaging) / 'C' (contact).
    pub queue_mode: u8,
}

/// connReqData целиком.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnReqData {
    pub agent_v_min: u16,
    pub agent_v_max: u16,
    pub queues: Vec<SmpQueueUri>,
    /// clientData: Some(largeString) или None.
    pub client_data: Option<Vec<u8>>,
}

fn put_short(out: &mut Vec<u8>, b: &[u8]) {
    assert!(b.len() <= 0xFE, "shortString до 254 байт");
    out.push(b.len() as u8);
    out.extend_from_slice(b);
}
fn put_large(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

fn get_short(d: &[u8], p: &mut usize) -> Result<Vec<u8>, String> {
    let l = *d.get(*p).ok_or("short: EOF len")? as usize;
    *p += 1;
    let v = d.get(*p..*p + l).ok_or("short: EOF body")?.to_vec();
    *p += l;
    Ok(v)
}
fn get_large(d: &[u8], p: &mut usize) -> Result<Vec<u8>, String> {
    let l = u16::from_be_bytes([*d.get(*p).ok_or("large: EOF")? , *d.get(*p + 1).ok_or("large: EOF")?]) as usize;
    *p += 2;
    let v = d.get(*p..*p + l).ok_or("large: EOF body")?.to_vec();
    *p += l;
    Ok(v)
}
fn get_u16(d: &[u8], p: &mut usize) -> Result<u16, String> {
    let b = d.get(*p..*p + 2).ok_or("u16: EOF")?;
    *p += 2;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn enc_queue(q: &SmpQueueUri) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&q.smp_v_min.to_be_bytes());
    o.extend_from_slice(&q.smp_v_max.to_be_bytes());
    // smpServer = hosts port serverKeyHash ; hosts = length *host
    o.push(1); // один хост
    put_short(&mut o, q.host.as_bytes());
    put_short(&mut o, q.port.to_string().as_bytes());
    put_short(&mut o, &q.server_key_hash);
    put_short(&mut o, &q.sender_id);
    o.push(q.dh_x509.len() as u8); // length = 1*1 OCTET
    o.extend_from_slice(&q.dh_x509);
    o.push(q.queue_mode);
    o
}

pub fn encode_conn_req(c: &ConnReqData) -> Vec<u8> {
    // connReqData = agentVersionRange smpQueueUris clientData
    // smpQueueUris = length 1*smpQueueUri — uri идут подряд, без largeString-обёртки.
    let mut o = Vec::new();
    o.extend_from_slice(&c.agent_v_min.to_be_bytes());
    o.extend_from_slice(&c.agent_v_max.to_be_bytes());
    o.push(c.queues.len() as u8);
    for q in &c.queues {
        o.extend_from_slice(&enc_queue(q));
    }
    match &c.client_data {
        None => o.push(b'0'),
        Some(d) => {
            o.push(b'1');
            put_large(&mut o, d);
        }
    }
    o
}

pub fn decode_conn_req(d: &[u8]) -> Result<ConnReqData, String> {
    let mut p = 0usize;
    let agent_v_min = get_u16(d, &mut p)?;
    let agent_v_max = get_u16(d, &mut p)?;
    let n = *d.get(p).ok_or("queues: EOF count")? as usize;
    p += 1;
    let mut queues = Vec::with_capacity(n);
    for _ in 0..n {
        let smp_v_min = get_u16(d, &mut p)?;
        let smp_v_max = get_u16(d, &mut p)?;
        let hosts_n = *d.get(p).ok_or("hosts: EOF")? as usize;
        p += 1;
        let mut hosts = Vec::with_capacity(hosts_n);
        for _ in 0..hosts_n {
            hosts.push(String::from_utf8(get_short(d, &mut p)?).map_err(|e| e.to_string())?);
        }
        let port = String::from_utf8(get_short(d, &mut p)?).map_err(|e| e.to_string())?
            .parse::<u16>().map_err(|e| format!("port: {e}"))?;
        let server_key_hash = get_short(d, &mut p)?;
        let sender_id = get_short(d, &mut p)?;
        let dh_len = *d.get(p).ok_or("dh: EOF len")? as usize;
        p += 1;
        let dh_x509 = d.get(p..p + dh_len).ok_or("dh: EOF body")?.to_vec();
        p += dh_len;
        let queue_mode = *d.get(p).ok_or("queueMode: EOF")?;
        p += 1;
        // Аудит H3: никаких паник на внешних данных (инвайт-URI) — hosts_n==0 даёт ошибку.
        let host = hosts.first().cloned().ok_or("smpQueueUri: пустой список хостов")?;
        queues.push(SmpQueueUri {
            smp_v_min, smp_v_max,
            host,
            port, server_key_hash, sender_id, dh_x509, queue_mode,
        });
    }
    let tag = *d.get(p).ok_or("clientData: EOF")?;
    p += 1;
    let client_data = match tag {
        b'0' => None,
        b'1' => Some(get_large(d, &mut p)?),
        t => return Err(format!("clientData tag: {t:#x}")),
    };
    Ok(ConnReqData { agent_v_min, agent_v_max, queues, client_data })
}

fn b64url_encode(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for chunk in b.chunks(3) {
        let n = chunk.len();
        let v = ((chunk[0] as u32) << 16) | ((*chunk.get(1).unwrap_or(&0) as u32) << 8) | (*chunk.get(2).unwrap_or(&0) as u32);
        s.push(A[(v >> 18) as usize & 63] as char);
        s.push(A[(v >> 12) as usize & 63] as char);
        if n > 1 { s.push(A[(v >> 6) as usize & 63] as char); }
        if n > 2 { s.push(A[v as usize & 63] as char); }
    }
    s
}
fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut vals = Vec::with_capacity(s.len());
    for c in s.chars() {
        let v = match c {
            'A'..='Z' => c as u8 - b'A',
            'a'..='z' => c as u8 - b'a' + 26,
            '0'..='9' => c as u8 - b'0' + 52,
            '-' => 62, '_' => 63,
            _ => return Err(format!("b64url char: {c}")),
        };
        vals.push(v);
    }
    let mut out = Vec::new();
    for chunk in vals.chunks(4) {
        let mut v = (chunk[0] as u32) << 18;
        if chunk.len() > 1 { v |= (chunk[1] as u32) << 12; }
        if chunk.len() > 2 { v |= (chunk[2] as u32) << 6; }
        if chunk.len() > 3 { v |= chunk[3] as u32; }
        out.push((v >> 16) as u8);
        if chunk.len() > 2 { out.push((v >> 8) as u8); }
        if chunk.len() > 3 { out.push(v as u8); }
    }
    Ok(out)
}

/// URI инвайта: `nexx://link#/<b64url(connReqData)>`.
pub fn encode_invite_uri(c: &ConnReqData) -> String {
    format!("nexx://link#/{}", b64url_encode(&encode_conn_req(c)))
}

/// Парсит URI инвайта (nexx://link#/... или голый b64url).
pub fn decode_invite_uri(uri: &str) -> Result<ConnReqData, String> {
    let payload = uri.rsplit('/').next().ok_or("uri: пусто")?;
    let payload = payload.split('#').next().unwrap_or(payload);
    let payload = payload.strip_prefix('/').unwrap_or(payload);
    let raw = if uri.starts_with("nexx://") {
        b64url_decode(uri.split("#/").nth(1).ok_or("uri: нет payload после #/")?)?
    } else {
        b64url_decode(payload)?
    };
    decode_conn_req(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ConnReqData {
        ConnReqData {
            agent_v_min: AGENT_V_MIN,
            agent_v_max: AGENT_V_MAX,
            queues: vec![SmpQueueUri {
                smp_v_min: 20,
                smp_v_max: 20,
                host: "smp6.simplex.im".into(),
                port: 5223,
                server_key_hash: vec![0xAA; 32],
                sender_id: b"snd-queue-id-raw-bytes".to_vec(),
                dh_x509: vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00, 1, 2, 3],
                queue_mode: b'M',
            }],
            client_data: Some(b"display-name=Alice".to_vec()),
        }
    }

    #[test]
    fn conn_req_roundtrip() {
        let c = sample();
        let enc = encode_conn_req(&c);
        let dec = decode_conn_req(&enc).unwrap();
        assert_eq!(c, dec);
    }

    #[test]
    fn invite_uri_roundtrip() {
        let c = sample();
        let uri = encode_invite_uri(&c);
        assert!(uri.starts_with("nexx://link#/"));
        let dec = decode_invite_uri(&uri).unwrap();
        assert_eq!(c, dec);
    }

    #[test]
    fn conn_req_no_client_data() {
        let mut c = sample();
        c.client_data = None;
        let dec = decode_conn_req(&encode_conn_req(&c)).unwrap();
        assert_eq!(dec.client_data, None);
        assert_eq!(dec, c);
    }
}
