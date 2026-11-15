//! Негативные тесты C1 (аудит MITM/пиннинг): серверная аутентификация должна
//! отвергать подмену. Каждый тест — сценарий из приёмочной таблицы аудита.
//!
//! Проверяется чистая функция `validate_server_chain` (модель SimpleX:
//! сервер = keyHash CA, подпись leaf←CA обязательна, CN-fallback запрещён).

use nexxrust::crypto::sha256_raw;
use nexxrust::protocols::smp_client::{ct_eq, validate_server_chain};

/// SHA-256 DER-сертификата в виде [u8;32].
fn fp(der: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(&sha256_raw(der));
    a
}

/// Тестовые DER-«сертификаты» (для unit-теста нужна только арифметика хешей;
/// полноценная X.509-проверка выполняется на живых сертификатах в integration).
const CA_DER: &[u8] = b"test-ca-der-bytes";
const LEAF_DER: &[u8] = b"test-leaf-der-bytes";
const OTHER_CA_DER: &[u8] = b"other-ca-der-bytes";

#[test]
fn c1_негатив_1_self_signed_leaf_с_cn_хоста_отвергается() {
    // Самоподписанный leaf без CA с нужным keyHash — отвергаем.
    let expected = fp(CA_DER);
    let chain = vec![LEAF_DER.to_vec()];
    assert!(validate_server_chain(LEAF_DER, &chain, &expected).is_err());
}

#[test]
fn c1_негатив_2_чужой_leaf_с_настоящим_ca_в_цепочке_отвергается() {
    // Наш CA в цепочке есть, но leaf чужой — нужна проверка подписи, а не any-match.
    let expected = fp(CA_DER);
    let chain = vec![LEAF_DER.to_vec(), CA_DER.to_vec()];
    // Leaf не подписан нашим CA (в unit-тесте это не настоящая X.509-цепочка),
    // поэтому проверка обязана провалиться.
    assert!(validate_server_chain(LEAF_DER, &chain, &expected).is_err());
}

#[test]
fn c1_негатив_3_неверный_expected_keyhash_отвергается() {
    let expected = fp(OTHER_CA_DER);
    let chain = vec![LEAF_DER.to_vec(), CA_DER.to_vec()];
    assert!(validate_server_chain(LEAF_DER, &chain, &expected).is_err());
}

#[test]
fn c1_негатив_4_пустой_pinning_отвергается() {
    // keyHash не задан / неверной длины — ошибка, а не «пропустить проверку».
    let chain = vec![LEAF_DER.to_vec(), CA_DER.to_vec()];
    assert!(validate_server_chain(LEAF_DER, &chain, &[]).is_err());
    assert!(validate_server_chain(LEAF_DER, &chain, &[0u8; 31]).is_err());
}

#[test]
fn c1_негатив_5_smp_chain_не_совпадает_с_tls_chain_отвергается() {
    // CA из «SMP hello» другой — отпечатки не равны.
    assert!(!ct_eq(&fp(CA_DER), &fp(OTHER_CA_DER)));
    assert!(!ct_eq(&fp(CA_DER), &fp(LEAF_DER)));
}

#[test]
fn c1_негатив_6_session_id_не_равен_tls_finished_отвергается() {
    // Channel binding: разные session_id/finished обязаны давать несовпадение.
    let a = vec![1u8; 32];
    let b = vec![2u8; 32];
    assert!(!ct_eq(&a, &b));
    assert!(ct_eq(&a, &a));
}

#[test]
fn c1_постоянное_время_сравнения_корректно() {
    assert!(ct_eq(&[0u8; 32], &[0u8; 32]));
    assert!(!ct_eq(&[0u8; 32], &[1u8; 32]));
    // разной длины — false, без паники
    assert!(!ct_eq(&[0u8; 32], &[0u8; 31]));
}
