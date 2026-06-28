// Vetores-ouro: valores esperados capturados do binário de referência
// `VaultSeed.exe`. Qualquer alteração não-intencional ao core falha aqui.

use crate::core::{build_default_bit_lists, MasterKeyInput};
use crate::{crypto, generator};

fn h32(hexs: &str) -> [u8; 32] {
    hex::decode(hexs).unwrap().try_into().unwrap()
}

fn h24(hexs: &str) -> [u8; 24] {
    hex::decode(hexs).unwrap().try_into().unwrap()
}

const SALT_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const NONCE_HEX: &str = "000102030405060708090a0b0c0d0e0f1011121314151617";
const KEY_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const SEED_HEX: &str = "0202020202020202020202020202020202020202020202020202020202020202";

const DEVICE_UUID: &str = "00000000-0000-0000-0000-000000000001";
const RESTRICTION_UUID: &str = "00000000-0000-0000-0000-000000000002";

#[test]
fn kmac256_fixed_vector() {
    let seed = h32(SEED_HEX);
    let mut out = [0u8; 32];
    crypto::kmac256_xof(&seed, b"v1|ctx|test", &mut out);
    assert_eq!(
        hex::encode(out),
        "3d60d1c3df78ffd4277c97cee813b92f39a55057d409651d16ef1c1871d8a395",
    );
}

#[test]
fn hmac_sha256_fixed_vector() {
    let key = h32(KEY_HEX);
    let mac = crypto::hmac_sha256(&key, b"mensagem-fixa");
    assert_eq!(
        hex::encode(mac),
        "d8f4c1c3d1462ebf504b7276357eda694b931aa70ac5b22cc4f48a0f02473cdf",
    );
}

#[test]
fn hkdf_sha256_fixed_vector() {
    let ikm = h32(KEY_HEX);
    let salt = h32(SALT_HEX);
    let out = crypto::hkdf_extract_expand(&ikm, Some(&salt), b"v1|info", 32);
    assert_eq!(
        hex::encode(out),
        "f6c410f3f0fd9c7140fe0dac2d83ce01be218f9d58ff0b56e15023953cb311db",
    );
}

#[test]
fn xchacha20poly1305_encrypt_fixed_vector() {
    let key = h32(KEY_HEX);
    let nonce = h24(NONCE_HEX);
    let (_, ciphertext) =
        crypto::xchacha20poly1305_encrypt(&key, &nonce, b"segredo", b"v1|aad");
    assert_eq!(
        hex::encode(&ciphertext),
        "0bb5bcf7f8f5b877957cfab752ecbab74ff024686c840a",
    );
}

#[test]
fn xchacha20poly1305_roundtrip_and_tamper() {
    let key = h32(KEY_HEX);
    let nonce = h24(NONCE_HEX);
    let ciphertext = hex::decode("0bb5bcf7f8f5b877957cfab752ecbab74ff024686c840a").unwrap();

    let plaintext =
        crypto::xchacha20poly1305_decrypt(&key, &nonce, &ciphertext, b"v1|aad").unwrap();
    assert_eq!(plaintext, b"segredo");

    assert!(crypto::xchacha20poly1305_decrypt(&key, &nonce, &ciphertext, b"aad-errado").is_err());
}

#[test]
fn argon2id_derive_key_fixed_vector() {
    let salt = h32(SALT_HEX);
    let password = MasterKeyInput::new("alpha".to_string(), "bravo".to_string())
        .normalize_and_concat();
    let key = crypto::derive_key_argon2id(&password, &salt, 65536, 3, 4, 32)
        .expect("parâmetros Argon2 válidos");
    assert_eq!(
        hex::encode(&key),
        "df72b8a863ca388e050ec1b870869bdaa136e62a20fe5ca662380e1ebff05ab0",
    );
}

#[test]
fn derive_kek_session_fixed_vector() {
    let salt = h32(SALT_HEX);
    let kek = crypto::derive_kek_session("alpha", "bravo", &salt, 65536, 3, 4, None, None)
        .unwrap();
    assert_eq!(
        hex::encode(kek),
        "71e7057b80b0523bc3e111c8a61a01b04b3ae0c49c9a343921f6de1f19822312",
    );
}

#[test]
fn build_context_fixed_string() {
    let context = generator::build_context("github.com", 0, DEVICE_UUID, RESTRICTION_UUID);
    assert_eq!(
        context,
        "v1|domain:github.com|variation:0|device:00000000-0000-0000-0000-000000000001|restriction:00000000-0000-0000-0000-000000000002",
    );
}

#[test]
fn generate_entropy_fixed_vector() {
    let seed = h32(SEED_HEX);
    let context = generator::build_context("github.com", 0, DEVICE_UUID, RESTRICTION_UUID);
    let mut entropy = [0u8; 40];
    crypto::kmac256_xof(&seed, context.as_bytes(), &mut entropy);
    assert_eq!(
        hex::encode(entropy),
        "1055c8c5458b2e984a45a55af7c237e0fda9d6c7ea36f75832f404d2fcaaf296c6bdba8656f513b5",
    );
}

#[test]
fn generate_password_end_to_end_fixed_vector() {
    let bit_lists = build_default_bit_lists();
    let masks = generator::build_max_masks(7, &bit_lists, 256);
    assert_eq!(masks.len(), 42, "sequência de máscaras esperada (42 posições)");

    let entropy = hex::decode(
        "1055c8c5458b2e984a45a55af7c237e0fda9d6c7ea36f75832f404d2fcaaf296c6bdba8656f513b5",
    )
    .unwrap();

    let result = generator::generate_password(&entropy, &masks, &bit_lists).unwrap();
    assert_eq!(result.password, "MXixMeSO6QTpk3XBDXZAS0Ui1ICc7PA4sxsUH2YYBJ");
    assert_eq!(result.password.len(), 42);
}

#[test]
fn static_password_key_derivation_fixed_vector() {
    let seed = h32(SEED_HEX);
    let context = "v1|STATIC|00000000-0000-0000-0000-0000000000aa";
    let mut key = [0u8; 32];
    crypto::kmac256_xof(&seed, context.as_bytes(), &mut key);
    assert_eq!(
        hex::encode(key),
        "cd9f1642520b5f1badb05ef8ecb72b620887cf1e8da5ea39bbc331e7b8742d7b",
    );
}
