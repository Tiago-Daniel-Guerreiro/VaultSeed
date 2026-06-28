use crate::core::MasterKeyInput;

use super::common;

#[test]
fn mk_concat_is_order_independent_by_design() {
    let ascending = MasterKeyInput::new("beta".to_string(), "alfa".to_string());
    let descending = MasterKeyInput::new("alfa".to_string(), "beta".to_string());

    let ascending_bytes = ascending.normalize_and_concat();
    let descending_bytes = descending.normalize_and_concat();

    assert_eq!(ascending_bytes, descending_bytes);
    assert_eq!(ascending_bytes, b"alfabeta".to_vec());
}

#[test]
fn mk_concat_nfc_normalizes_combining_characters() {
    let input = MasterKeyInput::new("a\u{0301}".to_string(), "b".to_string());

    assert_eq!(input.normalize_and_concat(), "bá".as_bytes());
}

#[test]
fn mk_validate_ambos_vazios() {
    let input = MasterKeyInput::new(String::new(), String::new());
    let err = input.validate().expect_err("empty keys should fail");
    assert!(format!("{err}").contains("K1 e K2 não podem estar ambos vazios"));
}

#[test]
fn mk_validate_exatamente_no_limite() {
    let input = MasterKeyInput::new("x".repeat(1024), "y".repeat(1024));
    input.validate().expect("boundary keys should pass");
}

#[test]
fn mk_concat_ambos_vazios_apos_trim() {
    let input = MasterKeyInput::new("   ".to_string(), "   ".to_string());
    assert_eq!(input.normalize_and_concat(), Vec::<u8>::new());
}

#[test]
fn canonicalize_name_used_by_device_and_restriction_defaults() {
    let _ = common::build_test_vault();
    let device_name = crate::models::Device::new(
        "  LAPTOP  ",
        [0u8; 32],
        crate::models::Argon2Params { m_cost_kib: 1, t_cost: 1, p_cost: 1 },
        crate::models::SeedEnvelope { nonce: [0u8; 24], ciphertext: vec![] },
    )
    .name;

    assert_eq!(device_name, "laptop");
}
