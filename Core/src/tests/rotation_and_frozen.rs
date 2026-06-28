use super::common;

use crate::core::{MasterKeyInput, PasswordRequest};
use crate::core::FileService;
use crate::models::{MaskOrLiteral};

#[test]
fn rotate_master_key_preserves_password_generation_and_invalidates_old_key() {
    let vault = common::build_test_vault();
    let old_key = MasterKeyInput::new("k1-old".to_string(), "k2-old".to_string());
    let new_key = MasterKeyInput::new("k1-new".to_string(), "k2-new".to_string());
    let (device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &old_key);
    let domain_uuid = vault
        .add_domain("rotate.example", restriction_uuid)
        .expect("add domain");
    let path = common::unique_temp_session_path("rotate_master_key");

    vault
        .save_session(&path, &old_key, None, true)
        .expect("save original session");

    let before = vault
        .generate_password(
            PasswordRequest {
                domain_uuid,
                forced_variation: Some(0),
            },
            &old_key,
        )
        .expect("generate before rotation");

    vault
        .rotate_master_key(&old_key, &new_key, &path, None)
        .expect("rotate master key");

    let after = vault
        .generate_password(
            PasswordRequest {
                domain_uuid,
                forced_variation: Some(0),
            },
            &new_key,
        )
        .expect("generate after rotation");

    assert_eq!(before.password, after.password);
    assert_eq!(before.variation, after.variation);
    assert_eq!(before.domain_uuid, after.domain_uuid);

    vault.close_session().expect("close rotated session");

    let rotated_file = vault.files.load_session_file(&path).expect("load rotated session file");

    let old_key_err = vault
        .open_session(rotated_file.clone(), &old_key, None, true)
        .expect_err("old key should fail after rotation");
    assert!(matches!(old_key_err, crate::errors::CoreError::Session(crate::errors::SessionError::WrongSessionKey)));

    vault
        .open_session(rotated_file, &new_key, None, true)
        .expect("new key should open rotated session");

    let decrypted = vault
        .generate_password(
            PasswordRequest {
                domain_uuid,
                forced_variation: Some(0),
            },
            &new_key,
        )
        .expect("generate after reopen");

    assert_eq!(before.password, decrypted.password);
    let _ = device_uuid;
    let _ = std::fs::remove_file(&path);
}

#[test]
fn frozen_password_reproduces_original_after_restriction_changed() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-frozen".to_string(), "k2-frozen".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);
    let domain_uuid = vault
        .add_domain("frozen.example", restriction_uuid)
        .expect("add domain");

    let original = vault
        .generate_password(
            PasswordRequest {
                domain_uuid,
                forced_variation: Some(0),
            },
            &master_key,
        )
        .expect("generate original password");

    vault
        .mark_domain_compromised(domain_uuid, 0, &master_key)
        .expect("freeze current password");

    vault
        .add_char_list_to_restriction(
            restriction_uuid,
            "extra",
            16,
            vec!["x".to_string(), "y".to_string()],
        )
        .expect("add extra char list");

    vault
        .insert_restriction_mask_position(restriction_uuid, 16, 0)
        .expect("change active format");

    let frozen = vault
        .generate_password_from_frozen(domain_uuid, 0, &master_key)
        .expect("generate frozen password");

    assert_eq!(frozen.password, original.password);
    assert_eq!(frozen.domain_uuid, domain_uuid);
    assert_eq!(frozen.variation, 0);

    let active = vault.generate_password(
        PasswordRequest { domain_uuid, forced_variation: Some(0) },
        &master_key,
    );
    assert!(matches!(
        active,
        Err(crate::errors::CoreError::Password(crate::errors::PasswordError::EmptyAlphabet))
    ));

    let _ = MaskOrLiteral::Mask(16);
}