use super::common;
use crate::core::FileService;

use crate::core::MasterKeyInput;
use crate::errors::{CoreError, SessionError};
use crate::models::Argon2Params;

#[test]
fn open_session_distinguishes_hmac_mismatch_from_wrong_key() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-open".to_string(), "k2-open".to_string());
    let wrong_key = MasterKeyInput::new("wrong-k1".to_string(), "wrong-k2".to_string());
    let path = common::unique_temp_session_path("hmac_vs_key");

    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);
    vault.add_domain("hmac.example", restriction_uuid).expect("add domain");

    vault.save_session(&path, &master_key, None, true).expect("save with hmac");
    vault.close_session().expect("close session");

    let original = vault.files.load_session_file(&path).expect("load session file");

    let wrong_key_err = vault
        .open_session(original.clone(), &wrong_key, None, true)
        .expect_err("wrong key should fail");
    assert!(matches!(wrong_key_err, CoreError::Session(SessionError::WrongSessionKey)));

    let mut tampered = original.clone();
    let mut hmac = tampered.session_hmac.expect("hmac should exist");
    hmac[0] ^= 0xFF;
    tampered.session_hmac = Some(hmac);

    let tampered_err = vault
        .open_session(tampered.clone(), &master_key, None, true)
        .expect_err("tampered hmac should fail");
    assert!(matches!(tampered_err, CoreError::Session(SessionError::SessionFileTampered)));

    vault.open_session(tampered, &master_key, None, false).expect("open without hmac verification");

    let _ = vault.close_session();
}

#[test]
fn create_session_twice_fails_already_open() {
    let vault = common::build_test_vault();
    let argon = Argon2Params {
        m_cost_kib: 1024,
        t_cost: 2,
        p_cost: 1,
    };

    vault
        .create_new_session([7u8; 32], argon.clone(), false, None)
        .expect("first session");

    let err = vault
        .create_new_session([7u8; 32], argon, false, None)
        .expect_err("second session should fail");

    assert!(matches!(err, CoreError::Session(SessionError::SessionAlreadyOpen)));
}

#[test]
fn operations_without_session_return_not_open() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-nosession".to_string(), "k2-nosession".to_string());

    let err = vault
        .add_device("Device-Test", &master_key)
        .expect_err("add_device without session should fail");

    assert!(matches!(err, CoreError::Session(SessionError::SessionNotOpen)));
}

#[test]
fn build_kek_hardware_not_configured() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-kext".to_string(), "k2-kext".to_string());
    let argon = Argon2Params {
        m_cost_kib: 1024,
        t_cost: 2,
        p_cost: 1,
    };

    vault
        .create_new_session([7u8; 32], argon, true, None)
        .expect("create hardware session");

    let path = common::unique_temp_session_path("hardware_not_configured");

    let err = vault
        .save_session(&path, &master_key, Some(&[9u8; 32]), true)
        .expect_err("missing salt_hkdf should fail");

    assert!(matches!(err, CoreError::Session(SessionError::HardwareNotConfigured)));
}

#[test]
fn rotate_kext_sem_salt_hkdf_falha() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-rotate".to_string(), "k2-rotate".to_string());
    let argon = Argon2Params {
        m_cost_kib: 1024,
        t_cost: 2,
        p_cost: 1,
    };

    vault
        .create_new_session([7u8; 32], argon, false, None)
        .expect("create session");

    let path = common::unique_temp_session_path("rotate_kext_missing_salt");

    let err = vault
        .rotate_kext(&master_key, Some(&[8u8; 32]), None, &path)
        .expect_err("missing salt_hkdf should fail during rotate_kext");

    assert!(matches!(err, CoreError::Session(SessionError::HardwareNotConfigured)));
}

#[test]
fn rotate_kext_activa_hardware_with_salt_hkdf() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-rotate-ok".to_string(), "k2-rotate-ok".to_string());
    let argon = Argon2Params {
        m_cost_kib: 1024,
        t_cost: 2,
        p_cost: 1,
    };

    vault
        .create_new_session([7u8; 32], argon, false, None)
        .expect("create session");

    let path = common::unique_temp_session_path("rotate_kext_ok");

    vault
        .rotate_kext(&master_key, Some(&[8u8; 32]), Some([9u8; 32]), &path)
        .expect("rotate kext with salt should succeed");

    assert!(vault.is_session_hardware_enabled().expect("hardware flag"));
}

#[test]
fn device_seed_envelope_round_trip_uses_device_aad() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-seed".to_string(), "k2-seed".to_string());
    let argon = Argon2Params {
        m_cost_kib: 1024,
        t_cost: 2,
        p_cost: 1,
    };
    let device_uuid = uuid::Uuid::new_v4();
    let salt_device = [11u8; 32];
    let seed = [22u8; 32];

    vault
        .create_new_session([9u8; 32], argon.clone(), false, None)
        .expect("create session");

    let envelope = vault
        .encrypt_device_seed_envelope(device_uuid, &salt_device, &argon, &master_key, &seed)
        .expect("encrypt envelope");

    let decrypted = vault
        .decrypt_device_seed_envelope(device_uuid, &salt_device, &argon, &master_key, &envelope)
        .expect("decrypt envelope");

    assert_eq!(decrypted, seed);
}
