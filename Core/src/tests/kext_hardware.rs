use crate::core::MasterKeyInput;
use crate::services::generator::GeneratorServiceImpl;
use crate::services::crypto::CryptoServiceImpl;
use crate::services::file::FileServiceImpl;
use crate::models::{Argon2Params, LocalState, SessionFile};
use crate::errors::{CoreError, SessionError};
use crate::core::FileService;

fn unique_path(label: &str) -> String {
    std::env::temp_dir()
        .join(format!("vaultseed_kext_{}_{}.vaultseed", label, uuid::Uuid::new_v4()))
        .to_string_lossy()
        .to_string()
}

#[test]
fn open_session_requires_kext_when_hardware_enabled() {
    let vault = crate::core::VaultCore::new(
        LocalState::new(),
        CryptoServiceImpl::new(),
        GeneratorServiceImpl::new(),
        FileServiceImpl::new(),
        false,
    );

    let master_key = MasterKeyInput::new("hk-k1".to_string(), "hk-k2".to_string());

    let argon = Argon2Params { m_cost_kib: 1024, t_cost: 2, p_cost: 1 };

    let salt_hkdf = [0x11u8; 32];
    vault.create_new_session([8u8; 32], argon, true, Some(salt_hkdf)).expect("create session hw");

    let device_uuid = vault.add_device("HwDevice", &master_key).expect("add device");
    let restriction_uuid = vault.list_restrictions(device_uuid).expect("list restrictions").first().unwrap().uuid;
    let _ = vault.add_domain("kext.example", restriction_uuid).expect("add domain");

    let path = unique_path("require_kext");
    let k_ext = [0x22u8; 32];
    vault.save_session(&path, &master_key, Some(&k_ext), true).expect("save session with k_ext");

    let session_file = vault.files.load_session_file(&path).expect("load saved");
    vault.close_session().expect("close saved session before reopen");

    let err = vault.open_session(session_file.clone(), &master_key, None, true).expect_err("open without k_ext should fail");
    assert!(matches!(err, CoreError::Session(SessionError::HardwareRequired)));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn open_session_fails_if_salt_hkdf_missing() {
    let header = crate::models::SessionHeader {
        schema_version: 1,
        salt_session: [0u8; 32],
        argon2: Argon2Params { m_cost_kib: 1024, t_cost: 2, p_cost: 1 },
        hardware_enabled: true,
        salt_hkdf: None,
    };

    let session_file = SessionFile { header, nonce_global: [0u8;24], ciphertext_global: Vec::new(), session_hmac: None };

    let vault = crate::core::VaultCore::new(
        LocalState::new(),
        CryptoServiceImpl::new(),
        GeneratorServiceImpl::new(),
        FileServiceImpl::new(),
        false,
    );

    let master_key = MasterKeyInput::new("hk-k1".to_string(), "hk-k2".to_string());

    let k_ext = [0x33u8; 32];
    let err = vault.open_session(session_file, &master_key, Some(&k_ext), true).expect_err("open should fail due missing salt_hkdf");
    assert!(matches!(err, CoreError::Session(SessionError::HardwareNotConfigured)));
}

#[test]
fn open_session_succeeds_with_kext_and_salt_hkdf() {
    let vault = crate::core::VaultCore::new(
        LocalState::new(),
        CryptoServiceImpl::new(),
        GeneratorServiceImpl::new(),
        FileServiceImpl::new(),
        false,
    );

    let master_key = MasterKeyInput::new("hk2-k1".to_string(), "hk2-k2".to_string());
    let argon = Argon2Params { m_cost_kib: 1024, t_cost: 2, p_cost: 1 };

    let salt_hkdf = [0x44u8; 32];
    vault.create_new_session([9u8; 32], argon, true, Some(salt_hkdf)).expect("create session hw");

    let device_uuid = vault.add_device("HwDevice2", &master_key).expect("add device");
    let restriction_uuid = vault.list_restrictions(device_uuid).expect("list restrictions").first().unwrap().uuid;
    let _ = vault.add_domain("kext2.example", restriction_uuid).expect("add domain");

    let path = unique_path("succeed_kext");
    let k_ext = [0x55u8; 32];
    vault.save_session(&path, &master_key, Some(&k_ext), true).expect("save session with k_ext");

    let session_file = vault.files.load_session_file(&path).expect("load saved");
    vault.close_session().expect("close saved session before reopen");

    vault.open_session(session_file, &master_key, Some(&k_ext), true).expect("open with k_ext should succeed");

    let _ = std::fs::remove_file(&path);
}
