use crate::core::{MasterKeyInput, PasswordRequest, VaultCore};
use crate::core::FileService;
use crate::services::generator::GeneratorServiceImpl;
use crate::models::{Argon2Params, LocalState};
use crate::services::crypto::CryptoServiceImpl;
use crate::services::file::FileServiceImpl;

#[test]
fn rotate_master_key_integration_real_crypto() {
    let vault = VaultCore::new(
        LocalState::new(),
        CryptoServiceImpl::new(),
        GeneratorServiceImpl::new(),
        FileServiceImpl::new(),
        false,
    );

    let old_key = MasterKeyInput::new("int-k1-old".to_string(), "int-k2-old".to_string());
    let new_key = MasterKeyInput::new("int-k1-new".to_string(), "int-k2-new".to_string());

    let argon = Argon2Params {
        m_cost_kib: 1024,
        t_cost: 2,
        p_cost: 1,
    };

    vault
        .create_new_session([7u8; 32], argon, false, None)
        .expect("create session");

    let device_uuid = vault.add_device("Device-Integration", &old_key).expect("add device");
    let restriction_uuid = vault
        .list_restrictions(device_uuid)
        .expect("list restrictions")
        .first()
        .expect("default restriction")
        .uuid;

    let domain_uuid = vault
        .add_domain("rotate.integration.example", restriction_uuid)
        .expect("add domain");

    let path = std::env::temp_dir()
        .join(format!("vaultseed_rotate_integration_{}.vaultseed", uuid::Uuid::new_v4()))
        .to_string_lossy()
        .to_string();

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

    let _ = std::fs::remove_file(&path);
}
