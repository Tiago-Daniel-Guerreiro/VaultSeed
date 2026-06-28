use crate::core::MasterKeyInput;
use crate::services::generator::GeneratorServiceImpl;
use crate::services::crypto::CryptoServiceImpl;
use crate::services::file::FileServiceImpl;
use crate::models::{Argon2Params, LocalState};
use crate::errors::{CoreError, SessionError};
use crate::core::FileService;

#[test]
fn session_hmac_and_wrong_key_behavior() {
    let vault = crate::core::VaultCore::new(
        LocalState::new(),
        CryptoServiceImpl::new(),
        GeneratorServiceImpl::new(),
        FileServiceImpl::new(),
        false,
    );

    let correct = MasterKeyInput::new("mk1".to_string(), "mk2".to_string());
    let wrong = MasterKeyInput::new("bad1".to_string(), "bad2".to_string());

    let argon = Argon2Params { m_cost_kib: 1024, t_cost: 2, p_cost: 1 };
    vault.create_new_session([3u8;32], argon, false, None).expect("create session");

    let path = std::env::temp_dir().join(format!("vaultseed_hmac_{}.vaultseed", uuid::Uuid::new_v4())).to_string_lossy().to_string();

    vault.save_session(&path, &correct, None, true).expect("save with hmac");

    let session_file = vault.files.load_session_file(&path).expect("load saved session");
    vault.close_session().expect("close saved session before reopen");

    let err = vault.open_session(session_file.clone(), &wrong, None, true).expect_err("open with wrong key should fail");
    assert!(matches!(err, CoreError::Session(SessionError::WrongSessionKey)));

    let mut tampered = session_file.clone();
    tampered.session_hmac = Some([0xFFu8; 32]);

    let err2 = vault.open_session(tampered, &correct, None, true).expect_err("open with tampered hmac should fail");
    assert!(matches!(err2, CoreError::Session(SessionError::SessionFileTampered)));

    let _ = std::fs::remove_file(&path);
}
