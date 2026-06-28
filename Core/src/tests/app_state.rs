use super::common;

use crate::core::{AppState, MasterKeyInput, SessionRuntime};
use crate::errors::SessionError;
use crate::models::{Argon2Params, LocalState, SessionFile, SessionHeader, SessionPayload};

#[test]
fn appstate_has_open_session_false() {
    let state = AppState::new(LocalState::new());
    assert!(!state.has_open_session());
}

#[test]
fn appstate_has_open_session_true() {
    let mut state = AppState::new(LocalState::new());
    state.session = Some(SessionRuntime::new(
        SessionFile {
            header: SessionHeader::new([7u8; 32], Argon2Params { m_cost_kib: 1, t_cost: 1, p_cost: 1 }, false, None),
            nonce_global: [0u8; 24],
            ciphertext_global: Vec::new(),
            session_hmac: None,
        },
        SessionPayload::new(),
    ));

    assert!(state.has_open_session());
}

#[test]
fn appstate_require_session_sem_sessao() {
    let state = AppState::new(LocalState::new());
    let err = state.require_session().expect_err("no session should fail");
    assert!(matches!(err, SessionError::SessionNotOpen));
}

#[test]
fn appstate_require_session_mut_sem_sessao() {
    let mut state = AppState::new(LocalState::new());
    let err = state.require_session_mut().expect_err("no session should fail");
    assert!(matches!(err, SessionError::SessionNotOpen));
}

#[test]
fn session_clear_selection_apaga_tudo() {
    let mut session = SessionRuntime::new(
        SessionFile {
            header: SessionHeader::new([7u8; 32], Argon2Params { m_cost_kib: 1, t_cost: 1, p_cost: 1 }, false, None),
            nonce_global: [0u8; 24],
            ciphertext_global: Vec::new(),
            session_hmac: None,
        },
        SessionPayload::new(),
    );

    session.selected_device = Some(uuid::Uuid::new_v4());
    session.selected_restriction = Some(uuid::Uuid::new_v4());
    session.selected_domain = Some(uuid::Uuid::new_v4());

    session.clear_selection();

    assert!(session.selected_device.is_none());
    assert!(session.selected_restriction.is_none());
    assert!(session.selected_domain.is_none());
}

#[test]
fn create_session_ok() {
    let vault = common::build_test_vault();

    vault
        .create_new_session(
            [7u8; 32],
            Argon2Params { m_cost_kib: 1024, t_cost: 2, p_cost: 1 },
            false,
            None,
        )
        .expect("create session");

    assert!(vault.get_session_header().is_ok());
}

#[test]
fn create_session_ja_aberta() {
    let vault = common::build_test_vault();

    vault
        .create_new_session(
            [7u8; 32],
            Argon2Params { m_cost_kib: 1024, t_cost: 2, p_cost: 1 },
            false,
            None,
        )
        .expect("create session");

    let err = vault
        .create_new_session(
            [8u8; 32],
            Argon2Params { m_cost_kib: 1024, t_cost: 2, p_cost: 1 },
            false,
            None,
        )
        .expect_err("second session should fail");

    assert!(matches!(err, crate::errors::CoreError::Session(SessionError::SessionAlreadyOpen)));
}

#[test]
fn get_overview_sem_sessao() {
    let vault = common::build_test_vault();
    let err = vault.get_session_overview().expect_err("no session");
    assert!(matches!(err, crate::errors::CoreError::Session(SessionError::SessionNotOpen)));
}

#[test]
fn get_overview_counts_corretos() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-overview".to_string(), "k2-overview".to_string());
    let (device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let d2 = vault.add_device("device-two", &master_key).expect("add second device");
    let r2 = vault
        .add_restriction("restriction-two", d2, crate::models::GenerationParams::default())
        .expect("add second restriction");
    let d3 = vault.add_device("device-three", &master_key).expect("add third device");
    let r3 = vault
        .add_restriction("restriction-three", d3, crate::models::GenerationParams::default())
        .expect("add third restriction");

    let _ = vault.add_domain("one.example", restriction_uuid).expect("add domain 1");
    let _ = vault.add_domain("two.example", r2).expect("add domain 2");
    let _ = vault.add_domain("three.example", r3).expect("add domain 3");
    let _ = vault
        .add_static_password(device_uuid, "folder", "label", crate::models::StaticPasswordPlaintext { label: "label".to_string(), value: "value".to_string(), notes: String::new(), compromised: false }, &master_key)
        .expect("add static password");

    let overview = vault.get_session_overview().expect("overview");
    assert_eq!(overview.device_count, 3);
    // Each device has a default restriction created during `add_device`,
    // so expected count = initial default + default for d2 + added r2 + default for d3 + added r3 = 5
    assert_eq!(overview.restriction_count, 5);
    assert_eq!(overview.domain_count, 3);
    assert_eq!(overview.static_password_count, 1);
}

#[test]
fn hardware_enabled_false() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-hw".to_string(), "k2-hw".to_string());
    common::setup_basic_session(&vault, &master_key);

    assert_eq!(vault.is_session_hardware_enabled().expect("flag"), false);
}

#[test]
fn hardware_enabled_true() {
    let vault = common::build_test_vault();
    vault
        .create_new_session(
            [7u8; 32],
            Argon2Params { m_cost_kib: 1024, t_cost: 2, p_cost: 1 },
            true,
            Some([9u8; 32]),
        )
        .expect("create hardware session");

    assert!(vault.is_session_hardware_enabled().expect("flag"));
}

#[test]
fn hardware_enabled_sem_sessao() {
    let vault = common::build_test_vault();
    let err = vault.is_session_hardware_enabled().expect_err("no session");
    assert!(matches!(err, crate::errors::CoreError::Session(SessionError::SessionNotOpen)));
}