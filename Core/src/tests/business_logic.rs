use super::common;

use crate::core::MasterKeyInput;
use crate::errors::{CoreError, DomainError, DeviceError, RestrictionError};
use crate::models::{GenerationParams, StaticPasswordPlaintext};

#[test]
fn add_device_rejects_duplicate_name() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-dup-device".to_string(), "k2-dup-device".to_string());
    let (_device_uuid, _restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let err = vault
        .add_device(" device-test ", &master_key)
        .expect_err("duplicate device should fail");

    assert!(matches!(err, CoreError::Device(DeviceError::NameAlreadyExists(name)) if name == " device-test "));
}

#[test]
fn remove_last_device_fails() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-last".to_string(), "k2-last".to_string());
    let (device_uuid, _restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let err = vault
        .remove_device(device_uuid)
        .expect_err("removing last device should fail");

    assert!(matches!(err, CoreError::Device(DeviceError::CannotDeleteLastDevice)));
}

#[test]
fn remove_device_with_restrictions_fails() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-restrict".to_string(), "k2-restrict".to_string());
    let (device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);
    let _second_device = vault.add_device("Device-Second", &master_key).expect("add second device");

    let _ = vault
        .add_restriction("Extra Restriction", device_uuid, GenerationParams::default())
        .expect("add restriction");

    let err = vault
        .remove_device(device_uuid)
        .expect_err("device with restrictions should fail");

    assert!(matches!(err, CoreError::Device(DeviceError::CannotDeleteDeviceWithRestrictions)));
    let _ = restriction_uuid;
}

#[test]
fn select_device_clears_lower_selections() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-select".to_string(), "k2-select".to_string());
    let (device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);
    let domain_uuid = vault.add_domain("Example.com", restriction_uuid).expect("add domain");

    vault.select_restriction(restriction_uuid).expect("select restriction");
    vault.select_domain(domain_uuid).expect("select domain");
    vault.select_device(device_uuid).expect("select device");

    let state = vault.state();
    let state = state.read().unwrap();
    let session = state.session.as_ref().expect("session");

    assert_eq!(session.selected_device, Some(device_uuid));
    assert!(session.selected_restriction.is_none());
    assert!(session.selected_domain.is_none());
}

#[test]
fn add_restriction_duplicate_name_fails() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-restrict-dup".to_string(), "k2-restrict-dup".to_string());
    let (device_uuid, _restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let err = vault
        .add_restriction("PADRÃO", device_uuid, GenerationParams::default())
        .expect_err("duplicate restriction should fail");

    assert!(matches!(err, CoreError::Restriction(RestrictionError::NameAlreadyExists(name)) if name == "PADRÃO"));
}

#[test]
fn add_char_list_bit_abaixo_user_min_returns_occupied() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-charlist".to_string(), "k2-charlist".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let err = vault
        .add_char_list_to_restriction(restriction_uuid, "custom", 15, vec!["x".to_string()])
        .expect_err("bit 15 should be treated as occupied by reserved range");

    assert!(matches!(err, CoreError::Device(DeviceError::CharListBitOccupied(15))));
}

#[test]
fn add_domain_duplicate_identifier_fails() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-domain-dup".to_string(), "k2-domain-dup".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let _ = vault.add_domain("Example.com", restriction_uuid).expect("add first domain");

    let err = vault
        .add_domain("example.com", restriction_uuid)
        .expect_err("duplicate domain should fail");

    assert!(matches!(err, CoreError::Domain(DomainError::IdentifierAlreadyExists(name)) if name == "example.com"));
}

#[test]
fn change_domain_restriction_device_mismatch_fails() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-domain-mismatch".to_string(), "k2-domain-mismatch".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);
    let second_device = vault.add_device("Device-Second", &master_key).expect("add second device");
    let second_restriction = vault
        .add_restriction("Secondary", second_device, GenerationParams::default())
        .expect("add second restriction");

    let domain_uuid = vault.add_domain("example.org", restriction_uuid).expect("add domain");

    let err = vault
        .change_domain_restriction(domain_uuid, second_restriction)
        .expect_err("cross-device restriction change should fail");

    assert!(matches!(err, CoreError::Domain(DomainError::RestrictionDeviceMismatch)));
}

#[test]
fn static_password_update_and_compromise_stay_consistent() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-static".to_string(), "k2-static".to_string());
    let (device_uuid, _restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let plaintext = StaticPasswordPlaintext {
        label: "site-a".to_string(),
        value: "initial-value".to_string(),
        notes: "initial-notes".to_string(),
        compromised: false,
    };

    let entry_uuid = vault
        .add_static_password(device_uuid, "folder-a", &plaintext.label, plaintext.clone(), &master_key)
        .expect("add static password");

    let fetched = vault.get_static_password(entry_uuid, &master_key).expect("get static password");
    assert_eq!(fetched, plaintext);

    let updated = StaticPasswordPlaintext {
        label: "site-b".to_string(),
        value: "updated-value".to_string(),
        notes: "updated-notes".to_string(),
        compromised: true,
    };

    vault
        .update_static_password(entry_uuid, updated.clone(), &master_key)
        .expect("update static password");

    let fetched_updated = vault
        .get_static_password(entry_uuid, &master_key)
        .expect("get updated static password");
    assert_eq!(fetched_updated, updated);

    let stored = vault
        .list_static_passwords(device_uuid)
        .expect("list static passwords")
        .into_iter()
        .find(|entry| entry.uuid == entry_uuid)
        .expect("stored entry");

    assert!(stored.compromised);

    vault
        .mark_static_password_compromised(entry_uuid, &master_key)
        .expect("mark compromised");

    let fetched_compromised = vault
        .get_static_password(entry_uuid, &master_key)
        .expect("get compromised static password");
    assert!(fetched_compromised.compromised);

    let stored_compromised = vault
        .list_static_passwords(device_uuid)
        .expect("list compromised static passwords")
        .into_iter()
        .find(|entry| entry.uuid == entry_uuid)
        .expect("stored compromised entry");

    assert!(stored_compromised.compromised);
    assert_eq!(fetched_compromised, updated);
}
