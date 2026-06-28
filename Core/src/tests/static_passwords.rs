use super::common;

use crate::models::StaticPasswordPlaintext;
use crate::core::MasterKeyInput;

#[test]
fn add_and_get_static_password_ok() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-static".to_string(), "k2-static".to_string());
    let (device_uuid, _restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let plaintext = StaticPasswordPlaintext {
        label: "label-a".to_string(),
        value: "value-a".to_string(),
        notes: "notes".to_string(),
        compromised: false,
    };

    let uuid = vault
        .add_static_password(device_uuid, "/folder", "label-a", plaintext.clone(), &master_key)
        .expect("add static");

    let got = vault.get_static_password(uuid, &master_key).expect("get static");
    assert_eq!(got.label, plaintext.label);
    assert_eq!(got.value, plaintext.value);
    assert_eq!(got.notes, plaintext.notes);
    assert_eq!(got.compromised, plaintext.compromised);
}

#[test]
fn update_static_password_ok() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-update".to_string(), "k2-update".to_string());
    let (device_uuid, _restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let plaintext = StaticPasswordPlaintext {
        label: "label-b".to_string(),
        value: "value-b".to_string(),
        notes: "notes".to_string(),
        compromised: false,
    };

    let uuid = vault
        .add_static_password(device_uuid, "/folder", "label-b", plaintext, &master_key)
        .expect("add static");

    let updated = StaticPasswordPlaintext {
        label: "label-b-new".to_string(),
        value: "value-b-new".to_string(),
        notes: "updated".to_string(),
        compromised: true,
    };

    vault
        .update_static_password(uuid, updated.clone(), &master_key)
        .expect("update static");

    let got = vault.get_static_password(uuid, &master_key).expect("get static");
    assert_eq!(got.label, updated.label);
    assert_eq!(got.value, updated.value);
    assert_eq!(got.notes, updated.notes);
    assert!(got.compromised);
}

#[test]
fn mark_static_password_compromised_sets_flag() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-mark".to_string(), "k2-mark".to_string());
    let (device_uuid, _restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let plaintext = StaticPasswordPlaintext {
        label: "label-c".to_string(),
        value: "value-c".to_string(),
        notes: String::new(),
        compromised: false,
    };

    let uuid = vault
        .add_static_password(device_uuid, "/folder", "label-c", plaintext, &master_key)
        .expect("add static");

    vault
        .mark_static_password_compromised(uuid, &master_key)
        .expect("mark compromised");

    let got = vault.get_static_password(uuid, &master_key).expect("get static");
    assert!(got.compromised);
}

#[test]
fn remove_static_password_ok() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-remove".to_string(), "k2-remove".to_string());
    let (device_uuid, _restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let plaintext = StaticPasswordPlaintext {
        label: "label-d".to_string(),
        value: "value-d".to_string(),
        notes: String::new(),
        compromised: false,
    };

    let uuid = vault
        .add_static_password(device_uuid, "/folder", "label-d", plaintext, &master_key)
        .expect("add static");

    vault.remove_static_password(uuid).expect("remove");

    let err = vault.get_static_password(uuid, &master_key).expect_err("should be gone");
    assert!(matches!(err, crate::errors::CoreError::StaticPassword(crate::errors::StaticPasswordError::UuidNotFound(_))));
}

#[test]
fn rename_and_clear_static_password_folder() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-folder".to_string(), "k2-folder".to_string());
    let (device_uuid, _restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let plaintext = StaticPasswordPlaintext {
        label: "label-e".to_string(),
        value: "value-e".to_string(),
        notes: String::new(),
        compromised: false,
    };

    let _uuid = vault
        .add_static_password(device_uuid, "/old", "label-e", plaintext, &master_key)
        .expect("add static");

    vault
        .rename_static_password_folder(device_uuid, "/old", "/new")
        .expect("rename folder");

    let list = vault.list_static_passwords(device_uuid).expect("list");
    assert!(list.iter().all(|s| s.folder_path == "/new"));

    vault
        .clear_static_password_folder(device_uuid, "/new")
        .expect("clear folder");

    let list2 = vault.list_static_passwords(device_uuid).expect("list");
    assert!(list2.iter().all(|s| s.folder_path.is_empty()));
}

#[test]
fn get_with_wrong_master_key_fails() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-right".to_string(), "k2-right".to_string());
    let wrong = MasterKeyInput::new("k1-wrong".to_string(), "k2-wrong".to_string());
    let (device_uuid, _restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let plaintext = StaticPasswordPlaintext {
        label: "label-f".to_string(),
        value: "value-f".to_string(),
        notes: String::new(),
        compromised: false,
    };

    let uuid = vault
        .add_static_password(device_uuid, "/folder", "label-f", plaintext, &master_key)
        .expect("add static");

    let err = vault.get_static_password(uuid, &wrong).expect_err("wrong key should fail");
    match err {
        crate::errors::CoreError::Device(crate::errors::DeviceError::SeedDecryptionFailed) => {}
        crate::errors::CoreError::StaticPassword(crate::errors::StaticPasswordError::DecryptionFailed) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}
