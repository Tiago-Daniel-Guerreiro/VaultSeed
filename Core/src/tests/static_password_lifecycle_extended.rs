use super::common;
use crate::core::MasterKeyInput;
use crate::models::StaticPasswordPlaintext;

#[test]
fn rename_nonexistent_folder_returns_error() {
    let vault = common::build_test_vault();
    let master = MasterKeyInput::new("k1-ext".to_string(), "k2-ext".to_string());
    let (device_uuid, _r) = common::setup_basic_session(&vault, &master);

    let err = vault
        .rename_static_password_folder(device_uuid, "/nope", "/new")
        .expect_err("should fail");

    assert!(matches!(err, crate::errors::CoreError::StaticPassword(crate::errors::StaticPasswordError::NotFound(_))));
}

#[test]
fn clear_nonexistent_folder_returns_error() {
    let vault = common::build_test_vault();
    let master = MasterKeyInput::new("k1-ext2".to_string(), "k2-ext2".to_string());
    let (device_uuid, _r) = common::setup_basic_session(&vault, &master);

    let err = vault
        .clear_static_password_folder(device_uuid, "/no-folder")
        .expect_err("should fail");

    assert!(matches!(err, crate::errors::CoreError::StaticPassword(crate::errors::StaticPasswordError::NotFound(_))));
}

#[test]
fn rename_affects_only_target_device() {
    let vault = common::build_test_vault();
    let master = MasterKeyInput::new("k1-same".to_string(), "k2-same".to_string());
    let (device_a, _r) = common::setup_basic_session(&vault, &master);

    let device_b = vault.add_device("OtherDevice", &master).expect("add device");

    let plaintext = StaticPasswordPlaintext {
        label: "lab".to_string(),
        value: "val".to_string(),
        notes: String::new(),
        compromised: false,
    };

    let _u1 = vault.add_static_password(device_a, "/shared", "a1", plaintext.clone(), &master).expect("add a");
    let _u2 = vault.add_static_password(device_b, "/shared", "b1", plaintext, &master).expect("add b");

    vault.rename_static_password_folder(device_a, "/shared", "/moved").expect("rename");

    let la = vault.list_static_passwords(device_a).expect("list a");
    assert!(la.iter().all(|s| s.folder_path == "/moved"));

    let lb = vault.list_static_passwords(device_b).expect("list b");
    assert!(lb.iter().all(|s| s.folder_path == "/shared"));
}
