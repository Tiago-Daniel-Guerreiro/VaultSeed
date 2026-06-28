use crate::tests::common;
use crate::core::MasterKeyInput;
use crate::errors::{CoreError, DeviceError, StaticPasswordError};
use serde_json;
use crate::core::CryptoService;
use zeroize::Zeroize;

#[test]
fn device_seed_aad_mismatch_detected_on_rotate() {
    let vault = common::build_test_vault();
    let old_key = MasterKeyInput::new("aad-k1-old".to_string(), "aad-k2-old".to_string());
    let new_key = MasterKeyInput::new("aad-k1-new".to_string(), "aad-k2-new".to_string());

    let (device_uuid, _restriction_uuid) = common::setup_basic_session(&vault, &old_key);

    let device = {
        let state = vault.read_state();
        let session = state.require_session().expect("session");
        session
            .payload
            .devices
            .iter()
            .find(|d| d.uuid == device_uuid)
            .cloned()
            .expect("device present")
    };

    let mut k_user_bytes = old_key.normalize_and_concat();
    let kek = vault
        .crypto
        .derive_argon2(&k_user_bytes, &device.salt_device, device.argon2.m_cost_kib, device.argon2.t_cost, device.argon2.p_cost)
        .expect("derive kek");
    k_user_bytes.zeroize();

    let seed_plain = vault
        .crypto
        .decrypt_aead(&kek, &device.seed_envelope.nonce, &device.seed_aad(), &device.seed_envelope.ciphertext)
        .expect("decrypt seed ok");

    let wrong_aad = b"v1|seed|device:00000000-0000-0000-0000-000000000000";
    let tampered_cipher = vault
        .crypto
        .encrypt_aead(&kek, &device.seed_envelope.nonce, wrong_aad, &seed_plain)
        .expect("re-encrypt tampered");

    {
        let mut state = vault.write_state();
        let session = state.require_session_mut().expect("session mut");
        if let Some(d) = session.payload.devices.iter_mut().find(|d| d.uuid == device_uuid) {
            d.seed_envelope.ciphertext = tampered_cipher;
        }
    }

    let path = common::unique_temp_session_path("aad-device");
    let res = vault.rotate_master_key(&old_key, &new_key, &path, None);
    assert!(matches!(res.unwrap_err(), CoreError::Device(DeviceError::SeedDecryptionFailed)));
}

#[test]
fn static_password_aad_mismatch_detected_on_get() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("sp-k1".to_string(), "sp-k2".to_string());

    let (device_uuid, _restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let plaintext = crate::models::StaticPasswordPlaintext { label: "lbl".to_string(), value: "secret".to_string(), notes: String::new(), compromised: false };
    let entry_uuid = vault.add_static_password(device_uuid, "/f", "lbl", plaintext.clone(), &master_key).expect("add static");

    let (nonce, _ciphertext) = {
        let state = vault.read_state();
        let session = state.require_session().expect("session");
        let e = session.payload.static_passwords.iter().find(|s| s.uuid == entry_uuid).expect("entry");
        (e.nonce, e.ciphertext.clone())
    };

    let device = vault.get_device(device_uuid).expect("get device");
    let dec = vault.decrypt_device_seed_internal(&device, &master_key).expect("decrypt seed");

    let kmac_context = format!("v1|STATIC|{}", entry_uuid);
    let key_bytes = vault.crypto.derive_kmac256(&dec.seed, &kmac_context, 32).expect("derive kmac");
    let key: [u8; 32] = key_bytes.try_into().expect("key len");

    let wrong_aad = format!("v1|STATIC|senha_estatica:{}|device:{}-tampered", entry_uuid, device_uuid);

    let plaintext_bytes = serde_json::to_vec(&plaintext).expect("serialize plaintext");
    let tampered_cipher = vault.crypto.encrypt_aead(&key, &nonce, wrong_aad.as_bytes(), &plaintext_bytes).expect("encrypt tampered");

    {
        let mut state = vault.write_state();
        let session = state.require_session_mut().expect("session mut");
        if let Some(e) = session.payload.static_passwords.iter_mut().find(|s| s.uuid == entry_uuid) {
            e.ciphertext = tampered_cipher;
        }
    }

    let res = vault.get_static_password(entry_uuid, &master_key);
    assert!(matches!(res.unwrap_err(), CoreError::StaticPassword(StaticPasswordError::DecryptionFailed)));
}
