use crate::models::GenerationParams;
use crate::core::MasterKeyInput;
use crate::tests::common;
use std::sync::{Arc, Mutex};
use std::thread;

#[test]
fn concurrent_add_remove_restrictions_and_domains() {
    let vault = Arc::new(common::build_test_vault());
    let master = MasterKeyInput::new("k1-conc".to_string(), "k2-conc".to_string());
    let (device_uuid, _r) = common::setup_basic_session(&vault, &master);

    let created = Arc::new(Mutex::new(Vec::new()));

    let mut handles = Vec::new();
    for t in 0..6 {
        let vault = Arc::clone(&vault);
        let created = Arc::clone(&created);
        let handle = thread::spawn(move || {
            for i in 0..50 {
                let name = format!("conc-r-{}-{}", t, i);
                let res = vault.add_restriction(&name, device_uuid, GenerationParams::default());
                if let Ok(uuid) = res {
                    created.lock().unwrap().push(uuid);
                    let _ = vault.add_domain(&format!("d-{}-{}", t, i), uuid);
                }
            }
        });
        handles.push(handle);
    }

    for _ in 0..4 {
        let vault = Arc::clone(&vault);
        let created = Arc::clone(&created);
        let handle = thread::spawn(move || {
            for _ in 0..60 {
                let opt = created.lock().unwrap().pop();
                if let Some(uuid) = opt {
                    let _ = vault.remove_restriction(uuid);
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.join();
    }

    let list = vault.list_restrictions(device_uuid).expect("list restrictions");
    assert!(list.iter().all(|r| r.device_uuid == device_uuid));
}
