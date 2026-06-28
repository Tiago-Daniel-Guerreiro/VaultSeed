use std::thread;
use std::time::Duration;

use crate::tests::common;
use crate::core::MasterKeyInput;

#[test]
fn lock_poison_recovery_via_helpers() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("lock-k1".to_string(), "lock-k2".to_string());

    let _ = vault.create_new_session([1u8; 32], crate::models::Argon2Params { m_cost_kib: 1024, t_cost: 2, p_cost: 1 }, false, None);

    // Poison the lock by panicking while holding a write guard in another thread,
    // then verify read_state/write_state recover from the PoisonError.
    let state_arc = vault.state();
    let handle = thread::spawn(move || {
        let _guard = state_arc.write().unwrap();
        panic!("intentional panic to poison lock");
    });

    let _ = handle.join();

    thread::sleep(Duration::from_millis(10));

    let _read = vault.read_state();
    let _write = vault.write_state();

    let _ = vault.add_device("LockRecoveryDevice", &master_key).expect("add device after poisoned lock");
}
