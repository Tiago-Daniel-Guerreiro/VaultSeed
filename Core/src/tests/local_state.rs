use super::common;

#[test]
fn clear_local_state_ok() {
    let vault = common::build_test_vault();

    vault
        .set_last_session_path(Some("C:/tmp/session.vaultseed".to_string()))
        .expect("set path");
    vault
        .set_calibration_targets(Some(100), Some(300))
        .expect("set calibration");

    vault.clear_local_state().expect("clear local state");

    let local_state = vault.get_local_state();
    let expected = crate::models::LocalState::new();

    assert_eq!(local_state.last_session_path, expected.last_session_path);
    assert_eq!(local_state.session_file_timestamp, expected.session_file_timestamp);
    assert_eq!(local_state.session_file_hash, expected.session_file_hash);
    assert_eq!(local_state.calibration_min_target_ms, expected.calibration_min_target_ms);
    assert_eq!(local_state.calibration_max_target_ms, expected.calibration_max_target_ms);
    assert_eq!(local_state.benchmark_argon2_m_cost_kib, expected.benchmark_argon2_m_cost_kib);
    assert_eq!(local_state.benchmark_argon2_t_cost, expected.benchmark_argon2_t_cost);
    assert_eq!(local_state.benchmark_argon2_p_cost, expected.benchmark_argon2_p_cost);
    assert_eq!(local_state.benchmark_k1_len, expected.benchmark_k1_len);
    assert_eq!(local_state.benchmark_k2_len, expected.benchmark_k2_len);
    assert_eq!(local_state.benchmark_device_count, expected.benchmark_device_count);
    assert_eq!(local_state.benchmark_domains_per_device, expected.benchmark_domains_per_device);
    assert_eq!(local_state.benchmark_static_passwords_per_device, expected.benchmark_static_passwords_per_device);
}
