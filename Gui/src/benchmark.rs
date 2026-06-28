use slint::ComponentHandle;
use std::sync::{Arc, Mutex};

use crate::core::{CryptoService, FileService, GeneratorService};
use crate::AppWindow;
use crate::ui::{CalibrationBenchmarkResult, ExportBenchmarkResult};

use super::{helpers, AppState};
use super::local_state::build_local_state_item;

pub fn register<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    register_run_calibration(ui, Arc::clone(&state));
    register_run_export(ui, Arc::clone(&state));
    register_open_settings(ui, Arc::clone(&state));
    register_calibration_verify(ui, Arc::clone(&state));
}

/// on_calibration_verify(m, t, p) - mede o tempo do Argon2id para os parâmetros editados (em thread, para não bloquear a UI) e devolve-o ao modal.
fn register_calibration_verify<C, G, F>(
    ui:     &AppWindow,
    _state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_calibration_verify(move |m_str, t_str, p_str| {
        let ui = ui_handle.unwrap();

        let m = m_str.as_str().parse::<u32>()
            .unwrap_or(crate::crypto::MIN_M_COST_KIB)
            .max(crate::crypto::MIN_M_COST_KIB);
        let t = t_str.as_str().parse::<u32>()
            .unwrap_or(crate::crypto::MIN_T_COST)
            .max(crate::crypto::MIN_T_COST);
        let p = p_str.as_str().parse::<u32>()
            .unwrap_or(crate::crypto::MIN_P_COST)
            .max(crate::crypto::MIN_P_COST);

        ui.set_calibration_modal_verify_done(false);
        ui.set_calibration_modal_verifying(true);

        let ui_handle = ui.as_weak();
        helpers::spawn_async(move || {
            let ms = crate::crypto::benchmark_argon2(m, t, p).as_millis() as i32;
            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                ui.set_calibration_modal_verifying(false);
                ui.set_calibration_modal_verify_ms(format!("{}", ms).into());
                ui.set_calibration_modal_verify_done(true);
            }).unwrap();
        });
    });
}

/// Sincroniza a configuração actual do LocalState com a BenchmarkView.
/// Chamado antes de navegar para a vista de benchmark.
pub fn refresh_benchmark_config<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let s     = state.lock().unwrap();
    let vault = s.vault.lock().unwrap();
    let ls    = vault.get_local_state();
    drop(vault);
    drop(s);

    let min_ms = ls
        .calibration_min_target_ms
        .map(|v| format!("{}", v))
        .unwrap_or_else(|| format!("{}", crate::crypto::ARGON2_CALIBRATION_TARGET_MIN_MS));

    let max_ms = ls
        .calibration_max_target_ms
        .map(|v| format!("{}", v))
        .unwrap_or_else(|| format!("{}", crate::crypto::ARGON2_CALIBRATION_TARGET_MAX_MS));

    ui.set_benchmark_current_min_ms(min_ms.into());
    ui.set_benchmark_current_max_ms(max_ms.into());

    let m = ls.benchmark_argon2_m_cost_kib
        .map(|v| format!("{} KiB", v))
        .unwrap_or_else(|| format!("{} KiB (mínimo)", crate::crypto::MIN_M_COST_KIB));

    let t = ls.benchmark_argon2_t_cost
        .map(|v| v.to_string())
        .unwrap_or_else(|| format!("{} (mínimo)", crate::crypto::MIN_T_COST));

    let p = ls.benchmark_argon2_p_cost
        .map(|v| v.to_string())
        .unwrap_or_else(|| format!("{} (mínimo)", crate::crypto::MIN_P_COST));

    let devices = ls.benchmark_device_count
        .map(|v| v.to_string())
        .unwrap_or_else(|| "2 (padrão)".to_string());

    let domains = ls.benchmark_domains_per_device
        .map(|v| v.to_string())
        .unwrap_or_else(|| "100 (padrão)".to_string());

    let static_pw = ls.benchmark_static_passwords_per_device
        .map(|v| v.to_string())
        .unwrap_or_else(|| "100 (padrão)".to_string());

    let k1_len = ls.benchmark_k1_len
        .map(|v| v.to_string())
        .unwrap_or_else(|| "12 (padrão)".to_string());

    let k2_len = ls.benchmark_k2_len
        .map(|v| v.to_string())
        .unwrap_or_else(|| "12 (padrão)".to_string());

    ui.set_benchmark_config_argon2_m(m.into());
    ui.set_benchmark_config_argon2_t(t.into());
    ui.set_benchmark_config_argon2_p(p.into());
    ui.set_benchmark_config_devices(devices.into());
    ui.set_benchmark_config_domains(domains.into());
    ui.set_benchmark_config_static(static_pw.into());
    ui.set_benchmark_config_k1_len(k1_len.into());
    ui.set_benchmark_config_k2_len(k2_len.into());
}

/// Chamado após login para pré-popular o estado local na UI
pub fn refresh_local_state<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let s     = state.lock().unwrap();
    let vault = s.vault.lock().unwrap();
    let ls    = vault.get_local_state();
    drop(vault);
    drop(s);

    let item = build_local_state_item(&ls);
    ui.set_settings_state(item);

    refresh_benchmark_config(ui, state);
}

fn register_run_calibration<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_run_calibration(move || {
        let ui = ui_handle.unwrap();

        let (min_ms, max_ms) = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            let ls    = vault.get_local_state();

            let min = ls.calibration_min_target_ms
                .unwrap_or(crate::crypto::ARGON2_CALIBRATION_TARGET_MIN_MS);
            let max = ls.calibration_max_target_ms
                .unwrap_or(crate::crypto::ARGON2_CALIBRATION_TARGET_MAX_MS);

            (min, max)
        };

        ui.set_benchmark_calibration_has_result(false);
        ui.set_benchmark_calibration_running(true);
        ui.set_benchmark_error_calibration("".into());

        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let started = web_time::Instant::now();
            let cal     = crate::crypto::Calibrator::new()
                .with_min(min_ms)
                .with_max(max_ms)
                .run();
            let total_ms = started.elapsed().as_millis() as i32;

            let argon2_ms  = cal.duration.as_millis() as i32;
            let target_min = min_ms as i32;
            let target_max = max_ms as i32;

            let comparison = if argon2_ms < target_min {
                "below"
            } else if argon2_ms > target_max {
                "above"
            } else {
                "within"
            };

            let diff_ms = if argon2_ms < target_min {
                target_min - argon2_ms
            } else if argon2_ms > target_max {
                argon2_ms - target_max
            } else {
                0
            };

            let result = CalibrationBenchmarkResult {
                m_cost:        cal.m_cost_kib as i32,
                t_cost:        cal.t_cost as i32,
                p_cost:        cal.p_cost as i32,
                argon2_ms,
                total_ms,
                comparison:    comparison.into(),
                diff_ms,
                min_target_ms: target_min,
                max_target_ms: target_max,
            };

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();

                ui.set_benchmark_calibration_running(false);
                ui.set_benchmark_calibration_result(result);
                ui.set_benchmark_calibration_has_result(true);
                ui.set_benchmark_error_calibration("".into());

                helpers::toast_success(
                    &ui,
                    &state,
                    &format!(
                        "Calibração concluída: m={} KiB t={} p={} ({}ms)",
                        cal.m_cost_kib, cal.t_cost, cal.p_cost, argon2_ms
                    ),
                );
            }).unwrap();
        });
    });
}

fn register_run_export<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_run_export(move || {
        let ui = ui_handle.unwrap();

        let (m_cost, t_cost, p_cost) = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            let ls    = vault.get_local_state();

            (
                ls.benchmark_argon2_m_cost_kib.unwrap_or(crate::crypto::MIN_M_COST_KIB),
                ls.benchmark_argon2_t_cost.unwrap_or(crate::crypto::MIN_T_COST),
                ls.benchmark_argon2_p_cost.unwrap_or(crate::crypto::MIN_P_COST),
            )
        };

        ui.set_benchmark_export_has_result(false);
        ui.set_benchmark_export_running(true);
        ui.set_benchmark_error_export("".into());

        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let result = {
                let vault = helpers::clone_vault(&state);
                vault.run_export_benchmark()
            };

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                ui.set_benchmark_export_running(false);

                match result {
                    Ok(report) => {
                        let export_result = ExportBenchmarkResult {
                            device_count:    report.device_count as i32,
                            domain_count:    report.domain_count as i32,
                            static_pw_count: report.static_password_count as i32,
                            setup_ms:        report.setup_duration.as_millis() as i32,
                            prepare_ms:      report.prepare_duration.as_millis() as i32,
                            export_ms:       report.export_duration.as_millis() as i32,
                            generation_ms:   report.generation_duration.as_millis() as i32,
                            total_ms:        report.total_duration.as_millis() as i32,
                            argon2_m:        m_cost as i32,
                            argon2_t:        t_cost as i32,
                            argon2_p:        p_cost as i32,
                        };

                        ui.set_benchmark_export_result(export_result);
                        ui.set_benchmark_export_has_result(true);
                        ui.set_benchmark_error_export("".into());

                        helpers::toast_success(
                            &ui,
                            &state,
                            &format!(
                                "Benchmark concluído: {} domínios em {}ms",
                                report.domain_count,
                                report.total_duration.as_millis()
                            ),
                        );
                    }

                    Err(e) => {
                        ui.set_benchmark_error_export(
                            format!("Erro no benchmark: {}", e).into()
                        );
                        helpers::toast_error(
                            &ui,
                            &state,
                            &format!("Erro no benchmark: {}", e),
                        );
                    }
                }
            }).unwrap();
        });
    });
}

fn register_open_settings<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_benchmark_open_settings(move || {
        let ui = ui_handle.unwrap();

        super::local_state::refresh_local_state(&ui, &state);

        ui.set_active_view(2);              // 2 = Configurações
        ui.set_settings_active_panel(0);    // 0 = Calibração
    });
}