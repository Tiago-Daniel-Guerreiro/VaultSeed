use slint::ComponentHandle;
use std::sync::{Arc, Mutex};

use crate::core::{CryptoService, FileService, GeneratorService, MasterKeyInput};
use crate::models::Argon2Params;
use crate::AppWindow;

use crate::ui::{SessionOverviewItem, CalibrationResultItem};

use super::{helpers, AppState};

pub fn register<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    register_calibrate(ui, Arc::clone(&state));
    register_apply_calibration(ui, Arc::clone(&state));
    register_apply_manual_argon2(ui, Arc::clone(&state));
    register_regenerate_salt(ui, Arc::clone(&state));
    register_save(ui, Arc::clone(&state));
    register_activate_hardware(ui, Arc::clone(&state));
    register_deactivate_hardware(ui, Arc::clone(&state));
    register_create_xor(ui, Arc::clone(&state));
    register_verify_xor(ui, Arc::clone(&state));
    register_verify_xor_loaded(ui, Arc::clone(&state));
    register_pick_xor_file(ui, Arc::clone(&state));
    register_rotate_keys(ui, Arc::clone(&state));
    register_delete_session_file(ui, Arc::clone(&state));
}

pub fn refresh_session_overview<C, G, F>(
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

    let overview = match vault.get_session_overview() {
        Ok(o)  => o,
        Err(_) => return,
    };

    let h = &overview.header;

    let item = SessionOverviewItem {
        schema_version:    h.schema_version as i32,
        salt_session_hex:  hex::encode(h.salt_session).into(),
        argon2_m:          h.argon2.m_cost_kib as i32,
        argon2_t:          h.argon2.t_cost as i32,
        argon2_p:          h.argon2.p_cost as i32,
        hardware_enabled:  h.hardware_enabled,
        salt_hkdf_hex:     h.salt_hkdf
                               .map(hex::encode)
                               .unwrap_or_default()
                               .into(),
        nonce_global_hex:  hex::encode(overview.nonce_global).into(),
        ciphertext_len:    overview.ciphertext_global_len as i32,
        device_count:      overview.device_count as i32,
        restriction_count: overview.restriction_count as i32,
        domain_count:      overview.domain_count as i32,
        static_pw_count:   overview.static_password_count as i32,
    };

    ui.set_session_overview(item);

    let default_path = vault
        .default_session_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "session.vaultseed".to_string());

    ui.set_session_default_path(default_path.into());
}

fn register_calibrate<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_calibrate(move |target_secs| {
        let ui = ui_handle.unwrap();

        let secs: u128 = match target_secs.trim().parse() {
            Ok(v) if v > 0 => v,
            _ => {
                ui.set_session_error_argon2("Tempo alvo inválido (mínimo: 1 segundo).".into());
                return;
            }
        };

        helpers::show_loading(&ui, "A calibrar Argon2id...");
        ui.set_session_error_argon2("".into());
        ui.set_session_show_calibration_result(false);

        let (min_ms, max_ms) = (secs * 1000, secs * 1000 + 1000);
        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let cal     = crate::crypto::Calibrator::new()
                .with_min(min_ms)
                .with_max(max_ms)
                .run();

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

            {
                let mut s = state.lock().unwrap();
                s.pending_confirm_action = Some(format!(
                    "calibration-result:{}:{}:{}",
                    cal.m_cost_kib, cal.t_cost, cal.p_cost
                ));
            }

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                let result = CalibrationResultItem {
                    m_cost:        cal.m_cost_kib as i32,
                    t_cost:        cal.t_cost as i32,
                    p_cost:        cal.p_cost as i32,
                    duration_ms:   argon2_ms,
                    within_range:  comparison == "within",
                };

                ui.set_session_calibration_result(result);
                ui.set_session_show_calibration_result(true);
            }).unwrap();
        });
    });
}

fn register_apply_calibration<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_apply_calibration(move || {
        let ui = ui_handle.unwrap();

        let action = {
            let mut s = state.lock().unwrap();
            s.pending_confirm_action.take()
        };

        let action = match action {
            Some(a) if a.starts_with("calibration-result:") => a,
            _ => {
                ui.set_session_error_argon2("Nenhum resultado de calibração disponível.".into());
                return;
            }
        };

        let parts: Vec<&str> = action
            .trim_start_matches("calibration-result:")
            .split(':')
            .collect();

        if parts.len() < 3 {
            ui.set_session_error_argon2("Erro ao ler resultado de calibração.".into());
            return;
        }

        let (m, t, p) = match (
            parts[0].parse::<u32>(),
            parts[1].parse::<u32>(),
            parts[2].parse::<u32>(),
        ) {
            (Ok(m), Ok(t), Ok(p)) => (m, t, p),
            _ => {
                ui.set_session_error_argon2("Resultado de calibração inválido.".into());
                return;
            }
        };

        apply_argon2_params(&ui, &state, m, t, p);
    });
}

fn register_apply_manual_argon2<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_apply_manual_argon2(move |m_str, t_str, p_str| {
        let ui = ui_handle.unwrap();

        let m = match helpers::parse_u32_with_min(m_str.as_str(), 65_536) {
            Ok(v)  => v,
            Err(e) => { ui.set_session_error_argon2(e.into()); return; }
        };
        let t = match helpers::parse_u32_with_min(t_str.as_str(), 3) {
            Ok(v)  => v,
            Err(e) => { ui.set_session_error_argon2(e.into()); return; }
        };
        let p = match helpers::parse_u32_with_min(p_str.as_str(), 4) {
            Ok(v)  => v,
            Err(e) => { ui.set_session_error_argon2(e.into()); return; }
        };

        helpers::show_loading(&ui, "A testar parâmetros Argon2id...");

        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            // Mede o tempo sem aplicar; mostra o resultado e pede confirmação explícita (corresponde ao "Aplicar?" do console).
            let duration = crate::crypto::benchmark_argon2(m, t, p);
            let argon2_ms = duration.as_millis() as i32;

            {
                let mut s = state.lock().unwrap();
                s.pending_confirm_action = Some(format!(
                    "calibration-result:{}:{}:{}", m, t, p
                ));
            }

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                let result = CalibrationResultItem {
                    m_cost:       m as i32,
                    t_cost:       t as i32,
                    p_cost:       p as i32,
                    duration_ms:  argon2_ms,
                    within_range: true, // sem intervalo alvo no modo manual
                };

                ui.set_session_calibration_result(result);
                ui.set_session_show_calibration_result(true);
                ui.set_session_error_argon2("".into());
            }).unwrap();
        });
    });
}

fn register_regenerate_salt<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_regenerate_salt(move || {
        let ui = ui_handle.unwrap();

        helpers::ask_confirm(
            &ui,
            &state,
            "Regenerar salt da sessão?",
            "Esta operação invalida todos os backups existentes do ficheiro de sessão.",
            "warning",
            "regenerate-salt".to_string(),
        );
    });
}

pub fn handle_regenerate_salt_confirmed<C, G, F>(
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

    match vault.regenerate_session_salt() {
        Ok(new_salt) => {
            drop(vault);
            drop(s);
            refresh_session_overview(ui, state);
            helpers::toast_success(
                ui,
                state,
                &format!("Salt regenerado: {}. Guarde a sessão.", hex::encode(new_salt)),
            );
        }
        Err(e) => {
            helpers::toast_error(ui, state, &format!("Erro ao regenerar salt: {}", e));
        }
    }
}

fn register_save<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_save(move |path, k1, k2, k_ext, xor_path_a, xor_path_b, create_hmac| {
        let ui = ui_handle.unwrap();

        let path = if helpers::wasm_browser_storage_active(&state) {
            helpers::WASM_BROWSER_SESSION_KEY.to_string()
        } else {
            path.to_string()
        };
        let k_ext      = k_ext.to_string();
        let xor_path_a = xor_path_a.to_string();
        let xor_path_b = xor_path_b.to_string();

        let (resolved_k1, resolved_k2) = if !xor_path_a.is_empty() {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            match vault.files.read_xor_files(&xor_path_a, &xor_path_b) {
                Ok(pair) => pair,
                Err(e)   => {
                    ui.set_session_error_save(
                        format!("Erro nos ficheiros XOR: {}", e).into()
                    );
                    return;
                }
            }
        } else {
            (k1.to_string(), k2.to_string())
        };

        if resolved_k1.is_empty() {
            ui.set_session_error_save("K1 não pode estar vazio.".into());
            return;
        }

        let k_ext_bytes: Option<[u8; 32]> = if !k_ext.is_empty() {
            match helpers::read_32_bytes(&k_ext) {
                Ok(b)  => Some(b),
                Err(e) => {
                    ui.set_session_error_save(format!("K_ext inválido: {}", e).into());
                    return;
                }
            }
        } else {
            None
        };

        helpers::show_loading(&ui, "A guardar sessão...");
        ui.set_session_error_save("".into());

        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let master_key = MasterKeyInput::new(resolved_k1, resolved_k2);
            let result: Result<(), vaultseed_core::errors::CoreError> = {
                let vault = helpers::clone_vault(&state);
                vault.save_session(&path, &master_key, k_ext_bytes.as_ref(), create_hmac)
            };

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok(()) => {
                        state.lock().unwrap().session_path = path.clone();
                        let _ = {
                            let s     = state.lock().unwrap();
                            let vault = s.vault.lock().unwrap();
                            vault.set_last_session_path(Some(path.clone()))
                        };

                        #[cfg(target_arch = "wasm32")]
                        {
                            if let Err(e) = crate::services::file::FileServiceImpl::download_session_file(
                                &path,
                                "vaultseed-session.vaultseed",
                            ) {
                                helpers::toast_error(
                                    &ui, &state,
                                    &format!("Sessão guardada, mas o download falhou: {e}"),
                                );
                            }
                        }

                        // Quando este guardar foi pedido a partir do diálogo de
                        // alterações pendentes ao tentar fechar a janela
                        // (lock-unsaved-is-quit), guardar com sucesso deve
                        // terminar a aplicação - sem isto a janela ficava
                        // aberta e bloqueada para sempre depois de guardar.
                        if ui.get_lock_unsaved_is_quit() {
                            ui.set_lock_unsaved_is_quit(false);
                            let _ = slint::quit_event_loop();
                        } else {
                            helpers::toast_success(
                                &ui,
                                &state,
                                &format!("Sessão guardada em: {}", path),
                            );
                        }
                    }
                    Err(e) => {
                        ui.set_session_error_save(format!("{}", e).into());
                    }
                }
            }).unwrap();
        });
    });
}

fn register_activate_hardware<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_activate_hardware(move |kext_value, kext_source, save_path, k1, k2| {
        let ui = ui_handle.unwrap();

        if k1.is_empty() || k2.is_empty() {
            ui.set_session_error_hardware("K1 e K2 são obrigatórios.".into());
            return;
        }

        let kext_value  = kext_value.to_string();
        let kext_source = kext_source.to_string();
        let save_path   = save_path.to_string();
        let k1          = k1.to_string();
        let k2          = k2.to_string();

        helpers::show_loading(&ui, "A ativar fator físico...");
        ui.set_session_error_hardware("".into());

        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let result = run_activate_hardware(
                &state,
                &kext_value,
                &kext_source,
                &save_path,
                &k1,
                &k2,
            );

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok(()) => {
                        refresh_session_overview(&ui, &state);
                        helpers::toast_success(
                            &ui,
                            &state,
                            "Fator físico ativado. Sessão guardada.",
                        );
                    }
                    Err(e) => {
                        ui.set_session_error_hardware(e.into());
                    }
                }
            }).unwrap();
        });
    });
}

fn run_activate_hardware<C, G, F>(
    state:       &Arc<Mutex<AppState<C, G, F>>>,
    kext_value:  &str,
    kext_source: &str,
    save_path:   &str,
    k1:          &str,
    k2:          &str,
) -> Result<(), String>
where
    C: CryptoService + Clone,
    G: GeneratorService + Clone,
    F: FileService + Clone,
{
    // Larga o Mutex antes do Argon2id (ver helpers::clone_vault).
    let vault = helpers::clone_vault(state);

    let k_ext: [u8; 32] = match kext_source {
        "file" | "hex" => helpers::read_32_bytes(kext_value)
            .map_err(|e| format!("K_ext inválido: {}", e))?,

        "new" => {
            let new_key = crate::crypto::generate_salt();
            std::fs::write(kext_value, new_key)
                .map_err(|e| format!("Erro ao criar ficheiro K_ext: {}", e))?;
            new_key
        }

        _ => return Err("Fonte de K_ext inválida.".into()),
    };

    let salt_hkdf = crate::crypto::generate_salt();

    let master_key = MasterKeyInput::new(k1.to_string(), k2.to_string());

    vault
        .rotate_kext(&master_key, Some(&k_ext), Some(salt_hkdf), save_path)
        .map_err(|e| format!("{}", e))
}

fn register_deactivate_hardware<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_deactivate_hardware(move |save_path, k1, k2| {
        let ui = ui_handle.unwrap();

        if k1.is_empty() || k2.is_empty() {
            ui.set_session_error_hardware("K1 e K2 são obrigatórios.".into());
            return;
        }

        let save_path = save_path.to_string();
        let k1        = k1.to_string();
        let k2        = k2.to_string();

        helpers::show_loading(&ui, "A desativar fator físico...");
        ui.set_session_error_hardware("".into());

        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let result: Result<(), String> = {
                let vault      = helpers::clone_vault(&state);
                let master_key = MasterKeyInput::new(k1, k2);
                vault.rotate_kext(&master_key, None, None, &save_path)
                    .map_err(|e| format!("{}", e))
            };

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok(()) => {
                        refresh_session_overview(&ui, &state);
                        helpers::toast_success(
                            &ui,
                            &state,
                            "Fator físico desativado. Sessão guardada.",
                        );
                    }
                    Err(e) => {
                        ui.set_session_error_hardware(e.into());
                    }
                }
            }).unwrap();
        });
    });
}

fn register_create_xor<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_create_xor(move |path_a, path_b, k1, k2| {
        let ui = ui_handle.unwrap();

        let path_a = path_a.to_string();
        let path_b = path_b.to_string();

        if path_a == path_b {
            ui.set_session_error_xor("Os caminhos dos ficheiros têm de ser diferentes.".into());
            return;
        }
        if k1.is_empty() && k2.is_empty() {
            ui.set_session_error_xor("Introduza pelo menos uma chave.".into());
            return;
        }

        let k1        = k1.to_string();
        let k2        = k2.to_string();
        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::show_loading(&ui, "A criar ficheiros XOR...");
        ui.set_session_error_xor("".into());
        ui.set_session_success_xor("".into());

        helpers::spawn_async(move || {
            #[cfg(not(target_arch = "wasm32"))]
            let result: Result<bool, String> = {
                let s     = state.lock().unwrap();
                let vault = s.vault.lock().unwrap();
                vault.create_xor_files(&k1, &k2, &path_a, &path_b)
                    .map_err(|e| format!("{}", e))
                    .and_then(|()| {
                        vault.recover_keys_from_xor(&path_a, &path_b)
                            .map_err(|e| format!("criados, mas a verificação falhou: {}", e))
                            .map(|rec| rec.k1 == k1 && rec.k2 == k2)
                    })
            };
            #[cfg(target_arch = "wasm32")]
            let result: Result<bool, String> = {
                let _ = &state;
                crate::services::file::FileServiceImpl::create_xor_files_bytes(
                    &k1, &k2, &path_a, &path_b,
                ).map(|()| true)
            };

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok(true) => {
                        #[cfg(not(target_arch = "wasm32"))]
                        let message = format!("Ficheiros XOR criados e verificados: {} / {}", path_a, path_b);
                        #[cfg(target_arch = "wasm32")]
                        let message = format!("Ficheiros XOR descarregados: {} / {}", path_a, path_b);
                        ui.set_session_success_xor(message.into());
                    }
                    Ok(false) => {
                        ui.set_session_error_xor(
                            "Ficheiros XOR criados, mas a verificação NÃO corresponde às chaves originais.".into()
                        );
                    }
                    Err(e) => {
                        ui.set_session_error_xor(e.into());
                    }
                }
            }).unwrap();
        });
    });
}

fn register_verify_xor<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_verify_xor(move |path_a, path_b| {
        let ui = ui_handle.unwrap();

        let path_a = path_a.to_string();
        let path_b = path_b.to_string();

        helpers::show_loading(&ui, "A verificar ficheiros XOR...");
        ui.set_session_error_xor("".into());
        ui.set_session_success_xor("".into());

        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let result = {
                let s     = state.lock().unwrap();
                let vault = s.vault.lock().unwrap();
                vault.recover_keys_from_xor(&path_a, &path_b)
                    .map_err(|e| format!("{}", e))
            };

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok(recovered) => {
                        // Mostra comprimentos como confirmação sem expor as chaves
                        ui.set_session_success_xor(
                            format!(
                                "XOR verificado - K1: {} chars, K2: {} chars",
                                recovered.k1.len(),
                                recovered.k2.len()
                            ).into()
                        );
                    }
                    Err(e) => {
                        ui.set_session_error_xor(format!("Erro na verificação XOR: {}", e).into());
                    }
                }
            }).unwrap();
        });
    });
}

fn register_verify_xor_loaded<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_verify_xor_loaded(move || {
        let ui = ui_handle.unwrap();

        ui.set_session_error_xor("".into());
        ui.set_session_success_xor("".into());

        #[cfg(target_arch = "wasm32")]
        {
            let s = state.lock().unwrap();
            let (Some(share_a), Some(share_b)) = (&s.xor_loaded_a, &s.xor_loaded_b) else {
                ui.set_session_error_xor("Carrega os dois ficheiros antes de verificar.".into());
                return;
            };

            match crate::services::file::FileServiceImpl::read_xor_files_bytes(share_a, share_b) {
                Ok(recovered) => {
                    ui.set_session_success_xor(
                        format!(
                            "XOR verificado - K1: {} chars, K2: {} chars",
                            recovered.0.len(),
                            recovered.1.len()
                        ).into()
                    );
                }
                Err(e) => {
                    ui.set_session_error_xor(format!("Erro na verificação XOR: {}", e).into());
                }
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = &state;
        }
    });
}

fn register_pick_xor_file<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_pick_xor_file(move |which| {
        #[cfg(target_arch = "wasm32")]
        {
            let ui = ui_handle.unwrap();
            wasm_pick_xor_file(ui.as_weak(), Arc::clone(&state), which.to_string());
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (&ui_handle, &state, which);
        }
    });
}

#[cfg(target_arch = "wasm32")]
fn wasm_pick_xor_file<C, G, F>(
    ui_handle: slint::Weak<AppWindow>,
    state:     Arc<Mutex<AppState<C, G, F>>>,
    which:     String,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::JsCast;

    let window = match web_sys::window() {
        Some(w) => w,
        None    => return,
    };
    let document = match window.document() {
        Some(d) => d,
        None    => return,
    };

    let input = match document.create_element("input") {
        Ok(el) => el,
        Err(_) => return,
    };
    let input: web_sys::HtmlInputElement = match input.dyn_into() {
        Ok(i)  => i,
        Err(_) => return,
    };
    input.set_type("file");
    input.style().set_property("display", "none").ok();
    if document.body().map(|b| b.append_child(&input).is_ok()) != Some(true) {
        return;
    }

    let input_for_change  = input.clone();
    let input_for_cleanup = input.clone();
    let change_closure = Closure::<dyn FnMut()>::new(move || {
        if let Some(window) = web_sys::window() {
            if let Some(document) = window.document() {
                if let Some(body) = document.body() {
                    let _ = body.remove_child(&input_for_cleanup);
                }
            }
        }

        let files = match input_for_change.files() {
            Some(f) => f,
            None    => return,
        };
        let file = match files.get(0) {
            Some(f) => f,
            None    => return,
        };

        let reader = match web_sys::FileReader::new() {
            Ok(r)  => r,
            Err(_) => return,
        };

        let reader_for_load = reader.clone();
        let ui_handle        = ui_handle.clone();
        let state            = Arc::clone(&state);
        let which            = which.clone();
        let load_closure = Closure::<dyn FnMut()>::new(move || {
            let Some(ui) = ui_handle.upgrade() else { return; };

            let bytes = reader_for_load
                .result()
                .ok()
                .map(|v| js_sys::Uint8Array::new(&v).to_vec());

            let bytes = match bytes {
                Some(b) => b,
                None    => {
                    ui.set_session_error_xor("Não foi possível ler o ficheiro.".into());
                    return;
                }
            };

            {
                let mut s = state.lock().unwrap();
                if which == "a" {
                    s.xor_loaded_a = Some(bytes);
                } else {
                    s.xor_loaded_b = Some(bytes);
                }
                ui.set_session_xor_a_loaded(s.xor_loaded_a.is_some());
                ui.set_session_xor_b_loaded(s.xor_loaded_b.is_some());
            }
            ui.set_session_error_xor("".into());
        });
        reader.set_onload(Some(load_closure.as_ref().unchecked_ref()));
        load_closure.forget();

        let _ = reader.read_as_array_buffer(&file);
    });

    input.set_onchange(Some(change_closure.as_ref().unchecked_ref()));
    change_closure.forget();

    input.click();
}

fn register_rotate_keys<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_rotate_keys(move |old_k1, old_k2, new_k1, new_k2, conf_k1, conf_k2, path| {
        let ui = ui_handle.unwrap();

        if let Err(e) = helpers::validate_match(
            new_k1.as_str(), conf_k1.as_str(), "K1"
        ) {
            ui.set_session_error_rotate(e.into());
            return;
        }
        if let Err(e) = helpers::validate_match(
            new_k2.as_str(), conf_k2.as_str(), "K2"
        ) {
            ui.set_session_error_rotate(e.into());
            return;
        }
        if new_k1 == old_k1 && new_k2 == old_k2 {
            ui.set_session_error_rotate(
                "As novas chaves são iguais às actuais.".into()
            );
            return;
        }

        ui.set_session_error_rotate("".into());

        // Guarda os parâmetros no estado (as chaves podem conter ':') e pede confirmação. A acção transporta apenas a etiqueta.
        state.lock().unwrap().pending_rotate_keys = Some(super::PendingRotateKeys {
            old_k1: old_k1.to_string(),
            old_k2: old_k2.to_string(),
            new_k1: new_k1.to_string(),
            new_k2: new_k2.to_string(),
            path:   path.to_string(),
        });

        helpers::ask_confirm(
            &ui,
            &state,
            "Rotacionar K1/K2?",
            "As chaves antigas deixam de funcionar imediatamente. Esta operação é irreversível.",
            "danger",
            "rotate-keys".to_string(),
        );
    });
}

pub fn handle_rotate_keys_confirmed<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let params = match state.lock().unwrap().pending_rotate_keys.take() {
        Some(p) => p,
        None    => {
            helpers::toast_error(ui, state, "Erro interno: parâmetros de rotação em falta.");
            return;
        }
    };

    let old_k1 = params.old_k1;
    let old_k2 = params.old_k2;
    let new_k1 = params.new_k1;
    let new_k2 = params.new_k2;
    let path   = params.path;

    helpers::show_loading(ui, "A rotacionar chaves...");

    let state     = Arc::clone(state);
    let ui_handle = ui.as_weak();

    helpers::spawn_async(move || {
        let result = {
            let vault      = helpers::clone_vault(&state);
            let old_key    = MasterKeyInput::new(old_k1, old_k2);
            let new_key    = MasterKeyInput::new(new_k1, new_k2);
            vault.rotate_master_key(&old_key, &new_key, &path, None)
                .map_err(|e| format!("{}", e))
        };

        slint::invoke_from_event_loop(move || {
            let ui = ui_handle.unwrap();
            helpers::hide_loading(&ui);

            match result {
                Ok(()) => {
                    state.lock().unwrap().session_path = path.clone();
                    refresh_session_overview(&ui, &state);
                    helpers::toast_success(
                        &ui,
                        &state,
                        &format!("Chaves rotacionadas. Sessão guardada em: {}", path),
                    );
                }
                Err(e) => {
                    ui.set_session_error_rotate(e.into());
                }
            }
        }).unwrap();
    });
}

fn apply_argon2_params<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    m:     u32,
    t:     u32,
    p:     u32,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let s     = state.lock().unwrap();
    let vault = s.vault.lock().unwrap();

    match vault.update_session_argon2_params(Argon2Params {
        m_cost_kib: m,
        t_cost:     t,
        p_cost:     p,
    }) {
        Ok(()) => {
            drop(vault);
            drop(s);
            refresh_session_overview(ui, state);
            helpers::toast_success(
                ui,
                state,
                "Parâmetros Argon2id actualizados. Guarde a sessão.",
            );
            ui.set_session_error_argon2("".into());
            ui.set_session_show_calibration_result(false);
        }
        Err(e) => {
            ui.set_session_error_argon2(format!("{}", e).into());
        }
    }
}

fn register_delete_session_file<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_delete_session_file(move || {
        let ui   = ui_handle.unwrap();
        let path = state.lock().unwrap().session_path.clone();

        helpers::ask_confirm(
            &ui,
            &state,
            "Apagar ficheiro de sessão?",
            &format!(
                "Remove definitivamente o ficheiro em \"{}\". Sem uma cópia \
                guardada noutro local, perdes o acesso a esta sessão.",
                path
            ),
            "danger",
            "delete-session-file".to_string(),
        );
    });
}

pub fn handle_delete_session_file_confirmed<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let path = state.lock().unwrap().session_path.clone();

    let result = {
        let s     = state.lock().unwrap();
        let vault = s.vault.lock().unwrap();
        vault.delete_session_file(&path).map_err(|e| format!("{}", e))
    };

    match result {
        Ok(()) => {
            crate::handle_lock_confirmed(ui, state);
        }
        Err(e) => {
            ui.set_session_error_delete_session(e.into());
        }
    }
}