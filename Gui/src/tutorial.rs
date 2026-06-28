use slint::ComponentHandle;
use std::sync::{Arc, Mutex};

use crate::core::{
    CryptoService, FileService, GeneratorService,
    MasterKeyInput, PasswordRequest,
};
use crate::models::Argon2Params;
use crate::AppWindow;

use super::{helpers, AppState};

#[derive(Default, Clone)]
struct TutorialState {
    session_path:   String,
    device_name:    String,
    domain_name:    String,
    domain_uuid:    Option<uuid::Uuid>,
    k1_pending:     String,
    k2_pending:     String,
    k1_confirmed:   String,
    k2_confirmed:   String,
    device_argon2:  Option<Argon2Params>,
    session_argon2: Option<Argon2Params>,
    
    path_warning_seen: Option<String>,
}

type SharedTutorialState = Arc<Mutex<TutorialState>>;

pub fn register<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let tut_state: SharedTutorialState = Arc::new(Mutex::new(TutorialState::default()));

    register_cancel(ui, Arc::clone(&state), Arc::clone(&tut_state));

    {
        let ui_handle = ui.as_weak();
        ui.on_on_tutorial_step0_next(move || {
            let ui = ui_handle.unwrap();
            ui.set_tutorial_error("".into());
            ui.set_tutorial_step(1);
        });
    }

    register_step1(ui, Arc::clone(&state), Arc::clone(&tut_state));
    register_step1_override(ui, Arc::clone(&tut_state));
    register_step1_acknowledge_warning(ui, Arc::clone(&tut_state));
    register_device_calibrate_auto(ui, Arc::clone(&state));
    register_device_calibrate(ui);
    register_device_calibrate_next(ui, Arc::clone(&tut_state));
    register_step2(ui, Arc::clone(&state), Arc::clone(&tut_state));
    register_session_calibrate_auto(ui);
    register_session_calibrate(ui);
    register_session_calibrate_next(ui, Arc::clone(&tut_state));
    register_step3(ui, Arc::clone(&tut_state));
    register_step4(ui, Arc::clone(&state), Arc::clone(&tut_state));
    register_step7_verify(ui, Arc::clone(&state), Arc::clone(&tut_state));
    register_step7_restart(ui, Arc::clone(&state), Arc::clone(&tut_state));
    register_finish(ui, Arc::clone(&state), Arc::clone(&tut_state));
}

fn register_cancel<C, G, F>(
    ui:        &AppWindow,
    state:     Arc<Mutex<AppState<C, G, F>>>,
    tut_state: SharedTutorialState,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_cancel(move || {
        let ui = ui_handle.unwrap();

        {
            let s = state.lock().unwrap();
            let _ = s.vault.lock().unwrap().close_session();
        }

        *tut_state.lock().unwrap() = TutorialState::default();

        ui.set_show_tutorial(false);
        ui.set_tutorial_step(0);
        ui.set_tutorial_error("".into());
        ui.set_tutorial_password("".into());
        ui.set_tutorial_loading(false);
        ui.set_tutorial_step1_file_warning("".into());
    });
}

fn register_step1<C, G, F>(
    ui:        &AppWindow,
    _state:    Arc<Mutex<AppState<C, G, F>>>,
    tut_state: SharedTutorialState,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_step1(move |session_path, device_name| {
        let ui = ui_handle.unwrap();

        let resolved_path = if session_path.trim().is_empty() {
            let default_folder = ui.get_tutorial_default_path().to_string();
            std::path::Path::new(&default_folder)
                .join("session.vaultseed")
                .display()
                .to_string()
        } else {
            let p = std::path::Path::new(session_path.trim());
            if p.is_dir() {
                p.join("session.vaultseed").display().to_string()
            } else {
                session_path.trim().to_string()
            }
        };

        let resolved_device = if device_name.trim().is_empty() {
            ui.get_tutorial_default_device().to_string()
        } else {
            device_name.trim().to_string()
        };

        if resolved_path.is_empty() {
            ui.set_tutorial_error("O caminho da sessão não pode estar vazio.".into());
            return;
        }
        if resolved_device.is_empty() {
            ui.set_tutorial_error("O nome do dispositivo não pode estar vazio.".into());
            return;
        }

        // A pasta de destino tem de existir - o ficheiro de sessão em si ainda não existe (vai ser criado no passo 6).
        let parent_exists = std::path::Path::new(&resolved_path)
            .parent()
            .map(|p| p.as_os_str().is_empty() || p.exists())
            .unwrap_or(true);

        if !parent_exists {
            ui.set_tutorial_error("A pasta de destino não existe.".into());
            return;
        }

        // Se o ficheiro já existe pedir confirmação antes de substituir
        let already_acknowledged = {
            let t = tut_state.lock().unwrap();
            t.path_warning_seen.as_deref() == Some(resolved_path.as_str())
        };

        if std::path::Path::new(&resolved_path).exists() && !already_acknowledged {
            {
                let mut t      = tut_state.lock().unwrap();
                t.session_path = resolved_path.clone();
                t.device_name  = resolved_device;
            }
            ui.set_tutorial_step1_file_warning(
                format!("O ficheiro '{}' já existe e será substituído.", resolved_path).into()
            );
            ui.set_tutorial_error("".into());
            return;
        }

        {
            let mut t          = tut_state.lock().unwrap();
            t.session_path     = resolved_path;
            t.device_name      = resolved_device;
            t.path_warning_seen = None;
        }

        ui.set_tutorial_error("".into());
        ui.set_tutorial_step1_file_warning("".into());
        ui.set_tutorial_step(2);
    });
}

fn register_step1_acknowledge_warning(
    ui:        &AppWindow,
    tut_state: SharedTutorialState,
) {
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_step1_acknowledge_warning(move || {
        let _ui = ui_handle.unwrap();
        let mut t = tut_state.lock().unwrap();
        t.path_warning_seen = Some(t.session_path.clone());
    });
}

fn register_step1_override(
    ui:        &AppWindow,
    _tut_state: SharedTutorialState,
) {
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_step1_override(move || {
        let ui = ui_handle.unwrap();
        ui.set_tutorial_step1_file_warning("".into());
        ui.set_tutorial_error("".into());
        ui.set_tutorial_step(2);
    });
}

fn register_device_calibrate_auto<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_device_calibrate_auto(move || {
        let ui = ui_handle.unwrap();
        ui.set_tutorial_device_calibrating(true);
        ui.set_tutorial_device_time_ms("".into());

        // O dispositivo usa o tempo alvo configurado nas configurações locais
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

        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let result = crate::crypto::Calibrator::new()
                .with_min(min_ms)
                .with_max(max_ms)
                .run();

            let ms   = result.duration.as_millis();
            let m    = result.m_cost_kib.to_string();
            let t    = result.t_cost.to_string();
            let p    = result.p_cost.to_string();
            let time = format!("{ms} ms");

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                ui.set_tutorial_device_calibrating(false);
                ui.set_tutorial_device_m(m.into());
                ui.set_tutorial_device_t(t.into());
                ui.set_tutorial_device_p(p.into());
                ui.set_tutorial_device_time_ms(time.into());
            }).unwrap();
        });
    });
}

fn register_device_calibrate(ui: &AppWindow) {
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_device_calibrate(move |m_str, t_str, p_str| {
        let ui = ui_handle.unwrap();

        let m: u32 = m_str.trim().parse().unwrap_or(0);
        let t: u32 = t_str.trim().parse().unwrap_or(0);
        let p: u32 = p_str.trim().parse().unwrap_or(0);

        if crate::crypto::validate_argon2_params(m, t, p).is_err() {
            ui.set_tutorial_error("Parâmetros inválidos.".into());
            return;
        }

        ui.set_tutorial_device_calibrating(true);
        ui.set_tutorial_error("".into());

        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let ms = crate::crypto::benchmark_argon2(m, t, p).as_millis();
            let time = format!("{ms} ms");

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                ui.set_tutorial_device_calibrating(false);
                ui.set_tutorial_device_time_ms(time.into());
            }).unwrap();
        });
    });
}

fn register_device_calibrate_next(
    ui:        &AppWindow,
    tut_state: SharedTutorialState,
) {
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_device_calibrate_next(move |m_str, t_str, p_str| {
        let ui = ui_handle.unwrap();

        let m: u32 = m_str.trim().parse().unwrap_or(0);
        let t: u32 = t_str.trim().parse().unwrap_or(0);
        let p: u32 = p_str.trim().parse().unwrap_or(0);

        if let Err(e) = crate::crypto::validate_argon2_params(m, t, p) {
            ui.set_tutorial_error(e.into());
            return;
        }

        tut_state.lock().unwrap().device_argon2 =
            Some(Argon2Params { m_cost_kib: m, t_cost: t, p_cost: p });

        ui.set_tutorial_error("".into());
        ui.set_tutorial_step(3);
    });
}

fn register_step2<C, G, F>(
    ui:        &AppWindow,
    _state:    Arc<Mutex<AppState<C, G, F>>>,
    tut_state: SharedTutorialState,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_step2(move |domain| {
        let ui = ui_handle.unwrap();

        if domain.trim().is_empty() {
            ui.set_tutorial_error("O identificador do domínio não pode estar vazio.".into());
            return;
        }

        tut_state.lock().unwrap().domain_name = domain.to_string();

        ui.set_tutorial_error("".into());
        ui.set_tutorial_step(4);
    });
}

fn register_session_calibrate_auto(ui: &AppWindow) {
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_session_calibrate_auto(move || {
        let ui = ui_handle.unwrap();

        // No WASM, `spawn_async` corre de forma síncrona na própria thread da UI (não há thread no browser), por isso o popup fica bloqueado 
        ui.set_tutorial_session_calibrating(true);
        ui.set_tutorial_session_time_ms("".into());

        let ui_handle = ui.as_weak();
        
        helpers::spawn_async(move || {
            // Definimos os limites dependendo da plataforma onde a app está a correr.
            let (min_time, max_time) = if cfg!(target_arch = "wasm32") {
                // 1s a 5s: Tempos reduzidos para não sobrecarregar o browser, pois o WASM tem recursos bastante mais limitados
                (1_000, 5_000)
            } else {
                // 10s a 15s: Valores normais para aplicações nativas (Desktop/Mobile).
                (10_000, 15_000)
            };

            let result = crate::crypto::Calibrator::new()
                .with_min(min_time)
                .with_max(max_time)
                .run();

            let ms   = result.duration.as_millis();
            let m    = result.m_cost_kib.to_string();
            let t    = result.t_cost.to_string();
            let p    = result.p_cost.to_string();
            let time = format!("{ms} ms");

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                ui.set_tutorial_session_calibrating(false);
                ui.set_tutorial_session_m(m.into());
                ui.set_tutorial_session_t(t.into());
                ui.set_tutorial_session_p(p.into());
                ui.set_tutorial_session_time_ms(time.into());
            }).unwrap();
        });
    });
}

fn register_session_calibrate(ui: &AppWindow) {
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_session_calibrate(move |m_str, t_str, p_str| {
        let ui = ui_handle.unwrap();

        let m: u32 = m_str.trim().parse().unwrap_or(0);
        let t: u32 = t_str.trim().parse().unwrap_or(0);
        let p: u32 = p_str.trim().parse().unwrap_or(0);

        if crate::crypto::validate_argon2_params(m, t, p).is_err() {
            ui.set_tutorial_error("Parâmetros inválidos.".into());
            return;
        }

        ui.set_tutorial_session_calibrating(true);
        ui.set_tutorial_error("".into());

        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let ms = crate::crypto::benchmark_argon2(m, t, p).as_millis();
            let time = format!("{ms} ms");

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                ui.set_tutorial_session_calibrating(false);
                ui.set_tutorial_session_time_ms(time.into());
            }).unwrap();
        });
    });
}

fn register_session_calibrate_next(
    ui:        &AppWindow,
    tut_state: SharedTutorialState,
) {
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_session_calibrate_next(move |m_str, t_str, p_str| {
        let ui = ui_handle.unwrap();

        let m: u32 = m_str.trim().parse().unwrap_or(0);
        let t: u32 = t_str.trim().parse().unwrap_or(0);
        let p: u32 = p_str.trim().parse().unwrap_or(0);

        if let Err(e) = crate::crypto::validate_argon2_params(m, t, p) {
            ui.set_tutorial_error(e.into());
            return;
        }

        tut_state.lock().unwrap().session_argon2 =
            Some(Argon2Params { m_cost_kib: m, t_cost: t, p_cost: p });

        ui.set_tutorial_error("".into());
        ui.set_tutorial_step(5);
    });
}

fn register_step3(
    ui:        &AppWindow,
    tut_state: SharedTutorialState,
) {
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_step3(move |k1, k2| {
        let ui = ui_handle.unwrap();

        if k1.is_empty() {
            ui.set_tutorial_error("K1 não pode estar vazio.".into());
            return;
        }
        if k2.is_empty() {
            ui.set_tutorial_error("K2 não pode estar vazio.".into());
            return;
        }

        {
            let mut t  = tut_state.lock().unwrap();
            t.k1_pending = k1.to_string();
            t.k2_pending = k2.to_string();
        }

        ui.set_tutorial_error("".into());
        ui.set_tutorial_step(6);
    });
}

fn register_step4<C, G, F>(
    ui:        &AppWindow,
    state:     Arc<Mutex<AppState<C, G, F>>>,
    tut_state: SharedTutorialState,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_step4(move |k1_confirm, k2_confirm| {
        let ui = ui_handle.unwrap();

        let (k1_orig, k2_orig) = {
            let t = tut_state.lock().unwrap();
            (t.k1_pending.clone(), t.k2_pending.clone())
        };

        if k1_confirm.as_str() != k1_orig {
            ui.set_tutorial_error("K1 não coincide com o valor introduzido anteriormente.".into());
            return;
        }
        if k2_confirm.as_str() != k2_orig {
            ui.set_tutorial_error("K2 não coincide com o valor introduzido anteriormente.".into());
            return;
        }

        let (device_argon2, session_argon2, session_path, device_name, domain_name) = {
            let mut t_lock = tut_state.lock().unwrap();
            t_lock.k1_pending = String::new();
            t_lock.k2_pending = String::new();
            t_lock.k1_confirmed = k1_orig.clone();
            t_lock.k2_confirmed = k2_orig.clone();

            let device_argon2 = match t_lock.device_argon2.clone() {
                Some(a) => a,
                None => {
                    ui.set_tutorial_error("Erro interno: calibração do dispositivo em falta.".into());
                    return;
                }
            };
            let session_argon2 = match t_lock.session_argon2.clone() {
                Some(a) => a,
                None => {
                    ui.set_tutorial_error("Erro interno: calibração da sessão em falta.".into());
                    return;
                }
            };

            (
                device_argon2,
                session_argon2,
                t_lock.session_path.clone(),
                t_lock.device_name.clone(),
                t_lock.domain_name.clone(),
            )
        };

        let (k1, k2) = {
            let mut t_lock = tut_state.lock().unwrap();
            (std::mem::take(&mut t_lock.k1_confirmed), std::mem::take(&mut t_lock.k2_confirmed))
        };

        ui.set_tutorial_step(7);
        ui.set_tutorial_loading(true);
        ui.set_tutorial_loading_msg("A criar sessão e dispositivo...".into());
        ui.set_tutorial_error("".into());

        let state     = Arc::clone(&state);
        let tut_state = Arc::clone(&tut_state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let result = run_session_creation(
                &state,
                &session_path,
                &device_name,
                &domain_name,
                &k1,
                &k2,
                session_argon2,
                device_argon2,
            );

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                ui.set_tutorial_loading(false);

                match result {
                    Ok(domain_uuid) => {
                        tut_state.lock().unwrap().domain_uuid = Some(domain_uuid);
                        ui.set_tutorial_step(8);
                        ui.set_tutorial_error("".into());
                    }

                    Err(e) => {
                        ui.set_tutorial_step(6);
                        ui.set_tutorial_error(e.into());

                        let s = state.lock().unwrap();
                        let _ = s.vault.lock().unwrap().close_session();
                    }
                }
            }).unwrap();
        });
    });
}

fn register_step7_verify<C, G, F>(
    ui:        &AppWindow,
    state:     Arc<Mutex<AppState<C, G, F>>>,
    tut_state: SharedTutorialState,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_step7_verify(move |k1, k2| {
        let ui = ui_handle.unwrap();

        if k1.is_empty() || k2.is_empty() {
            ui.set_tutorial_error("Introduza K1 e K2 para verificar.".into());
            return;
        }

        let domain_uuid = match tut_state.lock().unwrap().domain_uuid {
            Some(u) => u,
            None => {
                ui.set_tutorial_error("Erro interno: domínio não encontrado.".into());
                return;
            }
        };

        ui.set_tutorial_loading(true);
        ui.set_tutorial_loading_msg("A verificar chaves e gerar senha...".into());
        ui.set_tutorial_error("".into());

        let k1_str    = k1.to_string();
        let k2_str    = k2.to_string();
        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let result = run_verify_and_generate(
                &state,
                domain_uuid,
                &k1_str,
                &k2_str,
            );

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                ui.set_tutorial_loading(false);

                match result {
                    Ok(password) => {
                        ui.set_tutorial_password(password.into());
                        ui.set_tutorial_error("".into());
                    }

                    Err(e) => {
                        ui.set_tutorial_error(
                            format!("Chaves incorretas ou sessão inválida: {}", e).into()
                        );
                        ui.set_tutorial_password("".into());
                    }
                }
            }).unwrap();
        });
    });
}

fn register_step7_restart<C, G, F>(
    ui:        &AppWindow,
    state:     Arc<Mutex<AppState<C, G, F>>>,
    tut_state: SharedTutorialState,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_step7_restart(move || {
        let ui = ui_handle.unwrap();

        {
            let s = state.lock().unwrap();
            let _ = s.vault.lock().unwrap().close_session();
        }

        {
            let mut t     = tut_state.lock().unwrap();
            t.domain_uuid = None;
        }

        ui.set_tutorial_step(0);
        ui.set_tutorial_error("".into());
        ui.set_tutorial_password("".into());
        ui.set_tutorial_loading(false);
    });
}

fn register_finish<C, G, F>(
    ui:        &AppWindow,
    state:     Arc<Mutex<AppState<C, G, F>>>,
    tut_state: SharedTutorialState,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_tutorial_finish(move |k1, k2| {
        let ui = ui_handle.unwrap();
        let step = ui.get_tutorial_step();

        if step == 8 || step == 9 {
            close_tutorial_and_unlock(&ui, &state, &tut_state);
            return;
        }

        let session_path = tut_state.lock().unwrap().session_path.clone();
        let k1 = k1.to_string();
        let k2 = k2.to_string();

        if k1.is_empty() || k2.is_empty() {
            ui.set_tutorial_error("Verifique as chaves antes de gravar.".into());
            return;
        }

        ui.set_tutorial_loading(true);
        ui.set_tutorial_loading_msg("A gravar sessão...".into());
        ui.set_tutorial_error("".into());

        let state     = Arc::clone(&state);
        let tut_state = Arc::clone(&tut_state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let master_key = MasterKeyInput::new(k1, k2);
            let result     = {
                let s     = state.lock().unwrap();
                let vault = s.vault.lock().unwrap();
                vault.save_session(&session_path, &master_key, None, true)
            };

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                ui.set_tutorial_loading(false);

                match result {
                    Ok(()) => {
                        state.lock().unwrap().session_path = session_path.clone();
                        close_tutorial_and_unlock(&ui, &state, &tut_state);
                    }

                    Err(e) => {
                        ui.set_tutorial_step(8);
                        ui.set_tutorial_error(
                            format!("Erro ao gravar sessão: {}", e).into()
                        );
                    }
                }
            }).unwrap();
        });
    });
}

fn close_tutorial_and_unlock<C, G, F>(
    ui:        &AppWindow,
    state:     &Arc<Mutex<AppState<C, G, F>>>,
    tut_state: &SharedTutorialState,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    *tut_state.lock().unwrap() = TutorialState::default();

    ui.set_show_tutorial(false);
    ui.set_tutorial_step(0);
    ui.set_tutorial_error("".into());
    ui.set_tutorial_password("".into());
    ui.set_tutorial_loading(false);

    super::auth::load_initial_ui_data(ui, state);

    ui.set_is_unlocked(true);
    ui.set_active_view(0);

    helpers::show_toast(
        ui,
        state,
        "Sessão criada com sucesso! Bem-vindo ao VaultSeed.",
        "success",
    );
}

fn run_session_creation<C, G, F>(
    state:          &Arc<Mutex<AppState<C, G, F>>>,
    session_path:   &str,
    device_name:    &str,
    domain_name:    &str,
    k1:             &str,
    k2:             &str,
    session_argon2: Argon2Params,
    device_argon2:  Argon2Params,
) -> Result<uuid::Uuid, String>
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let s     = state.lock().unwrap();
    let vault = s.vault.lock().unwrap();

    let salt_session = vault
        .crypto
        .generate_random_32()
        .map_err(|e| format!("Erro ao gerar salt: {}", e))?;

    vault
        .create_new_session(salt_session, session_argon2, false, None)
        .map_err(|e| format!("Erro ao criar sessão: {}", e))?;

    let master_key  = MasterKeyInput::new(k1.to_string(), k2.to_string());
    let device_uuid = vault
        .add_device_with_argon2(device_name, &master_key, device_argon2)
        .map_err(|e| format!("Erro ao criar dispositivo: {}", e))?;

    let restriction_uuid = vault
        .list_restrictions(device_uuid)
        .map_err(|e| format!("Erro ao listar restrições: {}", e))?
        .into_iter()
        .next()
        .map(|r| r.uuid)
        .ok_or_else(|| "Restrição inicial não encontrada.".to_string())?;

    let domain_uuid = vault
        .add_domain(domain_name, restriction_uuid)
        .map_err(|e| format!("Erro ao criar domínio: {}", e))?;

    vault
        .save_session(session_path, &master_key, None, true)
        .map_err(|e| format!("Erro ao guardar sessão: {}", e))?;

    Ok(domain_uuid)
}

fn run_verify_and_generate<C, G, F>(
    state:       &Arc<Mutex<AppState<C, G, F>>>,
    domain_uuid: uuid::Uuid,
    k1:          &str,
    k2:          &str,
) -> Result<String, String>
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let s          = state.lock().unwrap();
    let vault      = s.vault.lock().unwrap();
    let master_key = MasterKeyInput::new(k1.to_string(), k2.to_string());

    let mut result = vault
        .generate_password(
            PasswordRequest {
                domain_uuid,
                forced_variation: None,
            },
            &master_key,
        )
        .map_err(|e| format!("{}", e))?;

    Ok(std::mem::take(&mut result.password))
}
