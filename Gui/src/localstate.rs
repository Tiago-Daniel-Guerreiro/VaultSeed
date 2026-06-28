use slint::ComponentHandle;
use std::sync::{Arc, Mutex};

use crate::core::{CryptoService, FileService, GeneratorService};
use crate::AppWindow;
use crate::ui::LocalStateItem;

use super::{helpers, AppState};

pub fn register<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    register_set_calibration(ui, Arc::clone(&state));
    register_clear_calibration(ui, Arc::clone(&state));
    register_set_benchmark_argon2(ui, Arc::clone(&state));
    register_calibration_accept(ui, Arc::clone(&state));
    register_set_benchmark_export(ui, Arc::clone(&state));
    register_delete_local(ui, Arc::clone(&state));
    register_open_benchmark(ui, Arc::clone(&state));
    register_prelogin_open_settings(ui, Arc::clone(&state));
    register_set_wasm_browser_storage(ui, Arc::clone(&state));
    register_pick_replace_session(ui, Arc::clone(&state));
}

fn register_set_wasm_browser_storage<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_set_wasm_browser_storage(move |enabled| {
        let ui = ui_handle.unwrap();

        let result = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.set_wasm_browser_storage(enabled)
        };

        match result {
            Ok(()) => {
                refresh_local_state(&ui, &state);
                ui.set_settings_error_browser_storage("".into());
            }
            Err(e) => {
                ui.set_settings_error_browser_storage(format!("{}", e).into());
            }
        }
    });
}

fn register_pick_replace_session<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_pick_replace_session(move || {
        #[cfg(target_arch = "wasm32")]
        {
            let ui = ui_handle.unwrap();
            let path = helpers::WASM_BROWSER_SESSION_KEY.to_string();
            wasm_pick_and_replace_session(ui.as_weak(), Arc::clone(&state), path);
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (&ui_handle, &state);
        }
    });
}

// Cria um <input type="file"> temporário, simula o clique e atualiza a sessão após o utilizador escolher o ficheiro.
#[cfg(target_arch = "wasm32")]
fn wasm_pick_and_replace_session<C, G, F>(
    ui_handle: slint::Weak<AppWindow>,
    state:     Arc<Mutex<AppState<C, G, F>>>,
    path:      String,
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
    input.set_accept(".vaultseed,.json");
    input.style().set_property("display", "none").ok();
    if document.body().map(|b| b.append_child(&input).is_ok()) != Some(true) {
        return;
    }

    let input_for_change = input.clone();
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
        let ui_handle  = ui_handle.clone();
        let state      = Arc::clone(&state);
        let path       = path.clone();
        let load_closure = Closure::<dyn FnMut()>::new(move || {
            let Some(ui) = ui_handle.upgrade() else { return; };

            let content = reader_for_load
                .result()
                .ok()
                .and_then(|v| v.as_string());

            let content = match content {
                Some(c) => c,
                None    => {
                    ui.set_settings_error_browser_storage(
                        "Não foi possível ler o ficheiro.".into()
                    );
                    return;
                }
            };

            match crate::services::file::FileServiceImpl::replace_session_with_uploaded(&path, &content) {
                Ok(()) => {
                    ui.set_settings_error_browser_storage("".into());
                    helpers::toast_success(
                        &ui, &state,
                        "Sessão do browser substituída pelo ficheiro carregado.",
                    );
                }
                Err(e) => {
                    ui.set_settings_error_browser_storage(e.into());
                }
            }
        });
        reader.set_onload(Some(load_closure.as_ref().unchecked_ref()));
        load_closure.forget();

        let _ = reader.read_as_text(&file);
    });

    input.set_onchange(Some(change_closure.as_ref().unchecked_ref()));
    change_closure.forget();

    input.click();
}

fn register_prelogin_open_settings<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_prelogin_open_settings(move || {
        let ui = ui_handle.unwrap();
        refresh_local_state(&ui, &state);
        super::benchmark::refresh_benchmark_config(&ui, &state);
    });
}

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

    let item = build_local_state_item(&ls);
    ui.set_settings_state(item);
}

fn register_set_calibration<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_set_calibration(move |min_str, max_str| {
        let ui = ui_handle.unwrap();

        let min: u128 = match min_str.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                ui.set_settings_error_calibration(
                    "Mínimo inválido - introduza um número inteiro positivo.".into()
                );
                return;
            }
        };

        let max: u128 = match max_str.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                ui.set_settings_error_calibration(
                    "Máximo inválido - introduza um número inteiro positivo.".into()
                );
                return;
            }
        };

        if min >= max {
            ui.set_settings_error_calibration(
                "O mínimo deve ser inferior ao máximo.".into()
            );
            return;
        }

        if max - min < 200 {
            ui.set_settings_error_calibration(
                "A diferença entre mínimo e máximo deve ser de pelo menos 200 ms.".into()
            );
            return;
        }

        let result = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.set_calibration_targets(Some(min), Some(max))
                .map_err(|e| format!("{}", e))
        };

        match result {
            Ok(()) => {
                ui.set_settings_error_calibration("".into());
                refresh_local_state(&ui, &state);
                helpers::toast_success(
                    &ui,
                    &state,
                    &format!("Calibração definida: {} ms -> {} ms", min, max),
                );
            }
            Err(e) => {
                ui.set_settings_error_calibration(e.into());
            }
        }
    });
}

fn register_clear_calibration<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_clear_calibration(move || {
        let ui = ui_handle.unwrap();

        let result = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.set_calibration_targets(None, None)
                .map_err(|e| format!("{}", e))
        };

        match result {
            Ok(()) => {
                ui.set_settings_error_calibration("".into());
                refresh_local_state(&ui, &state);
                helpers::toast_info(
                    &ui,
                    &state,
                    "Calibração reposta para valores padrão do sistema.",
                );
            }
            Err(e) => {
                ui.set_settings_error_calibration(e.into());
            }
        }
    });
}

fn register_set_benchmark_argon2<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_set_benchmark_argon2(move |m_str, t_str, p_str| {
        let ui = ui_handle.unwrap();

        let m = parse_optional_u32(m_str.as_str())
            .map(|v| v.max(crate::crypto::MIN_M_COST_KIB));
        let t = parse_optional_u32(t_str.as_str())
            .map(|v| v.max(crate::crypto::MIN_T_COST));
        let p = parse_optional_u32(p_str.as_str())
            .map(|v| v.max(crate::crypto::MIN_P_COST));

        let result = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.set_benchmark_argon2_params(m, t, p)
                .map_err(|e| format!("{}", e))
        };

        match result {
            Ok(()) => {
                ui.set_settings_error_argon2("".into());
                refresh_local_state(&ui, &state);
                helpers::toast_success(
                    &ui,
                    &state,
                    "Parâmetros Argon2id do benchmark actualizados.",
                );
            }
            Err(e) => {
                ui.set_settings_error_argon2(e.into());
            }
        }
    });
}

fn register_calibration_accept<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_calibration_accept(move |m_str, t_str, p_str| {
        let ui = ui_handle.unwrap();

        let m = parse_optional_u32(m_str.as_str())
            .map(|v| v.max(crate::crypto::MIN_M_COST_KIB));
        let t = parse_optional_u32(t_str.as_str())
            .map(|v| v.max(crate::crypto::MIN_T_COST));
        let p = parse_optional_u32(p_str.as_str())
            .map(|v| v.max(crate::crypto::MIN_P_COST));

        let result = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.set_benchmark_argon2_params(m, t, p)
                .map_err(|e| format!("{}", e))
        };

        match result {
            Ok(()) => {
                ui.set_settings_error_argon2("".into());
                refresh_local_state(&ui, &state);
                helpers::toast_success(
                    &ui,
                    &state,
                    "Parâmetros Argon2id aplicados a partir da calibração.",
                );
            }
            Err(e) => {
                ui.set_settings_error_argon2(e.into());
            }
        }
    });
}

fn register_set_benchmark_export<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_set_benchmark_export(move |devs_str, doms_str, stat_str, k1_str, k2_str| {
        let ui = ui_handle.unwrap();

        let device_count   = parse_optional_usize(devs_str.as_str()).map(|v| v.max(1));
        let domains_per    = parse_optional_usize(doms_str.as_str()).map(|v| v.max(1));
        let static_per     = parse_optional_usize(stat_str.as_str()).map(|v| v.max(1));
        let k1_len         = parse_optional_usize(k1_str.as_str()).map(|v| v.max(1));
        let k2_len         = parse_optional_usize(k2_str.as_str()).map(|v| v.max(1));

        let result = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.set_benchmark_export_settings(
                device_count,
                domains_per,
                static_per,
                k1_len,
                k2_len,
            ).map_err(|e| format!("{}", e))
        };

        match result {
            Ok(()) => {
                ui.set_settings_error_export("".into());
                refresh_local_state(&ui, &state);
                helpers::toast_success(
                    &ui,
                    &state,
                    "Configuração de exportação do benchmark actualizada.",
                );
            }
            Err(e) => {
                ui.set_settings_error_export(e.into());
            }
        }
    });
}

fn register_delete_local<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_delete_local(move || {
        let ui = ui_handle.unwrap();

        helpers::ask_confirm(
            &ui,
            &state,
            "Apagar dados locais?",
            "Remove o ficheiro de estado local. As sessões e senhas NÃO são afectadas.",
            "warning",
            "delete-local-state".to_string(),
        );
    });
}

pub fn handle_delete_local_confirmed<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let result = {
        let s     = state.lock().unwrap();
        let vault = s.vault.lock().unwrap();
        vault.delete_local_state()
            .map_err(|e| format!("{}", e))
    };

    match result {
        Ok(()) => {
            ui.set_settings_error_local("".into());
            // "Apagar e sair": termina a aplicação após apagar com sucesso.
            let _ = slint::quit_event_loop();
        }
        Err(e) => {
            ui.set_settings_error_local(e.into());
        }
    }
}

fn register_open_benchmark<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_open_benchmark(move || {
        let ui = ui_handle.unwrap();

        refresh_local_state(&ui, &state);
        super::benchmark::refresh_benchmark_config(&ui, &state);

        ui.set_active_view(3);
        ui.set_benchmark_active_panel(0);
    });
}

pub fn build_local_state_item(ls: &crate::models::LocalState) -> LocalStateItem {
    let fmt_min_target = |v: Option<u128>| -> slint::SharedString {
        v.map(|ms| ms.to_string())
            .unwrap_or_default()
            .into()
    };

    let fmt_argon2 = |v: Option<u32>, default: u32, suffix: &str| -> slint::SharedString {
        let n = v.unwrap_or(default);
        format!("{}{}", n, suffix).into()
    };

    let fmt_usize = |v: Option<usize>, default: usize| -> slint::SharedString {
        v.unwrap_or(default).to_string().into()
    };

    // Valores padrão para benchmark_export quando não configurados
    const DEFAULT_DEVICE_COUNT: usize = 3;
    const DEFAULT_DOMAINS_PER: usize = 10;
    const DEFAULT_STATIC_PER: usize = 5;
    const DEFAULT_K1_LEN: usize = 16;
    const DEFAULT_K2_LEN: usize = 16;

    LocalStateItem {
        calibration_min_ms: fmt_min_target(ls.calibration_min_target_ms),
        calibration_max_ms: fmt_min_target(ls.calibration_max_target_ms),

        benchmark_m_cost: fmt_argon2(
            ls.benchmark_argon2_m_cost_kib,
            crate::crypto::MIN_M_COST_KIB,
            ""
        ),
        benchmark_t_cost: fmt_argon2(
            ls.benchmark_argon2_t_cost,
            crate::crypto::MIN_T_COST,
            ""
        ),
        benchmark_p_cost: fmt_argon2(
            ls.benchmark_argon2_p_cost,
            crate::crypto::MIN_P_COST,
            ""
        ),

        benchmark_device_count:        fmt_usize(ls.benchmark_device_count, DEFAULT_DEVICE_COUNT),
        benchmark_domains_per_device:  fmt_usize(ls.benchmark_domains_per_device, DEFAULT_DOMAINS_PER),
        benchmark_static_per_device:   fmt_usize(ls.benchmark_static_passwords_per_device, DEFAULT_STATIC_PER),
        benchmark_k1_len:              fmt_usize(ls.benchmark_k1_len, DEFAULT_K1_LEN),
        benchmark_k2_len:              fmt_usize(ls.benchmark_k2_len, DEFAULT_K2_LEN),

        wasm_browser_storage: ls.wasm_browser_storage,
    }
}

fn parse_optional_u32(s: &str) -> Option<u32> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        trimmed.parse::<u32>().ok()
    }
}

fn parse_optional_usize(s: &str) -> Option<usize> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        trimmed.parse::<usize>().ok()
    }
}
