use slint::ComponentHandle;
use std::sync::{Arc, Mutex};
#[cfg(all(feature = "desktop", any(target_os = "windows", target_os = "macos", target_os = "linux")))]
use std::path::{Path, PathBuf};

use crate::core::{
    CryptoService, FileService, GeneratorService, MasterKeyInput,
};
use crate::errors::{CoreError, SessionError};
use crate::AppWindow;

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
    register_pick_path(ui);
    register_pick_xor_file_login(ui, Arc::clone(&state));
    register_login(ui, Arc::clone(&state));
    register_open_tutorial(ui, Arc::clone(&state));
    register_confirm_no_hmac(ui, Arc::clone(&state));
    register_pre_unlock(ui, Arc::clone(&state));
}

fn register_pick_xor_file_login<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_pick_xor_file_login(move |which| {
        #[cfg(target_arch = "wasm32")]
        {
            let ui = ui_handle.unwrap();
            wasm_pick_xor_file_login(ui.as_weak(), Arc::clone(&state), which.to_string());
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (&ui_handle, &state, which);
        }
    });
}

#[cfg(target_arch = "wasm32")]
fn wasm_pick_xor_file_login<C, G, F>(
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
                    ui.set_login_error("Não foi possível ler o ficheiro.".into());
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
                ui.set_login_xor_a_loaded(s.xor_loaded_a.is_some());
                ui.set_login_xor_b_loaded(s.xor_loaded_b.is_some());
            }
            ui.set_login_error("".into());
        });
        reader.set_onload(Some(load_closure.as_ref().unchecked_ref()));
        load_closure.forget();

        let _ = reader.read_as_array_buffer(&file);
    });

    input.set_onchange(Some(change_closure.as_ref().unchecked_ref()));
    change_closure.forget();
    input.click();
}

fn register_pick_path(ui: &AppWindow) {
    ui.on_on_pick_path(move |kind, current| {
        let _kind = kind.to_string();
        let current = current.to_string();

        #[cfg(all(feature = "desktop", any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            let mut dialog = rfd::FileDialog::new();

            let current_path = current.trim();
            if !current_path.is_empty() {
                let as_path = Path::new(current_path);
                if as_path.is_dir() {
                    dialog = dialog.set_directory(as_path);
                } else {
                    if let Some(parent) = as_path.parent() {
                        dialog = dialog.set_directory(parent);
                    }
                    if let Some(name) = as_path.file_name().and_then(|n| n.to_str()) {
                        dialog = dialog.set_file_name(name);
                    }
                }
            }

            let selected: Option<PathBuf> = match _kind.as_str() {
                "open-file" => dialog.pick_file(),
                "save-file" => dialog.save_file(),
                "folder" => dialog.pick_folder(),
                _ => None,
            };

            selected
                .map(|p| p.display().to_string())
                .unwrap_or_default()
                .into()
        }

        #[cfg(all(feature = "android", target_os = "android"))]
        {
            match _kind.as_str() {
                "open-file" => {
                    crate::android_native::launch_picker("open-file");
                    return current.into();
                }
                "folder" => {
                    let dir = crate::android_native::app_files_dir();
                    if dir.is_empty() {
                        return current.into();
                    }
                    return dir.into();
                }
                "save-file" => {
                    let dir = crate::android_native::app_files_dir();
                    if dir.is_empty() {
                        return current.into();
                    }
                    // Mantém o nome do ficheiro atual, se houver; senão usa o padrão.
                    let file_name = current
                        .trim()
                        .rsplit(|c| c == '/' || c == '\\')
                        .next()
                        .filter(|s| !s.is_empty())
                        .unwrap_or("session.vaultseed");
                    return format!("{}/{}", dir.trim_end_matches('/'), file_name).into();
                }
                _ => return current.into(),
            }
        }

        #[cfg(not(any(
            all(feature = "desktop", any(target_os = "windows", target_os = "macos", target_os = "linux")),
            all(feature = "android", target_os = "android"),
        )))]
        {
            current.into()
        }
    });
}

fn register_login<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_login(move |path, k1, k2, k_ext, xor_path_a, xor_path_b| {
        let ui = ui_handle.unwrap();

        #[cfg(target_arch = "wasm32")]
        let has_xor_bytes_wasm = {
            let s = state.lock().unwrap();
            s.xor_loaded_a.is_some() && s.xor_loaded_b.is_some()
        };
        #[cfg(not(target_arch = "wasm32"))]
        let has_xor_bytes_wasm = false;

        if k1.trim().is_empty() && xor_path_a.trim().is_empty() && !has_xor_bytes_wasm {
            ui.set_login_error("Introduza K1 ou os ficheiros XOR.".into());
            return;
        }

        helpers::show_loading(&ui, "A abrir sessão...");
        ui.set_login_error("".into());

        let path = if helpers::wasm_browser_storage_active(&state) {
            helpers::WASM_BROWSER_SESSION_KEY.to_string()
        } else {
            path.to_string()
        };

        let k1         = k1.to_string();
        let k2         = k2.to_string();
        let k_ext      = k_ext.to_string();
        let xor_path_a = xor_path_a.to_string();
        let xor_path_b = xor_path_b.to_string();
        let state      = Arc::clone(&state);
        let ui_handle  = ui.as_weak();

        helpers::spawn_async(move || {
            let result = run_login(
                &state,
                &path,
                &k1,
                &k2,
                &k_ext,
                &xor_path_a,
                &xor_path_b,
                true, // verify_hmac = true (primeira tentativa)
            );

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    LoginResult::Ok(session_path) => {
                        state.lock().unwrap().session_path = session_path.clone();

                        load_initial_ui_data(&ui, &state);

                        ui.set_is_unlocked(true);
                        ui.set_active_view(0);
                        ui.set_login_error("".into());
                        ui.set_login_hmac_warning(false);
                    }

                    LoginResult::NoHmac => {
                        // Ficheiro sem HMAC - mostra aviso e aguarda confirmação
                        ui.set_login_hmac_warning(true);
                        ui.set_login_hmac_tampered(false);

                        state.lock().unwrap().pending_login = Some(super::PendingLogin {
                            path, k1, k2, k_ext, xor_path_a, xor_path_b,
                        });
                    }

                    LoginResult::HmacFail => {
                        // HMAC não corresponde - permite abrir mesmo assim após confirmação
                        ui.set_login_hmac_tampered(true);
                        ui.set_login_hmac_warning(false);

                        state.lock().unwrap().pending_login = Some(super::PendingLogin {
                            path, k1, k2, k_ext, xor_path_a, xor_path_b,
                        });
                    }

                    LoginResult::Err(e) => {
                        ui.set_login_error(e.into());
                    }
                }
            }).unwrap();
        });
    });
}

/// Corresponde ao confirm() após HMAC fail no console
fn register_confirm_no_hmac<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_login_confirm_no_hmac(move || {
        let ui = ui_handle.unwrap();
        ui.set_login_hmac_warning(false);
        ui.set_login_hmac_tampered(false);

        let pending = state.lock().unwrap().pending_login.take();
        let pending = match pending {
            Some(p) => p,
            None    => return,
        };

        let path       = pending.path;
        let k1         = pending.k1;
        let k2         = pending.k2;
        let k_ext      = pending.k_ext;
        let xor_path_a = pending.xor_path_a;
        let xor_path_b = pending.xor_path_b;

        helpers::show_loading(&ui, "A abrir sessão sem verificação HMAC...");

        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let result = run_login(
                &state,
                &path,
                &k1,
                &k2,
                &k_ext,
                &xor_path_a,
                &xor_path_b,
                false, // verify_hmac = false (utilizador confirmou)
            );

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    LoginResult::Ok(session_path) => {
                        state.lock().unwrap().session_path = session_path;

                        load_initial_ui_data(&ui, &state);

                        ui.set_is_unlocked(true);
                        ui.set_active_view(0);
                        ui.set_login_error("".into());
                        ui.set_login_hmac_warning(false);
                    }

                    LoginResult::Err(e) => {
                        ui.set_login_error(e.into());
                    }

                    LoginResult::NoHmac | LoginResult::HmacFail => {
                        ui.set_login_error("Erro inesperado ao abrir sessão.".into());
                    }
                }
            }).unwrap();
        });
    });
}

/// Verifica se a sessão requer hardware factor
fn register_pre_unlock<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let state = Arc::clone(&state);
    ui.on_on_pre_unlock(move |path| {
        let s = state.lock().unwrap();
        let vault = s.vault.lock().unwrap();
        vault.files
            .load_session_file(path.as_str())
            .map(|f| f.header.hardware_enabled)
            .unwrap_or(false)
    });
}

fn register_open_tutorial<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_open_tutorial(move || {
        let ui = ui_handle.unwrap();

        let (default_path, default_device) = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();

            let folder_path = vault
                .default_session_path()
                .map(|p| {
                    p.parent()
                     .map(|parent| parent.display().to_string())
                     .unwrap_or_else(|| ".".to_string())
                })
                .unwrap_or_else(|_| ".".to_string());

            let device = std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "Meu_Pc".to_string());

            (folder_path, device)
        };

        ui.set_tutorial_default_path(default_path.into());
        ui.set_tutorial_default_device(default_device.into());
        ui.set_tutorial_step(0);
        ui.set_tutorial_error("".into());
        ui.set_tutorial_password("".into());
        ui.set_tutorial_loading(false);
        ui.set_show_tutorial(true);
    });
}

/// Resultado do processo de login. Corre em thread separada para não bloquear a UI.
enum LoginResult {
    Ok(String),   // caminho da sessão
    NoHmac,       // ficheiro sem HMAC - pede confirmação
    HmacFail,     // HMAC não corresponde
    Err(String),  // erro genérico
}

#[cfg(target_arch = "wasm32")]
fn resolve_wasm_xor_bytes<C, G, F>(
    state: &Arc<Mutex<AppState<C, G, F>>>,
) -> Option<Result<(String, String), String>>
where
    C: CryptoService + Clone,
    G: GeneratorService + Clone,
    F: FileService + Clone,
{
    let s = state.lock().unwrap();
    match (&s.xor_loaded_a, &s.xor_loaded_b) {
        (Some(a), Some(b)) => {
            Some(crate::services::file::FileServiceImpl::read_xor_files_bytes(a, b))
        }
        _ => None,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_wasm_xor_bytes<C, G, F>(
    _state: &Arc<Mutex<AppState<C, G, F>>>,
) -> Option<Result<(String, String), String>>
where
    C: CryptoService + Clone,
    G: GeneratorService + Clone,
    F: FileService + Clone,
{
    None
}

#[allow(clippy::too_many_arguments)]
fn run_login<C, G, F>(
    state:       &Arc<Mutex<AppState<C, G, F>>>,
    path:        &str,
    k1:          &str,
    k2:          &str,
    k_ext_input: &str,
    xor_path_a:  &str,
    xor_path_b:  &str,
    verify_hmac: bool,
) -> LoginResult
where
    C: CryptoService + Clone,
    G: GeneratorService + Clone,
    F: FileService + Clone,
{
    // Larga o Mutex antes do Argon2id (ver helpers::clone_vault).
    let vault = helpers::clone_vault(state);

    let session_file = match vault.files.load_session_file(path) {
        Ok(f)  => f,
        Err(e) => return LoginResult::Err(format!("Erro ao carregar ficheiro: {}", e)),
    };

    if verify_hmac && session_file.session_hmac.is_none() {
        return LoginResult::NoHmac;
    }

    let k_ext: Option<[u8; 32]> = if session_file.header.hardware_enabled {
        if k_ext_input.is_empty() {
            return LoginResult::Err(
                "Esta sessão requer fator físico (K_ext). Introduza o ficheiro ou hex.".into()
            );
        }
        match helpers::read_32_bytes(k_ext_input) {
            Ok(bytes) => Some(bytes),
            Err(e)    => return LoginResult::Err(format!("K_ext inválido: {}", e)),
        }
    } else {
        None
    };

    let wasm_xor_result = resolve_wasm_xor_bytes(state);

    let (resolved_k1, resolved_k2) = if let Some(result) = wasm_xor_result {
        match result {
            Ok((k1, k2)) => (k1, k2),
            Err(e)       => return LoginResult::Err(format!("Erro nos ficheiros XOR: {}", e)),
        }
    } else if !xor_path_a.is_empty() && !xor_path_b.is_empty() {
        match vault.files.read_xor_files(xor_path_a, xor_path_b) {
            Ok((k1, k2)) => (k1, k2),
            Err(e)       => return LoginResult::Err(format!("Erro nos ficheiros XOR: {}", e)),
        }
    } else {
        if k1.is_empty() {
            return LoginResult::Err("K1 não pode estar vazio.".into());
        }
        (k1.to_string(), k2.to_string())
    };

    let master_key = MasterKeyInput::new(resolved_k1, resolved_k2);
    if let Err(e) = master_key.validate() {
        return LoginResult::Err(format!("Chaves inválidas: {}", e));
    }

    let _backup = session_file.clone();

    let result = vault.open_session(
        session_file,
        &master_key,
        k_ext.as_ref(),
        verify_hmac,
    );

    match result {
        Ok(()) => {
            let _ = vault.set_last_session_path(Some(path.to_string()));
            LoginResult::Ok(path.to_string())
        }

        Err(CoreError::Session(SessionError::SessionFileTampered)) => {
            // HMAC falhou - informa a UI (que pedirá confirmação)
            LoginResult::HmacFail
        }

        Err(e) => LoginResult::Err(format!("{}", e)),
    }
}

/// Chamado após login bem-sucedido - popula todas as vistas
pub fn load_initial_ui_data<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    super::devices::refresh_device_list(ui, state);
    super::session::refresh_session_overview(ui, state);
    super::benchmark::refresh_local_state(ui, state);
    super::export::refresh_export_tree(ui, state);

    {
        let s     = state.lock().unwrap();
        let vault = s.vault.lock().unwrap();

        let default_path = vault
            .default_session_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "session.vaultseed".to_string());

        ui.set_login_default_path(default_path.into());
    }
}