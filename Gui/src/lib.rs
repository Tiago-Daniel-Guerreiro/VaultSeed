pub use vaultseed_core::{core, crypto, errors, generator, models, services};
pub use vaultseed_slint::*;
pub use vaultseed_slint as ui;

#[cfg(target_os = "android")]
pub mod android_native;
pub mod auth;
pub mod benchmark;
pub mod devices;
pub mod domains;
pub mod export;
pub mod helpers;
pub mod localstate;
pub mod restrictions;
pub mod search;
pub mod session;
pub mod static_passwords;
pub mod tutorial;

pub use self::localstate as local_state;

use std::sync::{Arc, Mutex};
use slint::ComponentHandle;

use crate::core::{CryptoService, FileService, GeneratorService, VaultCore};

pub struct AppState<C, G, F>
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    pub vault: Arc<Mutex<VaultCore<C, G, F>>>,

    pub selected_device_uuid: Option<uuid::Uuid>,
    pub selected_restriction_uuid: Option<uuid::Uuid>,
    pub selected_domain_uuid: Option<uuid::Uuid>,
    pub selected_static_uuid: Option<uuid::Uuid>,
    pub selected_folder: Option<String>,
    pub static_compromised_mode: bool,
    pub session_path: String,

    /// Acção pendente após ConfirmDialog confirmar
    pub pending_confirm_action: Option<String>,

    /// Parâmetros pendentes de adição de dispositivo (após MasterKeyDialog)
    pub pending_add_device: Option<PendingAddDevice>,
    
    /// Parâmetros pendentes de rotação de chaves (após ConfirmDialog)
    pub pending_rotate_keys: Option<PendingRotateKeys>,

    /// Parâmetros pendentes de remoção de pasta (após ConfirmDialog)
    pub pending_remove_folder: Option<(uuid::Uuid, String)>,

    /// Parâmetros pendentes de login a reabrir sem verificação HMAC
    pub pending_login: Option<PendingLogin>,

    /// Bits das listas de caracteres ativas no editor de "Definir padrão" (default_mask global da restrição). 
    pub selected_mask_bits: std::collections::BTreeSet<u8>,

    /// Bits das listas de caracteres ativas ao configurar um card "Personalizado" no painel "Gerar card/conjunto".
    pub card_mask_bits: std::collections::BTreeSet<u8>,

    /// Índice (0-based) da posição actualmente em vista no painel "Posição X".
    pub viewing_position_index: Option<usize>,

    /// Tipo de card a configurar no painel "Gerar card/conjunto": "default" | "custom" | "fixed", ou None se o painel está fechado.
    pub creating_card_kind: Option<String>,

    /// Geometria (width_px, x_offset_px) de cada posição da sequência actualmente exibida - cache usada para resolver o alvo de um arrasto (drag-and-drop) sem reconsultar o vault a cada movimento.
    pub drag_item_geometry: Vec<(i32, i32)>,

    /// x_offset (px) imediatamente após a última posição - início do espaço livre (preview de criação + zona de lixo).
    pub drag_sequence_end_x: i32,

    /// Bytes dos shares XOR carregados
    pub xor_loaded_a: Option<Vec<u8>>,
    pub xor_loaded_b: Option<Vec<u8>>,
}

/// Parâmetros de adição de dispositivo aguardando K1/K2
#[derive(Clone)]
pub struct PendingAddDevice {
    pub name:     String,
    pub m:        u32,
    pub t:        u32,
    pub p:        u32,
    pub salt:     String,
    pub seed_src: String,
    pub seed_val: String,
}

/// Parâmetros de rotação de chaves aguardando confirmação
#[derive(Clone)]
pub struct PendingRotateKeys {
    pub old_k1: String,
    pub old_k2: String,
    pub new_k1: String,
    pub new_k2: String,
    pub path:   String,
}

/// Parâmetros de login aguardando confirmação para reabrir sem HMAC
#[derive(Clone)]
pub struct PendingLogin {
    pub path:       String,
    pub k1:         String,
    pub k2:         String,
    pub k_ext:      String,
    pub xor_path_a: String,
    pub xor_path_b: String,
}

impl<C, G, F> AppState<C, G, F>
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    pub fn new(vault: VaultCore<C, G, F>) -> Self {
        let session_path = vault
            .default_session_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "session.vaultseed".to_string());

        Self {
            vault:                     Arc::new(Mutex::new(vault)),
            selected_device_uuid:      None,
            selected_restriction_uuid: None,
            selected_domain_uuid:      None,
            selected_static_uuid:      None,
            selected_folder:           None,
            static_compromised_mode:   false,
            session_path,
            pending_confirm_action:    None,
            pending_add_device:        None,
            pending_rotate_keys:       None,
            pending_remove_folder:     None,
            pending_login:             None,
            selected_mask_bits:        std::collections::BTreeSet::new(),
            card_mask_bits:            std::collections::BTreeSet::new(),
            viewing_position_index:    None,
            creating_card_kind:        None,
            drag_item_geometry:        Vec::new(),
            drag_sequence_end_x:       0,
            xor_loaded_a:              None,
            xor_loaded_b:              None,
        }
    }
}

/// Defaults da UI antes de `register_all_handlers` - usado pelos três pontos de entrada (desktop, Android, extensão WASM).
pub fn init_app_window<C, G, F>(
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

    let default_path = vault
        .default_session_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "session.vaultseed".to_string());

    ui.set_login_default_path(default_path.into());
    ui.set_app_version(env!("CARGO_PKG_VERSION").into());
    ui.set_is_wasm(cfg!(target_arch = "wasm32"));
    ui.set_login_hardware_enabled(false);
    ui.set_login_hmac_warning(false);
    ui.set_login_error("".into());
    ui.set_is_unlocked(false);
    ui.set_active_view(0);
    ui.set_active_sub_view(0);
    ui.set_show_tutorial(false);
    ui.set_confirm_show(false);
    ui.set_loading_show(false);
    ui.set_toast_show(false);
}

pub fn register_all_handlers<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    auth::register(ui, Arc::clone(&state));
    tutorial::register(ui, Arc::clone(&state));
    devices::register(ui, Arc::clone(&state));
    restrictions::register(ui, Arc::clone(&state));
    domains::register(ui, Arc::clone(&state));
    static_passwords::register(ui, Arc::clone(&state));
    session::register(ui, Arc::clone(&state));
    local_state::register(ui, Arc::clone(&state));
    export::register(ui, Arc::clone(&state));
    benchmark::register(ui, Arc::clone(&state));
    search::register(ui, Arc::clone(&state));

    register_global_handlers(ui, Arc::clone(&state));
}

fn register_global_handlers<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    register_lock(ui, Arc::clone(&state));
    register_save_shortcut(ui, Arc::clone(&state));
    register_confirm_ok(ui, Arc::clone(&state));
    register_confirm_cancel(ui, Arc::clone(&state));
    register_clipboard_copy(ui, Arc::clone(&state));
    register_compute_mixed_font_lines(ui);
}

/// Quebra de linha de texto misto (emoji + normal) de acordo com a largura
fn register_compute_mixed_font_lines(ui: &AppWindow) {
    ui.on_compute_mixed_font_lines(|text, limit| {
        let lines = helpers::split_emoji_runs(text.as_str(), limit.max(0) as usize);
        slint::ModelRc::new(std::rc::Rc::new(slint::VecModel::from(lines)))
    });
}

fn register_clipboard_copy<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.global::<crate::ui::ClipboardActions>().on_copy(move |value| {
        let ui = ui_handle.unwrap();
        helpers::copy_to_clipboard_with_toast(&ui, &state, &value, "Valor");
    });
}

fn register_lock<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();
    let state2    = Arc::clone(&state);

    ui.on_on_lock(move || {
        let ui = ui_handle.unwrap();

        let has_unsaved = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.has_unsaved_changes().unwrap_or(false)
        };

        if has_unsaved {
            ui.set_lock_unsaved_is_quit(false);
            ui.set_lock_unsaved_confirm_show(true);
        } else {
            handle_lock_confirmed(&ui, &state);
        }
    });

    let ui_handle = ui.as_weak();
    ui.on_on_lock_force(move || {
        let ui = ui_handle.unwrap();
        handle_lock_confirmed(&ui, &state2);
    });

    ui.on_on_quit_force(move || {
        let _ = slint::quit_event_loop();
    });
}

/// Executa o bloqueio efectivo (após confirmação)
pub fn handle_lock_confirmed<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    {
        let s = state.lock().unwrap();
        let _ = s.vault.lock().unwrap().close_session();
    }

    {
        let mut s = state.lock().unwrap();
        s.selected_device_uuid      = None;
        s.selected_restriction_uuid = None;
        s.selected_domain_uuid      = None;
        s.selected_static_uuid      = None;
        s.selected_folder           = None;
        s.static_compromised_mode   = false;
        s.pending_confirm_action    = None;
        s.pending_add_device        = None;
        s.pending_rotate_keys       = None;
        s.pending_remove_folder     = None;
        s.pending_login             = None;
        s.selected_mask_bits.clear();
        s.card_mask_bits.clear();
        s.viewing_position_index = None;
        s.creating_card_kind     = None;
        s.xor_loaded_a           = None;
        s.xor_loaded_b           = None;
    }

    ui.set_is_unlocked(false);
    ui.set_active_view(0);
    ui.set_active_sub_view(0);
    ui.set_main_menu_open(false);
    ui.set_login_view(0);
    ui.set_login_error("".into());
    ui.set_login_hmac_warning(false);
    helpers::hide_all_overlays(ui);
}

fn register_save_shortcut<C, G, F>(
    ui:    &AppWindow,
    _state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_open_save_panel(move || {
        let ui = ui_handle.unwrap();
        ui.set_active_view(1);
        ui.set_session_active_panel(2);
    });
}

fn register_confirm_ok<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_confirm_ok(move || {
        let ui = ui_handle.unwrap();
        ui.set_confirm_show(false);

        let action = {
            let mut s = state.lock().unwrap();
            s.pending_confirm_action.take()
        };

        if let Some(action) = action {
            dispatch_confirm_action(&ui, &state, &action);
        }
    });
}

fn register_confirm_cancel<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_confirm_cancel(move || {
        let ui = ui_handle.unwrap();
        ui.set_confirm_show(false);
        state.lock().unwrap().pending_confirm_action = None;
    });
}

/// Chamado após o utilizador confirmar no ConfirmDialog. Cada acção tem o formato "action-type:uuid" ou "action-type:uuid1:uuid2"
pub fn dispatch_confirm_action<C, G, F>(
    ui:     &AppWindow,
    state:  &Arc<Mutex<AppState<C, G, F>>>,
    action: &str,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    // Prefixo antes do primeiro ':' identifica a acção; 
    let (tag, rest) = match action.split_once(':') {
        Some((tag, rest)) => (tag, Some(rest)),
        None              => (action, None),
    };

    match tag {
        "remove-device" => {
            if let Some(uuid_str) = rest {
                if let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) {
                    devices::handle_remove_confirmed(ui, state, uuid);
                }
            }
        }

        "remove-restriction" => {
            if let Some(uuid_str) = rest {
                if let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) {
                    restrictions::handle_remove_confirmed(ui, state, uuid);
                }
            }
        }

        "clear-sequence" => {
            if let Some(uuid_str) = rest {
                if let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) {
                    restrictions::handle_clear_sequence_confirmed(ui, state, uuid);
                }
            }
        }

        "remove-position" => {
            // "remove-position:restriction_uuid:index"
            if let Some(rest) = rest {
                let parts: Vec<&str> = rest.splitn(2, ':').collect();
                if parts.len() == 2 {
                    if let (Ok(uuid), Ok(index)) = (uuid::Uuid::parse_str(parts[0]), parts[1].parse::<usize>()) {
                        restrictions::handle_remove_position_confirmed(ui, state, uuid, index);
                    }
                }
            }
        }

        "remove-charlist" => {
            // "remove-charlist:r_uuid:cl_uuid"
            if let Some(rest) = rest {
                let parts: Vec<&str> = rest.splitn(2, ':').collect();
                if parts.len() == 2 {
                    if let (Ok(r_uuid), Ok(cl_uuid)) = (
                        uuid::Uuid::parse_str(parts[0]),
                        uuid::Uuid::parse_str(parts[1]),
                    ) {
                        restrictions::handle_remove_charlist_confirmed(ui, state, r_uuid, cl_uuid);
                    }
                }
            }
        }

        "remove-domain" => {
            if let Some(uuid_str) = rest {
                if let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) {
                    domains::handle_remove_confirmed(ui, state, uuid);
                }
            }
        }

        "delete-frozen" => {
            // "delete-frozen:domain_uuid:record_uuid"
            if let Some(rest) = rest {
                let parts: Vec<&str> = rest.splitn(2, ':').collect();
                if parts.len() == 2 {
                    if let (Ok(domain_uuid), Ok(record_uuid)) = (
                        uuid::Uuid::parse_str(parts[0]),
                        uuid::Uuid::parse_str(parts[1]),
                    ) {
                        domains::handle_delete_frozen_confirmed(ui, state, domain_uuid, record_uuid);
                    }
                }
            }
        }

        "remove-static" => {
            if let Some(uuid_str) = rest {
                if let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) {
                    static_passwords::handle_remove_confirmed(ui, state, uuid);
                }
            }
        }

        "remove-folder" => {
            // Parâmetros lidos do estado (evita partir nomes de pasta com ':')
            let pending = state.lock().unwrap().pending_remove_folder.take();
            if let Some((device_uuid, folder_name)) = pending {
                static_passwords::handle_remove_folder_confirmed(
                    ui, state, device_uuid, folder_name,
                );
            }
        }

        "regenerate-salt"    => session::handle_regenerate_salt_confirmed(ui, state),
        "rotate-keys"        => session::handle_rotate_keys_confirmed(ui, state),
        "delete-local-state" => local_state::handle_delete_local_confirmed(ui, state),
        "delete-session-file" => session::handle_delete_session_file_confirmed(ui, state),

        "use-last-session-path" => {
            if let Some(path) = rest {
                let path = path.to_string();
                if !path.trim().is_empty() {
                    ui.set_login_default_path(path.clone().into());
                    ui.set_session_default_path(path.clone().into());
                    state.lock().unwrap().session_path = path.clone();
                    helpers::toast_info(ui, state, &format!("Caminho da sessão definido para: {}", path));
                }
            }
        }

        _ => {
            helpers::toast_error(
                ui, state,
                &format!("Acção de confirmação desconhecida: {}", action),
            );
        }
    }
}

