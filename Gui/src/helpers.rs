use slint::{ComponentHandle, SharedString, Timer, TimerMode, VecModel, ModelRc};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::core::{CryptoService, FileService, GeneratorService, VaultCore};
use crate::AppWindow;
use super::AppState;

thread_local! {
    static TOAST_TIMER: RefCell<Option<Timer>> = const { RefCell::new(None) };
}

/// Chave fixa em localStorage usada para a sessão quando o utilizador ativa"Usar armazenamento do browser" nas Definições (wasm) 
pub const WASM_BROWSER_SESSION_KEY: &str = "vaultseed-browser-session";

/// Lê se "Usar armazenamento do browser" está activo nas Definições.
pub fn wasm_browser_storage_active<C, G, F>(state: &Arc<Mutex<AppState<C, G, F>>>) -> bool
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let s     = state.lock().unwrap();
    let vault = s.vault.lock().unwrap();
    vault.get_local_state().wasm_browser_storage
}

pub fn clone_vault<C, G, F>(state: &Arc<Mutex<AppState<C, G, F>>>) -> VaultCore<C, G, F>
where
    C: CryptoService + Clone,
    G: GeneratorService + Clone,
    F: FileService + Clone,
{
    let s     = state.lock().unwrap();
    let vault = s.vault.lock().unwrap();
    vault.clone()
}

#[cfg(not(target_arch = "wasm32"))]
pub fn spawn_async<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    std::thread::spawn(f);
}

#[cfg(target_arch = "wasm32")]
pub fn spawn_async<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    f();
}

pub fn hide_all_overlays(ui: &AppWindow) {
    ui.set_loading_show(false);
    ui.set_confirm_show(false);
    ui.set_toast_show(false);
}

pub fn show_loading(ui: &AppWindow, message: &str) {
    ui.set_loading_message(message.into());
    ui.set_loading_show(true);
}

pub fn hide_loading(ui: &AppWindow) {
    ui.set_loading_show(false);
}

/// Auto-hide após 5 segundos; cancela qualquer toast anterior.
pub fn show_toast<C, G, F>(
    ui:    &AppWindow,
    _state: &Arc<Mutex<AppState<C, G, F>>>,
    message: &str,
    variant: &str, // "info" | "success" | "error" | "warning"
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    TOAST_TIMER.with(|cell| {
        if let Some(timer) = cell.borrow_mut().take() {
            timer.stop();
        }
    });

    ui.set_toast_message(message.into());
    ui.set_toast_variant(variant.into());
    ui.set_toast_show(true);

    let ui_handle = ui.as_weak();
    let timer = Timer::default();
    timer.start(TimerMode::SingleShot, Duration::from_secs(5), move || {
        if let Some(ui) = ui_handle.upgrade() {
            ui.set_toast_show(false);
        }
    });

    TOAST_TIMER.with(|cell| {
        *cell.borrow_mut() = Some(timer);
    });
}

pub fn toast_success<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    message: &str,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    show_toast(ui, state, message, "success");
}

pub fn toast_error<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    message: &str,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    show_toast(ui, state, message, "error");
}

pub fn toast_info<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    message: &str,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    show_toast(ui, state, message, "info");
}

pub fn ask_confirm<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    title:   &str,
    message: &str,
    variant: &str, // "danger" | "warning" | "info"
    action:  String, // ID da acção (ex: "remove-device-abc123")
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    state.lock().unwrap().pending_confirm_action = Some(action);

    ui.set_confirm_title(title.into());
    ui.set_confirm_message(message.into());
    ui.set_confirm_variant(variant.into());
    ui.set_confirm_ok("Confirmar".into());
    ui.set_confirm_cancel("Cancelar".into());
    ui.set_confirm_show(true);
}

pub fn dispatch_confirm_action<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    action: &str,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    if action.starts_with("remove-device:") {
        let uuid_str = action.trim_start_matches("remove-device:");
        if let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) {
            super::devices::handle_remove_confirmed(ui, state, uuid);
        }
    } else if action.starts_with("remove-restriction:") {
        let uuid_str = action.trim_start_matches("remove-restriction:");
        if let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) {
            super::restrictions::handle_remove_confirmed(ui, state, uuid);
        }
    } else if action.starts_with("remove-domain:") {
        let uuid_str = action.trim_start_matches("remove-domain:");
        if let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) {
            super::domains::handle_remove_confirmed(ui, state, uuid);
        }
    } else if action.starts_with("remove-static:") {
        let uuid_str = action.trim_start_matches("remove-static:");
        if let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) {
            super::static_passwords::handle_remove_confirmed(ui, state, uuid);
        }
    } else if action.starts_with("delete-frozen:") {
        let parts: Vec<&str> = action.trim_start_matches("delete-frozen:").split(':').collect();
        if parts.len() == 2 {
            if let (Ok(domain_uuid), Ok(record_uuid)) = (
                uuid::Uuid::parse_str(parts[0]),
                uuid::Uuid::parse_str(parts[1]),
            ) {
                super::domains::handle_delete_frozen_confirmed(ui, state, domain_uuid, record_uuid);
            }
        }
    } else if action.starts_with("remove-folder:") {
        let parts: Vec<&str> = action.trim_start_matches("remove-folder:").splitn(2, ':').collect();
        if parts.len() == 2 {
            if let Ok(device_uuid) = uuid::Uuid::parse_str(parts[0]) {
                let folder_name = parts[1];
                super::static_passwords::handle_remove_folder_confirmed(ui, state, device_uuid, folder_name.to_string());
            }
        }
    }
}

pub fn u32_to_str(value: u32) -> SharedString {
    value.to_string().into()
}

pub fn i32_to_str(value: i32) -> SharedString {
    value.to_string().into()
}

pub fn usize_to_str(value: usize) -> SharedString {
    value.to_string().into()
}

pub fn opt_str(value: Option<String>) -> SharedString {
    value.unwrap_or_default().into()
}

pub fn vec_to_model<T: Clone + 'static>(vec: Vec<T>) -> ModelRc<T> {
    Rc::new(VecModel::from(vec)).into()
}

/// Formata millibits para display (ex: 128500 -> "128.5")
pub fn format_millibits(millibits: u64) -> String {
    let bits = millibits as f64 / 1000.0;
    format!("{:.1}", bits)
}

pub fn format_timestamp(ts: &chrono::DateTime<chrono::Utc>) -> String {
    ts.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Copia texto para a clipboard via `UIPasteboard.generalPasteboard` (`setString:`). Groundwork não testado - iOS não está nos scripts de build/CI atuais.
#[cfg(target_os = "ios")]
fn copy_to_clipboard_ios(value: &str) -> Result<(), String> {
    use objc::{class, msg_send, sel, sel_impl};
    use objc::runtime::Object;

    const NS_UTF8_STRING_ENCODING: usize = 4;

    unsafe {
        let pasteboard: *mut Object = msg_send![class!(UIPasteboard), generalPasteboard];
        if pasteboard.is_null() {
            return Err("UIPasteboard indisponível".to_string());
        }

        let alloc: *mut Object = msg_send![class!(NSString), alloc];
        let ns_string: *mut Object = msg_send![
            alloc,
            initWithBytes: value.as_ptr()
            length: value.len()
            encoding: NS_UTF8_STRING_ENCODING
        ];

        let _: () = msg_send![pasteboard, setString: ns_string];
        let _: () = msg_send![ns_string, release];
    }

    Ok(())
}

#[allow(dead_code)]
pub(crate) fn copy_to_clipboard(_value: &str) -> Result<(), String> {
    #[cfg(all(
        feature = "clipboard",
        not(any(target_arch = "wasm32", target_os = "android", target_os = "ios"))
    ))]
    {
        use arboard::Clipboard;
        let mut clipboard = Clipboard::new().map_err(|e| e.to_string())?;
        clipboard.set_text(_value).map_err(|e| e.to_string())
    }

    #[cfg(target_os = "android")]
    {
        return crate::android_native::set_clipboard_text(_value);
    }

    #[cfg(target_os = "ios")]
    {
        return copy_to_clipboard_ios(_value);
    }

    #[cfg(not(any(
        all(feature = "clipboard", not(any(target_arch = "wasm32", target_os = "android", target_os = "ios"))),
        target_os = "android",
        target_os = "ios",
    )))]
    {
        let _ = _value;
        Err("Clipboard não disponível nesta plataforma.".to_string())
    }
}

pub fn copy_to_clipboard_with_toast<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    value: &str,
    label: &str,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    #[cfg(all(
        feature = "clipboard",
        not(any(target_arch = "wasm32", target_os = "android", target_os = "ios"))
    ))]
    {
        use arboard::Clipboard;
        match Clipboard::new() {
            Ok(mut clipboard) => {
                if let Err(e) = clipboard.set_text(value) {
                    toast_error(ui, state, &format!("Erro ao copiar: {}", e));
                } else {
                    toast_success(ui, state, &format!("{} copiada para a clipboard", label));
                }
            }
            Err(e) => {
                toast_error(ui, state, &format!("Erro ao aceder clipboard: {}", e));
            }
        }
    }

    #[cfg(target_os = "android")]
    {
        match crate::android_native::set_clipboard_text(value) {
            Ok(()) => toast_success(ui, state, &format!("{} copiada para a clipboard", label)),
            Err(e) => toast_error(ui, state, &format!("Erro ao copiar: {}", e)),
        }
        return;
    }

    #[cfg(target_os = "ios")]
    {
        match copy_to_clipboard_ios(value) {
            Ok(()) => toast_success(ui, state, &format!("{} copiada para a clipboard", label)),
            Err(e) => toast_error(ui, state, &format!("Erro ao copiar: {}", e)),
        }
        return;
    }

    #[cfg(not(any(
        all(feature = "clipboard", not(any(target_arch = "wasm32", target_os = "android", target_os = "ios"))),
        target_os = "android",
        target_os = "ios",
    )))]
    {
        let _ = (value, label);
        toast_error(ui, state, "Clipboard não disponível nesta plataforma.");
    }
}

/// Parse de máscara - decimal ou 0xHEX
pub fn parse_mask(input: &str) -> Result<u32, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("Entrada vazia".into());
    }
    if let Some(rest) = s.strip_prefix("0x") {
        u32::from_str_radix(rest, 16).map_err(|e| format!("Parse error: {}", e))
    } else {
        s.parse::<u32>().map_err(|e| format!("Parse error: {}", e))
    }
}

pub fn parse_u32_with_min(input: &str, min: u32) -> Result<u32, String> {
    let value = input
        .trim()
        .parse::<u32>()
        .map_err(|e| format!("Valor inválido: {}", e))?;

    if value < min {
        return Err(format!("Valor mínimo: {}", min));
    }

    Ok(value)
}

pub fn parse_csv_elements(input: &str) -> Result<Vec<String>, String> {
    let mut elements: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_escape = false;

    for c in input.chars() {
        match c {
            '{' if !in_escape => {
                in_escape = true;
            }
            '}' if in_escape => {
                in_escape = false;
                elements.push(current.clone());
                current.clear();
            }
            ',' if !in_escape => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    elements.push(trimmed);
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }

    if in_escape {
        return Err("Carácter especial sem '}' de fecho.".to_string());
    }

    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        elements.push(trimmed);
    }

    if elements.is_empty() {
        Err("Lista vazia".into())
    } else {
        Ok(elements)
    }
}

pub fn format_csv_elements(elements: &[String]) -> String {
    elements
        .iter()
        .map(|e| {
            if e.trim().is_empty() || e.trim() != e || e.contains(',') {
                format!("{{{}}}", e)
            } else {
                e.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn validate_match(a: &str, b: &str, field_name: &str) -> Result<(), String> {
    if a != b {
        Err(format!("{} não corresponde", field_name))
    } else {
        Ok(())
    }
}

pub fn validate_not_empty(s: &str, field_name: &str) -> Result<(), String> {
    if s.trim().is_empty() {
        Err(format!("{} não pode estar vazio", field_name))
    } else {
        Ok(())
    }
}

/// Lê 32 bytes de hex string ou ficheiro
pub fn read_32_bytes(input: &str) -> Result<[u8; 32], String> {
    if let Ok(bytes) = std::fs::read(input) {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Ok(arr);
        } else {
            return Err(format!("Ficheiro tem {} bytes, esperado 32", bytes.len()));
        }
    }

    let hex_input = input.trim().strip_prefix("0x").unwrap_or(input.trim());
    let bytes = hex::decode(hex_input).map_err(|e| format!("Hex inválido: {}", e))?;

    if bytes.len() != 32 {
        return Err(format!("Hex tem {} bytes, esperado 32", bytes.len()));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub fn bit_to_slot(bit: u8) -> u8 {
    bit - crate::core::USER_CHAR_LIST_BIT_MIN + 1
}

pub fn slot_to_bit(slot: u8) -> u8 {
    crate::core::USER_CHAR_LIST_BIT_MIN + (slot - 1)
}

/// Ex: 7 -> "0,1,2"
pub fn mask_bits_string(mask: u32) -> String {
    (0..32u8)
        .filter(|&bit| (mask & (1u32 << bit)) != 0)
        .map(|bit| bit.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Divide o texto em linhas compostas por blocos ("runs") separando emojis de texto normal. 
pub fn split_emoji_runs(text: &str, chars_per_line: usize) -> Vec<crate::ui::TextLine> {
    let mut lines: Vec<crate::ui::TextLine> = Vec::new();
    let mut current_runs: Vec<crate::ui::TextRun> = Vec::new();
    let mut chars_in_line = 0usize;
    let limit = chars_per_line.max(6);

    for c in text.chars() {
        if chars_in_line >= limit {
            lines.push(crate::ui::TextLine {
                runs: ModelRc::new(Rc::new(VecModel::from(std::mem::take(&mut current_runs)))),
            });
            chars_in_line = 0;
        }

        let is_emoji = crate::core::char_in_emoji_font(c);
        match current_runs.last_mut() {
            Some(run) if run.emoji == is_emoji => {
                let mut s = run.text.to_string();
                s.push(c);
                run.text = s.into();
            }
            _ => {
                current_runs.push(crate::ui::TextRun {
                    text:  c.to_string().into(),
                    emoji: is_emoji,
                });
            }
        }
        chars_in_line += 1;
    }

    if !current_runs.is_empty() {
        lines.push(crate::ui::TextLine {
            runs: ModelRc::new(Rc::new(VecModel::from(current_runs))),
        });
    }

    lines
}

/// Converte máscara para nomes legíveis de categorias.
pub fn mask_categories_string(mask: u32, char_lists: &[crate::models::CharacterList]) -> String {
    let parts: Vec<&str> = (0..crate::core::USER_CHAR_LIST_BIT_MIN)
        .filter(|&bit| mask & (1u32 << bit) != 0)
        .filter_map(|bit| char_lists.iter().find(|c| c.bit == bit))
        .map(|c| c.name.as_str())
        .collect();

    let custom = (crate::core::USER_CHAR_LIST_BIT_MIN..=crate::core::USER_CHAR_LIST_BIT_MAX)
        .filter(|&b| mask & (1u32 << b) != 0)
        .count();
    let mut out = parts.join(", ");
    if custom > 0 {
        if !out.is_empty() {
            out.push_str(", ");
        }
        out.push_str(&format!("+{} personalizada(s)", custom));
    }
    if out.is_empty() {
        out.push_str("(vazio)");
    }
    out
}