#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]

pub use vaultseed_core::{core, crypto, errors, generator, models, services};

#[cfg(not(target_family = "wasm"))]
pub use vaultseed_console as console;

#[cfg(any(feature = "android", feature = "desktop", feature = "extension"))]
pub use vaultseed_gui as gui;
#[cfg(any(feature = "android", feature = "desktop", feature = "extension"))]
pub use vaultseed_slint::*;

#[cfg(all(feature = "android", target_os = "android"))]
#[unsafe(no_mangle)]
fn android_main(app: slint::android::AndroidApp) {
    use std::process;
    use std::sync::{Arc, Mutex};

    use crate::AppWindow;
    use crate::core::VaultCore;
    use crate::gui::{register_all_handlers, AppState};
    use crate::models;
    use crate::services::crypto::CryptoServiceImpl;
    use crate::services::file::FileServiceImpl;
    use crate::services::generator::GeneratorServiceImpl;

    // init() usa `app`, mas precisamos de uma referência depois para integrações nativas
    let app_for_native = app.clone();

    slint::android::init(app).unwrap_or_else(|e| {
        eprintln!("Erro ao inicializar Android: {}", e);
        process::exit(1);
    });

    crate::gui::android_native::enable_fullscreen(&app_for_native);

    // Define HOME para que o FileService consiga resolver o diretório de config.
    // No Android, HOME não está definida por padrão; usamos o diretório de dados interno da app (sempre acessível sem permissões extra).
    if std::env::var_os("HOME").is_none() {
        if let Some(data_path) = app_for_native.internal_data_path() {
            std::env::set_var("HOME", data_path);
        }
    }

    let vault = VaultCore::new(
        models::LocalState::new(),
        CryptoServiceImpl::new(),
        GeneratorServiceImpl::new(),
        FileServiceImpl::new(),
        true,
    );

    let state = Arc::new(Mutex::new(AppState::new(vault)));

    let ui = AppWindow::new().unwrap_or_else(|e| {
        eprintln!("Erro ao criar janela: {}", e);
        process::exit(1);
    });

    crate::gui::init_app_window(&ui, &state);

    register_all_handlers(&ui, Arc::clone(&state));

    // A Activity auxiliar do seletor de ficheiros (SAF) entrega o resultado aqui
    crate::gui::android_native::store_handles(app_for_native, ui.as_weak());

    ui.run().unwrap_or_else(|e| {
        eprintln!("Erro no event loop: {}", e);
        process::exit(1);
    });
}

/// Lê o tamanho CSS (pixels lógicos) do `<canvas id="canvas">` do popup da extensão.
/// `None` se o elemento não existir mantém o tamanho por omissão do Slint em vez de forçar um valor arbitrário.
#[cfg(all(target_arch = "wasm32", feature = "extension"))]
fn canvas_logical_size() -> Option<slint::LogicalSize> {
    let window = web_sys::window()?;
    let document = window.document()?;
    let canvas = document.get_element_by_id("canvas")?;
    let rect = canvas.get_bounding_client_rect();
    let (width, height) = (rect.width(), rect.height());

    if width > 0.0 && height > 0.0 {
        Some(slint::LogicalSize::new(width as f32, height as f32))
    } else {
        None
    }
}

// Ponto de entrada da extensão de browser (WASM), chamado automaticamente pelo módulo gerado por `wasm-pack build --target web` - ver Wasm/extension/popup.html.
#[cfg(all(target_arch = "wasm32", feature = "extension"))]
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start_extension() {
    use std::sync::{Arc, Mutex};

    use crate::core::VaultCore;
    use crate::gui::{register_all_handlers, AppState};
    use crate::models;
    use crate::services::crypto::CryptoServiceImpl;
    use crate::services::file::FileServiceImpl;
    use crate::services::generator::GeneratorServiceImpl;
    use crate::AppWindow;

    console_error_panic_hook::set_once();

    let mut local_state = models::LocalState::new();
    local_state.wasm_browser_storage = true;

    let vault = VaultCore::new(
        local_state,
        CryptoServiceImpl::new(),
        GeneratorServiceImpl::new(),
        FileServiceImpl::new(),
        true,
    );

    let state = Arc::new(Mutex::new(AppState::new(vault)));
    let ui = AppWindow::new().expect("Erro ao criar janela");
    ui.set_is_wasm(true);

    if let Some(size) = canvas_logical_size() {
        ui.window().set_size(slint::WindowSize::Logical(size));
    }

    crate::gui::init_app_window(&ui, &state);

    register_all_handlers(&ui, Arc::clone(&state));

    if let Some(size) = canvas_logical_size() {
        let ui_weak = ui.as_weak();
        slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.window().set_size(slint::WindowSize::Logical(size));
            }
        })
        .expect("Erro ao agendar reaplicação do tamanho da janela");
    }

    ui.run().expect("Erro no event loop");
}
