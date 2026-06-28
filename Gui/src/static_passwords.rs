use slint::{ComponentHandle, ModelRc, VecModel};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use crate::core::{CryptoService, FileService, GeneratorService, MasterKeyInput};
use crate::models::StaticPasswordPlaintext;
use crate::AppWindow;

use crate::ui::{FolderItem, StaticPasswordItem, StaticPasswordDetail};

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
    register_select_folder(ui, Arc::clone(&state));
    register_select_password(ui, Arc::clone(&state));
    register_add(ui, Arc::clone(&state));
    register_view(ui, Arc::clone(&state));
    register_view_notes(ui, Arc::clone(&state));
    register_copy(ui, Arc::clone(&state));
    register_close_value(ui);
    register_close_notes(ui);
    register_mark_compromised(ui, Arc::clone(&state));
    register_remove_request(ui, Arc::clone(&state));
    register_rename(ui, Arc::clone(&state));
    register_edit_notes(ui, Arc::clone(&state));
    register_rename_folder(ui, Arc::clone(&state));
    register_remove_folder(ui, Arc::clone(&state));
    register_create_folder(ui, Arc::clone(&state));
    register_toggle_compromised_mode(ui, Arc::clone(&state));
    register_back(ui, Arc::clone(&state));
}

pub fn refresh_folder_list<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let device_uuid = match state.lock().unwrap().selected_device_uuid {
        Some(u) => u,
        None    => return,
    };

    let s     = state.lock().unwrap();
    let vault = s.vault.lock().unwrap();

    let all_passwords = vault.list_static_passwords(device_uuid).unwrap_or_default();
    let folder_names  = vault.list_static_password_folders(device_uuid).unwrap_or_default();

    let items: Vec<FolderItem> = folder_names
        .iter()
        .map(|name| {
            let normal_count = all_passwords
                .iter()
                .filter(|sp| &sp.folder_path == name && !sp.compromised)
                .count();

            let compromised_count = all_passwords
                .iter()
                .filter(|sp| &sp.folder_path == name && sp.compromised)
                .count();

            FolderItem {
                name:             name.clone().into(),
                display_name:     if name.is_empty() {
                                      "(raiz)".into()
                                  } else {
                                      name.clone().into()
                                  },
                normal_count:     normal_count as i32,
                compromised_count: compromised_count as i32,
            }
        })
        .collect();

    let selected_folder = s.selected_folder.clone();
    let selected_folder_index = match &selected_folder {
        Some(f) => folder_names
            .iter()
            .position(|n| n == f)
            .map(|i| i as i32)
            .unwrap_or(-1),
        None => -1,
    };

    let device_name = vault
        .get_device(device_uuid)
        .map(|d| d.name.clone())
        .unwrap_or_default();

    let compromised_mode = s.static_compromised_mode;

    drop(vault);
    drop(s);

    ui.set_static_folders(ModelRc::new(Rc::new(VecModel::from(items))));
    ui.set_static_selected_folder_index(selected_folder_index);
    ui.set_static_device_name(device_name.into());
    ui.set_static_device_uuid(device_uuid.to_string().into());
    ui.set_static_show_compromised_mode(compromised_mode);

    if selected_folder_index >= 0 {
        if let Some(folder) = selected_folder {
            refresh_password_list(ui, state, &folder, compromised_mode);
        }
    }
}

/// Actualiza a lista de senhas dentro da pasta seleccionada
fn refresh_password_list<C, G, F>(
    ui:              &AppWindow,
    state:           &Arc<Mutex<AppState<C, G, F>>>,
    folder:          &str,
    compromised_mode: bool,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let device_uuid = match state.lock().unwrap().selected_device_uuid {
        Some(u) => u,
        None    => return,
    };

    let s     = state.lock().unwrap();
    let vault = s.vault.lock().unwrap();

    let all_passwords = vault.list_static_passwords(device_uuid).unwrap_or_default();

    let items: Vec<StaticPasswordItem> = all_passwords
        .iter()
        .filter(|sp| sp.folder_path == folder && sp.compromised == compromised_mode)
        .map(|sp| StaticPasswordItem {
            uuid:        sp.uuid.to_string().into(),
            label:       sp.label.clone().into(),
            folder:      sp.folder_path.clone().into(),
            compromised: sp.compromised,
        })
        .collect();

    let selected_uuid = s.selected_static_uuid;
    let selected_index = match selected_uuid {
        Some(uuid) => items
            .iter()
            .position(|it| it.uuid.as_str() == uuid.to_string())
            .map(|i| i as i32)
            .unwrap_or(-1),
        None => -1,
    };

    drop(vault);
    drop(s);

    ui.set_static_passwords(ModelRc::new(Rc::new(VecModel::from(items))));
    ui.set_static_selected_pw_index(selected_index);

    if selected_index >= 0 {
        refresh_password_metadata(ui, state, selected_uuid.unwrap());
    }
}

/// Actualiza metadata da senha seleccionada (sem desencriptar o valor)
fn refresh_password_metadata<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    uuid:  uuid::Uuid,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let s     = state.lock().unwrap();
    let vault = s.vault.lock().unwrap();

    let sp = match vault.list_static_passwords(
        s.selected_device_uuid.unwrap_or_default()
    ) {
        Ok(list) => list.into_iter().find(|sp| sp.uuid == uuid),
        Err(_)   => None,
    };

    if let Some(sp) = sp {
        // Se já estávamos a mostrar este mesmo registo (ex: depois de renomear),
        // mantém o valor/notas já desencriptados em vez de os limpar.
        let previous = ui.get_static_selected_detail();
        let same_item = previous.uuid == sp.uuid.to_string();

        let detail = StaticPasswordDetail {
            uuid:        sp.uuid.to_string().into(),
            label:       sp.label.clone().into(),
            folder:      sp.folder_path.clone().into(),
            value:       if same_item { previous.value } else { "".into() },
            notes:       if same_item { previous.notes } else { "".into() },
            compromised: sp.compromised,
        };
        ui.set_static_selected_detail(detail);
        if !same_item {
            ui.set_static_value_visible(false);
            ui.set_static_notes_visible(false);
        }
    }
}

fn register_select_folder<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_static_select_folder(move |folder_name, compromised_mode| {
        let ui = ui_handle.unwrap();

        {
            let mut s              = state.lock().unwrap();
            s.selected_folder      = Some(folder_name.to_string());
            s.selected_static_uuid = None;
            s.static_compromised_mode = compromised_mode;
        }

        ui.set_static_selected_pw_index(-1);
        ui.set_static_show_add_form(false);
        ui.set_static_value_visible(false);
        ui.set_static_notes_visible(false);

        refresh_folder_list(&ui, &state);
    });
}

fn register_select_password<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_static_select_password(move |uuid_str| {
        let ui = ui_handle.unwrap();

        if uuid_str.is_empty() {
            state.lock().unwrap().selected_static_uuid = None;
            ui.set_static_selected_pw_index(-1);
            ui.set_static_value_visible(false);
            ui.set_static_notes_visible(false);
            return;
        }

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                helpers::toast_error(&ui, &state, "UUID inválido.");
                return;
            }
        };

        state.lock().unwrap().selected_static_uuid = Some(uuid);

        ui.set_static_show_add_form(false);
        ui.set_static_value_visible(false);
        ui.set_static_notes_visible(false);
        ui.set_static_error_decrypt("".into());
        ui.set_static_error_compromise("".into());

        refresh_password_metadata(&ui, &state, uuid);

        let folder = state.lock().unwrap().selected_folder.clone();
        let compromised_mode = state.lock().unwrap().static_compromised_mode;
        if let Some(f) = folder {
            refresh_password_list(&ui, &state, &f, compromised_mode);
        }
    });
}

fn register_add<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_static_add(move |label, value, notes, k1, k2| {
        let ui = ui_handle.unwrap();

        if label.trim().is_empty() {
            ui.set_static_error_add("A etiqueta não pode estar vazia.".into());
            return;
        }
        if value.trim().is_empty() {
            ui.set_static_error_add("O valor não pode estar vazio.".into());
            return;
        }
        if k1.is_empty() || k2.is_empty() {
            ui.set_static_error_add("K1 e K2 são obrigatórios.".into());
            return;
        }

        let device_uuid = match state.lock().unwrap().selected_device_uuid {
            Some(u) => u,
            None    => {
                ui.set_static_error_add("Nenhum dispositivo seleccionado.".into());
                return;
            }
        };

        let folder = state
            .lock()
            .unwrap()
            .selected_folder
            .clone()
            .unwrap_or_default();

        let label  = label.to_string();
        let value  = value.to_string();
        let notes  = notes.to_string();
        let k1     = k1.to_string();
        let k2     = k2.to_string();
        let state  = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::show_loading(&ui, "A guardar senha estática...");
        ui.set_static_error_add("".into());

        helpers::spawn_async(move || {
            let vault = helpers::clone_vault(&state);
            let master_key = MasterKeyInput::new(k1, k2);

            let plaintext = StaticPasswordPlaintext {
                label:       label.clone(),
                value,
                notes,
                compromised: false,
            };

            let result = vault.add_static_password(
                device_uuid,
                &folder,
                &label,
                plaintext,
                &master_key,
            ).map_err(|e| format!("{}", e));

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok(uuid) => {
                        state.lock().unwrap().selected_static_uuid = Some(uuid);
                        let compromised_mode = state.lock().unwrap().static_compromised_mode;
                        refresh_folder_list(&ui, &state);
                        refresh_password_list(&ui, &state, &folder, compromised_mode);
                        ui.set_static_show_add_form(false);
                        ui.set_static_error_add("".into());
                        helpers::toast_success(
                            &ui, &state,
                            &format!("Senha '{}' guardada.", label),
                        );
                    }
                    Err(e) => {
                        ui.set_static_error_add(e.into());
                    }
                }
            }).unwrap();
        });
    });
}

/// O valor é mostrado temporariamente e limpo após 15 segundos.
fn register_view<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_static_view(move |uuid_str, k1, k2| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_static_error_decrypt("UUID inválido.".into());
                return;
            }
        };

        if k1.is_empty() || k2.is_empty() {
            ui.set_static_error_decrypt("K1 e K2 são obrigatórios.".into());
            return;
        }

        let k1        = k1.to_string();
        let k2        = k2.to_string();
        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::show_loading(&ui, "A desencriptar senha...");
        ui.set_static_error_decrypt("".into());

        helpers::spawn_async(move || {
            let result = run_decrypt(&state, uuid, &k1, &k2);

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok(plaintext) => {
                        let mut detail = ui.get_static_selected_detail();
                        detail.value   = plaintext.value.clone().into();
                        detail.notes   = plaintext.notes.clone().into();
                        ui.set_static_selected_detail(detail);
                        ui.set_static_value_visible(true);
                        ui.set_static_error_decrypt("".into());
                    }
                    Err(e) => {
                        ui.set_static_error_decrypt(e.into());
                    }
                }
            }).unwrap();
        });
    });
}

fn register_copy<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_static_copy(move |uuid_str, k1, k2| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                helpers::toast_error(&ui, &state, "UUID inválido.");
                return;
            }
        };

        if k1.is_empty() && k2.is_empty() {
            let detail = ui.get_static_selected_detail();
            if !detail.value.is_empty() {
                helpers::copy_to_clipboard_with_toast(
                    &ui, &state,
                    detail.value.as_str(),
                    "Senha estática",
                );
            }
            return;
        }

        let k1        = k1.to_string();
        let k2        = k2.to_string();
        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let result = run_decrypt(&state, uuid, &k1, &k2);

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();

                match result {
                    Ok(plaintext) => {
                        helpers::copy_to_clipboard_with_toast(
                            &ui, &state,
                            &plaintext.value,
                            "Senha estática",
                        );
                    }
                    Err(e) => {
                        helpers::toast_error(&ui, &state, &format!("Erro: {}", e));
                    }
                }
            }).unwrap();
        });
    });
}

/// Mostra as notas temporariamente, atrás do mesmo gate de autenticação do valor.
fn register_view_notes<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_static_view_notes(move |uuid_str, k1, k2| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_static_error_decrypt("UUID inválido.".into());
                return;
            }
        };

        if k1.is_empty() || k2.is_empty() {
            ui.set_static_error_decrypt("K1 e K2 são obrigatórios.".into());
            return;
        }

        let k1        = k1.to_string();
        let k2        = k2.to_string();
        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::show_loading(&ui, "A desencriptar notas...");
        ui.set_static_error_decrypt("".into());

        helpers::spawn_async(move || {
            let result = run_decrypt(&state, uuid, &k1, &k2);

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok(plaintext) => {
                        let mut detail = ui.get_static_selected_detail();
                        detail.notes   = plaintext.notes.clone().into();
                        ui.set_static_selected_detail(detail);
                        ui.set_static_notes_visible(true);
                        ui.set_static_error_decrypt("".into());
                    }
                    Err(e) => {
                        ui.set_static_error_decrypt(e.into());
                    }
                }
            }).unwrap();
        });
    });
}

fn register_close_value(ui: &AppWindow) {
    let ui_handle = ui.as_weak();

    ui.on_on_static_close_value(move || {
        let ui = ui_handle.unwrap();
        ui.set_static_value_visible(false);
        let mut detail = ui.get_static_selected_detail();
        detail.value = "".into();
        ui.set_static_selected_detail(detail);
    });
}

fn register_close_notes(ui: &AppWindow) {
    let ui_handle = ui.as_weak();

    ui.on_on_static_close_notes(move || {
        let ui = ui_handle.unwrap();
        ui.set_static_notes_visible(false);
        let mut detail = ui.get_static_selected_detail();
        detail.notes = "".into();
        ui.set_static_selected_detail(detail);
    });
}

pub fn handle_view_password<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    uuid:  uuid::Uuid,
    k1:    slint::SharedString,
    k2:    slint::SharedString,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let k1        = k1.to_string();
    let k2        = k2.to_string();
    let state     = Arc::clone(state);
    let ui_handle = ui.as_weak();

    helpers::show_loading(ui, "A desencriptar senha...");

    helpers::spawn_async(move || {
        let result = run_decrypt(&state, uuid, &k1, &k2);

        slint::invoke_from_event_loop(move || {
            let ui = ui_handle.unwrap();
            helpers::hide_loading(&ui);

            match result {
                Ok(plaintext) => {
                    let mut detail = ui.get_static_selected_detail();
                    detail.value   = plaintext.value.clone().into();
                    detail.notes   = plaintext.notes.clone().into();
                    ui.set_static_selected_detail(detail);
                    ui.set_static_value_visible(true);
                }
                Err(e) => {
                    ui.set_static_error_decrypt(e.into());
                }
            }
        }).unwrap();
    });
}

pub fn handle_copy_password<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    uuid:  uuid::Uuid,
    k1:    slint::SharedString,
    k2:    slint::SharedString,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let k1        = k1.to_string();
    let k2        = k2.to_string();
    let state     = Arc::clone(state);
    let ui_handle = ui.as_weak();

    helpers::spawn_async(move || {
        let result = run_decrypt(&state, uuid, &k1, &k2);

        slint::invoke_from_event_loop(move || {
            let ui = ui_handle.unwrap();

            match result {
                Ok(plaintext) => {
                    helpers::copy_to_clipboard_with_toast(
                        &ui, &state,
                        &plaintext.value,
                        "Senha estática",
                    );
                }
                Err(e) => {
                    helpers::toast_error(&ui, &state, &format!("Erro: {}", e));
                }
            }
        }).unwrap();
    });
}

fn register_mark_compromised<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_static_mark_compromised(move |uuid_str, k1, k2| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_static_error_compromise("UUID inválido.".into());
                return;
            }
        };

        if k1.is_empty() || k2.is_empty() {
            ui.set_static_error_compromise("K1 e K2 são obrigatórios.".into());
            return;
        }

        let k1        = k1.to_string();
        let k2        = k2.to_string();
        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::show_loading(&ui, "A marcar como comprometida...");
        ui.set_static_error_compromise("".into());

        helpers::spawn_async(move || {
            let result = {
                let s          = state.lock().unwrap();
                let vault      = s.vault.lock().unwrap();
                let master_key = MasterKeyInput::new(k1, k2);
                vault.mark_static_password_compromised(uuid, &master_key)
                    .map_err(|e| format!("{}", e))
            };

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok(()) => {
                        state.lock().unwrap().selected_static_uuid = None;
                        ui.set_static_selected_pw_index(-1);
                        ui.set_static_value_visible(false);
                        ui.set_static_notes_visible(false);
                        ui.set_static_error_compromise("".into());

                        refresh_folder_list(&ui, &state);

                        let folder = state.lock().unwrap().selected_folder.clone();
                        let compromised_mode = state.lock().unwrap().static_compromised_mode;
                        if let Some(f) = folder {
                            refresh_password_list(&ui, &state, &f, compromised_mode);
                        }

                        helpers::toast_success(
                            &ui, &state,
                            "Senha marcada como comprometida.",
                        );
                    }
                    Err(e) => {
                        ui.set_static_error_compromise(e.into());
                    }
                }
            }).unwrap();
        });
    });
}

/// Renomear exige a chave mestra: o label tem uma cópia encriptada usada para verificação 
fn register_rename<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_static_rename(move |uuid_str, new_label, k1, k2| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                helpers::toast_error(&ui, &state, "UUID inválido.");
                return;
            }
        };

        if k1.is_empty() || k2.is_empty() {
            ui.set_static_error_decrypt("K1 e K2 são obrigatórios.".into());
            return;
        }

        let k1        = k1.to_string();
        let k2        = k2.to_string();
        let new_label = new_label.to_string();
        let state2    = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::show_loading(&ui, "A renomear senha estática...");
        ui.set_static_error_decrypt("".into());

        helpers::spawn_async(move || {
            let result = {
                let vault      = helpers::clone_vault(&state2);
                let master_key = MasterKeyInput::new(k1, k2);
                vault.rename_static_password(uuid, &new_label, &master_key)
                    .map_err(|e| format!("{}", e))
            };

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok(()) => {
                        ui.set_static_error_decrypt("".into());
                        let (folder, compromised) = {
                            let s = state2.lock().unwrap();
                            (s.selected_folder.clone().unwrap_or_default(), s.static_compromised_mode)
                        };
                        refresh_password_list(&ui, &state2, &folder, compromised);
                        refresh_password_metadata(&ui, &state2, uuid);
                        helpers::toast_success(&ui, &state2, "Senha estática renomeada.");
                    }
                    Err(e) => {
                        helpers::toast_error(&ui, &state2, &format!("Erro ao renomear: {}", e));
                    }
                }
            }).unwrap();
        });
    });
}

fn register_edit_notes<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_static_edit_notes(move |uuid_str, new_notes, k1, k2| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                helpers::toast_error(&ui, &state, "UUID inválido.");
                return;
            }
        };

        if k1.is_empty() || k2.is_empty() {
            ui.set_static_error_decrypt("K1 e K2 são obrigatórios.".into());
            return;
        }

        let k1        = k1.to_string();
        let k2        = k2.to_string();
        let new_notes = new_notes.to_string();
        let state2    = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::show_loading(&ui, "A guardar notas...");
        ui.set_static_error_decrypt("".into());

        helpers::spawn_async(move || {
            let result = run_edit_notes(&state2, uuid, &new_notes, &k1, &k2);

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok(plaintext) => {
                        let mut detail = ui.get_static_selected_detail();
                        detail.value = plaintext.value.clone().into();
                        detail.notes = plaintext.notes.clone().into();
                        ui.set_static_selected_detail(detail);
                        ui.set_static_value_visible(true);
                        ui.set_static_error_decrypt("".into());
                    }
                    Err(e) => {
                        ui.set_static_error_decrypt(e.into());
                    }
                }
            }).unwrap();
        });
    });
}

fn register_remove_request<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_static_remove_request(move |uuid_str| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                helpers::toast_error(&ui, &state, "UUID inválido.");
                return;
            }
        };

        helpers::ask_confirm(
            &ui,
            &state,
            "Remover senha estática?",
            "Remove permanentemente esta senha e o seu valor encriptado. Operação irreversível.",
            "danger",
            format!("remove-static:{}", uuid),
        );
    });
}

pub fn handle_remove_confirmed<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    uuid:  uuid::Uuid,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let result = {
        let s     = state.lock().unwrap();
        let vault = s.vault.lock().unwrap();
        vault.remove_static_password(uuid).map_err(|e| format!("{}", e))
    };

    match result {
        Ok(()) => {
            {
                let mut s = state.lock().unwrap();
                if s.selected_static_uuid == Some(uuid) {
                    s.selected_static_uuid = None;
                }
            }

            ui.set_static_selected_pw_index(-1);
            ui.set_static_value_visible(false);
            ui.set_static_notes_visible(false);

            let folder           = state.lock().unwrap().selected_folder.clone();
            let compromised_mode = state.lock().unwrap().static_compromised_mode;

            refresh_folder_list(ui, state);

            if let Some(f) = folder {
                refresh_password_list(ui, state, &f, compromised_mode);
            }

            helpers::toast_success(ui, state, "Senha removida.");
        }
        Err(e) => {
            helpers::toast_error(ui, state, &format!("Erro ao remover: {}", e));
        }
    }
}

fn register_rename_folder<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_static_rename_folder(move |old_name, new_name| {
        let ui = ui_handle.unwrap();

        if new_name.trim().is_empty() {
            ui.set_static_error_rename("O novo nome não pode estar vazio.".into());
            return;
        }

        if old_name == new_name {
            ui.set_static_error_rename("O nome é igual ao actual.".into());
            return;
        }

        let device_uuid = match state.lock().unwrap().selected_device_uuid {
            Some(u) => u,
            None    => {
                ui.set_static_error_rename("Nenhum dispositivo seleccionado.".into());
                return;
            }
        };

        let old_name = old_name.to_string();
        let new_name = new_name.to_string();

        let result = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.rename_static_password_folder(device_uuid, &old_name, &new_name)
                .map_err(|e| format!("{}", e))
        };

        match result {
            Ok(()) => {
                {
                    let mut s = state.lock().unwrap();
                    if s.selected_folder.as_deref() == Some(&old_name) {
                        s.selected_folder = Some(new_name.clone());
                    }
                }

                ui.set_static_error_rename("".into());
                refresh_folder_list(&ui, &state);
                helpers::toast_success(
                    &ui, &state,
                    &format!("Pasta '{}' renomeada para '{}'.", old_name, new_name),
                );
            }
            Err(e) => {
                ui.set_static_error_rename(e.into());
            }
        }
    });
}

/// Move todas as senhas para a raiz antes de remover a pasta.
fn register_remove_folder<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_static_remove_folder(move |folder_name| {
        let ui = ui_handle.unwrap();

        if folder_name.is_empty() {
            helpers::toast_error(&ui, &state, "Não é possível remover a pasta raiz.");
            return;
        }

        let device_uuid = match state.lock().unwrap().selected_device_uuid {
            Some(u) => u,
            None    => return,
        };

        // O nome da pasta pode conter ':', por isso é guardado no estado.
        state.lock().unwrap().pending_remove_folder =
            Some((device_uuid, folder_name.to_string()));

        helpers::ask_confirm(
            &ui,
            &state,
            "Remover pasta?",
            "As senhas desta pasta serão movidas para a raiz.",
            "warning",
            "remove-folder".to_string(),
        );
    });
}

pub fn handle_remove_folder_confirmed<C, G, F>(
    ui:          &AppWindow,
    state:       &Arc<Mutex<AppState<C, G, F>>>,
    device_uuid: uuid::Uuid,
    folder_name: String,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let result = {
        let s     = state.lock().unwrap();
        let vault = s.vault.lock().unwrap();
        vault.clear_static_password_folder(device_uuid, &folder_name)
            .map_err(|e| format!("{}", e))
    };

    match result {
        Ok(()) => {
            {
                let mut s = state.lock().unwrap();
                if s.selected_folder.as_deref() == Some(&folder_name) {
                    s.selected_folder      = Some(String::new());
                    s.selected_static_uuid = None;
                }
            }

            ui.set_static_error_remove("".into());
            refresh_folder_list(ui, state);

            let compromised_mode = state.lock().unwrap().static_compromised_mode;
            refresh_password_list(ui, state, "", compromised_mode);

            helpers::toast_success(
                ui, state,
                &format!("Pasta '{}' removida. Senhas movidas para a raiz.", folder_name),
            );
        }
        Err(e) => {
            ui.set_static_error_remove(e.into());
        }
    }
}

/// Cria uma pasta vazia (transitória, sem qualquer senha).
fn register_create_folder<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_static_create_folder(move |name| {
        let ui = ui_handle.unwrap();

        let name = name.trim().to_string();

        if name.is_empty() {
            ui.set_static_error_create_folder("O nome da pasta não pode estar vazio.".into());
            return;
        }

        let device_uuid = match state.lock().unwrap().selected_device_uuid {
            Some(u) => u,
            None    => {
                ui.set_static_error_create_folder("Nenhum dispositivo seleccionado.".into());
                return;
            }
        };

        let result = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.add_static_folder(device_uuid, &name).map_err(|e| format!("{}", e))
        };

        if let Err(e) = result {
            ui.set_static_error_create_folder(e.into());
            return;
        }

        state.lock().unwrap().selected_folder = Some(name.clone());

        ui.set_static_error_create_folder("".into());
        ui.set_static_show_folder_mgmt(false);
        refresh_folder_list(&ui, &state);
        helpers::toast_success(&ui, &state, &format!("Pasta '{}' criada.", name));
    });
}

fn register_toggle_compromised_mode<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_static_toggle_compromised_mode(move || {
        let ui = ui_handle.unwrap();

        let new_mode = {
            let mut s             = state.lock().unwrap();
            s.static_compromised_mode = !s.static_compromised_mode;
            s.selected_static_uuid    = None;
            s.static_compromised_mode
        };

        ui.set_static_selected_pw_index(-1);
        ui.set_static_value_visible(false);
        ui.set_static_notes_visible(false);
        ui.set_static_show_compromised_mode(new_mode);

        let folder = state.lock().unwrap().selected_folder.clone();
        if let Some(f) = folder {
            refresh_password_list(&ui, &state, &f, new_mode);
        }
    });
}

fn register_back<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_static_back(move || {
        let ui = ui_handle.unwrap();

        {
            let mut s              = state.lock().unwrap();
            s.selected_folder      = None;
            s.selected_static_uuid = None;
            s.static_compromised_mode = false;
        }

        ui.set_static_value_visible(false);
        ui.set_static_notes_visible(false);

        super::devices::refresh_device_list(&ui, &state);
        ui.set_active_sub_view(0);
    });
}

fn run_decrypt<C, G, F>(
    state: &Arc<Mutex<AppState<C, G, F>>>,
    uuid:  uuid::Uuid,
    k1:    &str,
    k2:    &str,
) -> Result<StaticPasswordPlaintext, String>
where
    C: CryptoService + Clone,
    G: GeneratorService + Clone,
    F: FileService + Clone,
{
    let vault      = helpers::clone_vault(state);
    let master_key = MasterKeyInput::new(k1.to_string(), k2.to_string());

    vault
        .get_static_password(uuid, &master_key)
        .map_err(|e| format!("Chaves incorrectas ou senha corrompida: {}", e))
}

fn run_edit_notes<C, G, F>(
    state:     &Arc<Mutex<AppState<C, G, F>>>,
    uuid:      uuid::Uuid,
    new_notes: &str,
    k1:        &str,
    k2:        &str,
) -> Result<StaticPasswordPlaintext, String>
where
    C: CryptoService + Clone,
    G: GeneratorService + Clone,
    F: FileService + Clone,
{
    let vault      = helpers::clone_vault(state);
    let master_key = MasterKeyInput::new(k1.to_string(), k2.to_string());

    let current = vault
        .get_static_password(uuid, &master_key)
        .map_err(|e| format!("Chaves incorrectas ou senha corrompida: {}", e))?;

    let new_plaintext = StaticPasswordPlaintext {
        label:       current.label.clone(),
        value:       current.value.clone(),
        notes:       new_notes.to_string(),
        compromised: current.compromised,
    };

    vault
        .update_static_password(uuid, new_plaintext.clone(), &master_key)
        .map_err(|e| format!("{}", e))?;

    Ok(new_plaintext)
}