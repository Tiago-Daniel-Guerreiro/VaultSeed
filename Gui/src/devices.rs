use slint::{ComponentHandle, ModelRc, VecModel};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use crate::core::{CryptoService, FileService, GeneratorService, MasterKeyInput};
use crate::models::Argon2Params;
use crate::AppWindow;

use crate::ui::{CalibrationResultItem, DeviceItem};

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
    register_select(ui, Arc::clone(&state));
    register_add(ui, Arc::clone(&state));
    register_rename(ui, Arc::clone(&state));
    register_edit_argon2(ui, Arc::clone(&state));
    register_edit_nonce(ui, Arc::clone(&state));
    register_regenerate_salt(ui, Arc::clone(&state));
    register_remove_request(ui, Arc::clone(&state));
    register_go_restrictions(ui, Arc::clone(&state));
    register_go_static_passwords(ui, Arc::clone(&state));
    register_calibrate_run(ui, Arc::clone(&state));
}

fn register_calibrate_run<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_devices_calibrate_run(move || {
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

        ui.set_devices_show_calibration_result(false);

        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let cal = crate::crypto::Calibrator::new()
                .with_min(min_ms)
                .with_max(max_ms)
                .run();

            let duration_ms = cal.duration.as_millis() as i32;
            let within_range = duration_ms >= min_ms as i32 && duration_ms <= max_ms as i32;

            let result = CalibrationResultItem {
                m_cost: cal.m_cost_kib as i32,
                t_cost: cal.t_cost as i32,
                p_cost: cal.p_cost as i32,
                duration_ms,
                within_range,
            };

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                ui.set_devices_calibration_result(result);
                ui.set_devices_show_calibration_result(true);
            }).unwrap();
        });
    });
}

pub fn refresh_device_list<C, G, F>(
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

    let devices = vault.list_devices().unwrap_or_default();

    let items: Vec<DeviceItem> = devices
        .iter()
        .map(|d| {
            let domain_count = vault
                .list_restrictions(d.uuid)
                .unwrap_or_default()
                .iter()
                .map(|r| vault.list_domains(r.uuid).unwrap_or_default().len())
                .sum::<usize>();

            let restriction_count = vault
                .list_restrictions(d.uuid)
                .unwrap_or_default()
                .len();

            let static_count = vault
                .list_static_passwords(d.uuid)
                .unwrap_or_default()
                .iter()
                .filter(|sp| !sp.compromised)
                .count();

            let static_folder_count = vault
                .list_static_password_folders(d.uuid)
                .unwrap_or_default()
                .len();

            DeviceItem {
                uuid:             d.uuid.to_string().into(),
                name:             d.name.clone().into(),
                argon2_m:         d.argon2.m_cost_kib as i32,
                argon2_t:         d.argon2.t_cost as i32,
                argon2_p:         d.argon2.p_cost as i32,
                salt_hex:         hex::encode(d.salt_device).into(),
                seed_nonce_hex:   hex::encode(d.seed_envelope.nonce).into(),
                seed_cipher_len:  d.seed_envelope.ciphertext.len() as i32,
                restriction_count: restriction_count as i32,
                domain_count:     domain_count as i32,
                static_pw_count:  static_count as i32,
                static_folder_count: static_folder_count as i32,
            }
        })
        .collect();

    let selected_index = match s.selected_device_uuid {
        Some(uuid) => devices
            .iter()
            .position(|d| d.uuid == uuid)
            .map(|i| i as i32)
            .unwrap_or(-1),
        None => -1,
    };

    let default_argon2 = Argon2Params { m_cost_kib: 65_536, t_cost: 3, p_cost: 4 };

    drop(vault);
    drop(s);

    ui.set_devices(ModelRc::new(Rc::new(VecModel::from(items))));
    ui.set_devices_default_argon2_m(default_argon2.m_cost_kib.to_string().into());
    ui.set_devices_default_argon2_t(default_argon2.t_cost.to_string().into());
    ui.set_devices_default_argon2_p(default_argon2.p_cost.to_string().into());
    ui.set_devices_selected_index(selected_index);

    if selected_index >= 0 {
        refresh_selected_device(ui, state);
    }
}

/// Actualiza apenas o painel de detalhe do dispositivo seleccionado
fn refresh_selected_device<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let uuid = match state.lock().unwrap().selected_device_uuid {
        Some(u) => u,
        None    => return,
    };

    let s     = state.lock().unwrap();
    let vault = s.vault.lock().unwrap();

    let device = match vault.get_device(uuid) {
        Ok(d)  => d,
        Err(_) => return,
    };

    let restriction_count = vault
        .list_restrictions(uuid)
        .unwrap_or_default()
        .len();

    let domain_count = vault
        .list_restrictions(uuid)
        .unwrap_or_default()
        .iter()
        .map(|r| vault.list_domains(r.uuid).unwrap_or_default().len())
        .sum::<usize>();

    let static_count = vault
        .list_static_passwords(uuid)
        .unwrap_or_default()
        .iter()
        .filter(|sp| !sp.compromised)
        .count();

    let static_folder_count = vault
        .list_static_password_folders(uuid)
        .unwrap_or_default()
        .len();

    let item = DeviceItem {
        uuid:             device.uuid.to_string().into(),
        name:             device.name.clone().into(),
        argon2_m:         device.argon2.m_cost_kib as i32,
        argon2_t:         device.argon2.t_cost as i32,
        argon2_p:         device.argon2.p_cost as i32,
        salt_hex:         hex::encode(device.salt_device).into(),
        seed_nonce_hex:   hex::encode(device.seed_envelope.nonce).into(),
        seed_cipher_len:  device.seed_envelope.ciphertext.len() as i32,
        restriction_count: restriction_count as i32,
        domain_count:     domain_count as i32,
        static_pw_count:  static_count as i32,
        static_folder_count: static_folder_count as i32,
    };

    ui.set_devices_selected_device(item);
}

fn register_select<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_devices_select(move |uuid_str| {
        let ui = ui_handle.unwrap();

        if uuid_str.is_empty() {
            state.lock().unwrap().selected_device_uuid = None;
            ui.set_devices_selected_index(-1);
            return;
        }

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                helpers::toast_error(&ui, &state, "UUID de dispositivo inválido.");
                return;
            }
        };

        {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            if let Err(e) = vault.select_device(uuid) {
                helpers::toast_error(&ui, &state, &format!("Erro ao selecionar dispositivo: {}", e));
                return;
            }
        }

        state.lock().unwrap().selected_device_uuid      = Some(uuid);
        state.lock().unwrap().selected_restriction_uuid = None;
        state.lock().unwrap().selected_domain_uuid      = None;
        state.lock().unwrap().selected_static_uuid      = None;

        refresh_device_list(&ui, &state);
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

    ui.on_on_devices_add(move |name, m_str, t_str, p_str, salt_str, seed_src, seed_val, k1, k2| {
        let ui = ui_handle.unwrap();

        if name.trim().is_empty() {
            ui.set_devices_error_add("O nome não pode estar vazio.".into());
            return;
        }

        let m = match helpers::parse_u32_with_min(m_str.as_str(), 65_536) {
            Ok(v)  => v,
            Err(e) => { ui.set_devices_error_add(e.into()); return; }
        };
        let t = match helpers::parse_u32_with_min(t_str.as_str(), 3) {
            Ok(v)  => v,
            Err(e) => { ui.set_devices_error_add(e.into()); return; }
        };
        let p = match helpers::parse_u32_with_min(p_str.as_str(), 4) {
            Ok(v)  => v,
            Err(e) => { ui.set_devices_error_add(e.into()); return; }
        };

        let name      = name.to_string();
        let salt_str  = salt_str.to_string();
        let seed_src  = seed_src.to_string();
        let seed_val  = seed_val.to_string();

        state.lock().unwrap().pending_add_device = Some(super::PendingAddDevice {
            name, m, t, p, salt: salt_str, seed_src, seed_val,
        });
        ui.set_devices_error_add("".into());

        handle_add_device_mk(&ui, &state, k1, k2);
    });
}

pub fn handle_add_device_mk<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    k1:    slint::SharedString,
    k2:    slint::SharedString,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let params = match state.lock().unwrap().pending_add_device.take() {
        Some(p) => p,
        None    => {
            helpers::toast_error(ui, state, "Erro interno: parâmetros de adição em falta.");
            return;
        }
    };

    let name     = params.name;
    let m        = params.m;
    let t        = params.t;
    let p        = params.p;
    let salt_str = params.salt;
    let seed_src = params.seed_src;
    let seed_val = params.seed_val;
    let k1       = k1.to_string();
    let k2       = k2.to_string();

    helpers::show_loading(ui, "A criar dispositivo...");

    let state     = Arc::clone(state);
    let ui_handle = ui.as_weak();

    helpers::spawn_async(move || {
        let result = run_add_device(
            &state,
            &name,
            m, t, p,
            &salt_str,
            &seed_src,
            &seed_val,
            &k1,
            &k2,
        );

        slint::invoke_from_event_loop(move || {
            let ui = ui_handle.unwrap();
            helpers::hide_loading(&ui);

            match result {
                Ok(uuid) => {
                    state.lock().unwrap().selected_device_uuid = Some(uuid);
                    refresh_device_list(&ui, &state);
                    ui.set_devices_show_add_form(false);
                    ui.set_devices_error_add("".into());
                    helpers::toast_success(
                        &ui,
                        &state,
                        &format!("Dispositivo criado: {}", uuid),
                    );
                }
                Err(e) => {
                    ui.set_devices_error_add(e.into());
                }
            }
        }).unwrap();
    });
}

#[allow(clippy::too_many_arguments)]
fn run_add_device<C, G, F>(
    state:    &Arc<Mutex<AppState<C, G, F>>>,
    name:     &str,
    m:        u32,
    t:        u32,
    p:        u32,
    salt_str: &str,
    seed_src: &str,
    seed_val: &str,
    k1:       &str,
    k2:       &str,
) -> Result<uuid::Uuid, String>
where
    C: CryptoService + Clone,
    G: GeneratorService + Clone,
    F: FileService + Clone,
{
    let vault      = helpers::clone_vault(state);
    let master_key = MasterKeyInput::new(k1.to_string(), k2.to_string());

    let argon2 = Argon2Params { m_cost_kib: m, t_cost: t, p_cost: p };
    let dev_uuid = uuid::Uuid::new_v4();

    let salt: [u8; 32] = if salt_str.is_empty() {
        vault.crypto.generate_random_32()
            .map_err(|e| format!("Erro ao gerar salt: {}", e))?
    } else {
        helpers::read_32_bytes(salt_str)
            .map_err(|e| format!("Salt inválido: {}", e))?
    };

    let envelope = match seed_src {
        "random" => {
            let seed = vault.crypto.generate_random_32()
                .map_err(|e| format!("Erro ao gerar seed: {}", e))?;
            vault.encrypt_device_seed_envelope(dev_uuid, &salt, &argon2, &master_key, &seed)
                .map_err(|e| format!("Erro ao encriptar seed: {}", e))?
        }

        "plaintext" => {
            let seed = helpers::read_32_bytes(seed_val)
                .map_err(|e| format!("Seed inválida: {}", e))?;
            vault.encrypt_device_seed_envelope(dev_uuid, &salt, &argon2, &master_key, &seed)
                .map_err(|e| format!("Erro ao encriptar seed: {}", e))?
        }

        "encrypted" => {
            let env = serde_json::from_str(seed_val)
                .or_else(|_| {
                    std::fs::read_to_string(seed_val)
                        .map_err(|e| e.to_string())
                        .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
                })
                .map_err(|e| format!("Seed encriptada inválida: {}", e))?;

            vault.decrypt_device_seed_envelope(dev_uuid, &salt, &argon2, &master_key, &env)
                .map_err(|_| "Não foi possível verificar a seed encriptada com estas chaves.".to_string())?;

            env
        }

        _ => return Err("Fonte de seed inválida.".into()),
    };

    vault.add_device_with_details(name, dev_uuid, salt, argon2, envelope)
        .map_err(|e| format!("Erro ao adicionar dispositivo: {}", e))
}

fn register_rename<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_devices_rename(move |uuid_str, new_name| {
        let ui = ui_handle.unwrap();

        if new_name.trim().is_empty() {
            ui.set_devices_error_rename("O nome não pode estar vazio.".into());
            return;
        }

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_devices_error_rename("UUID inválido.".into());
                return;
            }
        };

        let result = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.rename_device(uuid, new_name.as_str())
                .map_err(|e| format!("{}", e))
        };

        match result {
            Ok(()) => {
                ui.set_devices_error_rename("".into());
                refresh_device_list(&ui, &state);
                helpers::toast_success(&ui, &state, "Dispositivo renomeado.");
            }
            Err(e) => {
                ui.set_devices_error_rename(e.into());
            }
        }
    });
}

fn register_edit_argon2<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_devices_edit_argon2(move |uuid_str, m_str, t_str, p_str, k1, k2| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_devices_error_argon2("UUID inválido.".into());
                return;
            }
        };

        let m = match helpers::parse_u32_with_min(m_str.as_str(), 65_536) {
            Ok(v)  => v,
            Err(e) => { ui.set_devices_error_argon2(e.into()); return; }
        };
        let t = match helpers::parse_u32_with_min(t_str.as_str(), 3) {
            Ok(v)  => v,
            Err(e) => { ui.set_devices_error_argon2(e.into()); return; }
        };
        let p = match helpers::parse_u32_with_min(p_str.as_str(), 4) {
            Ok(v)  => v,
            Err(e) => { ui.set_devices_error_argon2(e.into()); return; }
        };

        handle_edit_argon2_mk(&ui, &state, &format!("edit-argon2:{}:{}:{}:{}", uuid, m, t, p), k1, k2);
    });
}

pub fn handle_edit_argon2_mk<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    action: &str,
    k1:    slint::SharedString,
    k2:    slint::SharedString,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let parts: Vec<&str> = action
        .trim_start_matches("edit-argon2:")
        .splitn(4, ':')
        .collect();

    if parts.len() < 4 {
        helpers::toast_error(ui, state, "Erro interno: parâmetros inválidos.");
        return;
    }

    let uuid = match uuid::Uuid::parse_str(parts[0]) {
        Ok(u)  => u,
        Err(_) => {
            helpers::toast_error(ui, state, "UUID inválido.");
            return;
        }
    };

    let m: u32 = parts[1].parse().unwrap_or(65_536);
    let t: u32 = parts[2].parse().unwrap_or(3);
    let p: u32 = parts[3].parse().unwrap_or(4);
    let k1     = k1.to_string();
    let k2     = k2.to_string();

    helpers::show_loading(ui, "A actualizar Argon2id do dispositivo...");

    let state     = Arc::clone(state);
    let ui_handle = ui.as_weak();

    helpers::spawn_async(move || {
        let result: Result<(), String> = {
            let vault      = helpers::clone_vault(&state);
            let master_key = MasterKeyInput::new(k1, k2);
            vault.update_device_argon2_and_regenerate_salt(
                uuid,
                &master_key,
                Argon2Params { m_cost_kib: m, t_cost: t, p_cost: p },
            ).map(|_| ()).map_err(|e| format!("{}", e))
        };

        slint::invoke_from_event_loop(move || {
            let ui = ui_handle.unwrap();
            helpers::hide_loading(&ui);

            match result {
                Ok(_) => {
                    refresh_device_list(&ui, &state);
                    ui.set_devices_error_argon2("".into());
                    helpers::toast_success(
                        &ui, &state,
                        "Argon2id e salt actualizados. Guarde a sessão.",
                    );
                }
                Err(e) => {
                    ui.set_devices_error_argon2(e.into());
                }
            }
        }).unwrap();
    });
}

fn register_edit_nonce<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_devices_edit_nonce(move |uuid_str, nonce_str, k1, k2| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_devices_error_nonce("UUID inválido.".into());
                return;
            }
        };

        handle_edit_nonce_mk(&ui, &state, &format!("edit-nonce:{}:{}", uuid, nonce_str), k1, k2);
    });
}

pub fn handle_edit_nonce_mk<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    action: &str,
    k1:    slint::SharedString,
    k2:    slint::SharedString,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let parts: Vec<&str> = action
        .trim_start_matches("edit-nonce:")
        .splitn(2, ':')
        .collect();

    if parts.len() < 2 {
        helpers::toast_error(ui, state, "Erro interno: parâmetros inválidos.");
        return;
    }

    let uuid      = match uuid::Uuid::parse_str(parts[0]) {
        Ok(u)  => u,
        Err(_) => {
            helpers::toast_error(ui, state, "UUID inválido.");
            return;
        }
    };
    let k1        = k1.to_string();
    let k2        = k2.to_string();

    helpers::show_loading(ui, "A actualizar nonce da seed...");

    let state     = Arc::clone(state);
    let ui_handle = ui.as_weak();

    helpers::spawn_async(move || {
        let result = {
            let vault      = helpers::clone_vault(&state);
            let master_key = MasterKeyInput::new(k1, k2);

            vault.update_device_seed_nonce(uuid, &master_key)
                .map(|_| ())
                .map_err(|e| format!("{}", e))
        };

        slint::invoke_from_event_loop(move || {
            let ui = ui_handle.unwrap();
            helpers::hide_loading(&ui);

            match result {
                Ok(()) => {
                    refresh_device_list(&ui, &state);
                    ui.set_devices_error_nonce("".into());
                    helpers::toast_success(
                        &ui, &state,
                        "Nonce actualizado. Guarde a sessão.",
                    );
                }
                Err(e) => {
                    ui.set_devices_error_nonce(e.into());
                }
            }
        }).unwrap();
    });
}

fn register_regenerate_salt<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_devices_regenerate_salt(move |uuid_str, k1, k2| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_devices_error_argon2("UUID inválido.".into());
                return;
            }
        };

        handle_regenerate_salt_mk(&ui, &state, &format!("regenerate-salt:{}", uuid), k1, k2);
    });
}

pub fn handle_regenerate_salt_mk<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    action: &str,
    k1:    slint::SharedString,
    k2:    slint::SharedString,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let uuid_str = action.trim_start_matches("regenerate-salt:");

    let uuid = match uuid::Uuid::parse_str(uuid_str) {
        Ok(u)  => u,
        Err(_) => {
            helpers::toast_error(ui, state, "UUID inválido.");
            return;
        }
    };

    let k1 = k1.to_string();
    let k2 = k2.to_string();

    helpers::show_loading(ui, "A regenerar salt do dispositivo...");

    let state     = Arc::clone(state);
    let ui_handle = ui.as_weak();

    helpers::spawn_async(move || {
        let result: Result<(), String> = {
            let vault      = helpers::clone_vault(&state);
            let master_key = MasterKeyInput::new(k1, k2);
            vault.regenerate_device_salt(uuid, &master_key)
                .map(|_| ())
                .map_err(|e| format!("{}", e))
        };

        slint::invoke_from_event_loop(move || {
            let ui = ui_handle.unwrap();
            helpers::hide_loading(&ui);

            match result {
                Ok(_) => {
                    refresh_device_list(&ui, &state);
                    ui.set_devices_error_argon2("".into());
                    helpers::toast_success(
                        &ui, &state,
                        "Salt regenerado. Guarde a sessão.",
                    );
                }
                Err(e) => {
                    helpers::toast_error(&ui, &state, &format!("Erro ao regenerar salt: {}", e));
                }
            }
        }).unwrap();
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

    ui.on_on_devices_remove_request(move |uuid_str| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                helpers::toast_error(&ui, &state, "UUID inválido.");
                return;
            }
        };

        let has_restrictions = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            !vault.list_restrictions(uuid).unwrap_or_default().is_empty()
        };

        if has_restrictions {
            helpers::toast_error(
                &ui,
                &state,
                "Remova todas as restrições deste dispositivo antes de o apagar.",
            );
            return;
        }

        helpers::ask_confirm(
            &ui,
            &state,
            "Remover dispositivo?",
            "Esta operação é irreversível. Todos os dados do dispositivo serão eliminados.",
            "danger",
            format!("remove-device:{}", uuid),
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
        vault.remove_device(uuid).map_err(|e| format!("{}", e))
    };

    match result {
        Ok(()) => {
            {
                let mut s = state.lock().unwrap();
                if s.selected_device_uuid == Some(uuid) {
                    s.selected_device_uuid      = None;
                    s.selected_restriction_uuid = None;
                    s.selected_domain_uuid      = None;
                    s.selected_static_uuid      = None;
                }
            }

            refresh_device_list(ui, state);
            helpers::toast_success(ui, state, "Dispositivo removido.");
        }
        Err(e) => {
            helpers::toast_error(ui, state, &format!("Erro ao remover: {}", e));
        }
    }
}

fn register_go_restrictions<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_devices_go_restrictions(move |uuid_str| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => return,
        };

        state.lock().unwrap().selected_device_uuid      = Some(uuid);
        state.lock().unwrap().selected_restriction_uuid = None;

        super::restrictions::refresh_restriction_list(&ui, &state);
        ui.set_active_sub_view(1);
    });
}

fn register_go_static_passwords<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_devices_go_static_passwords(move |uuid_str| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => return,
        };

        state.lock().unwrap().selected_device_uuid  = Some(uuid);
        state.lock().unwrap().selected_static_uuid  = None;
        state.lock().unwrap().selected_folder       = None;

        super::static_passwords::refresh_folder_list(&ui, &state);
        ui.set_active_sub_view(2);
    });
}