use slint::{ComponentHandle, ModelRc, VecModel};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use crate::core::{
    CryptoService, FileService, GeneratorService,
    MasterKeyInput, PasswordRequest,
};
use crate::models::MaskOrLiteral;
use crate::AppWindow;

use crate::ui::{
    DomainItem, PasswordResultItem, CompromisedVersionItem,
    FrozenDetailItem, RestrictionChoiceItem,
};

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
    register_view_password(ui, Arc::clone(&state));
    register_copy_password(ui, Arc::clone(&state));
    register_compromise(ui, Arc::clone(&state));
    register_change_restriction(ui, Arc::clone(&state));
    register_select_version(ui, Arc::clone(&state));
    register_view_frozen(ui, Arc::clone(&state));
    register_copy_frozen(ui, Arc::clone(&state));
    register_delete_frozen(ui, Arc::clone(&state));
    register_remove_request(ui, Arc::clone(&state));
    register_close_password(ui);
    register_go_back(ui, Arc::clone(&state));
}

pub fn refresh_domain_list<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let restriction_uuid = match state.lock().unwrap().selected_restriction_uuid {
        Some(u) => u,
        None    => return,
    };

    let s     = state.lock().unwrap();
    let vault = s.vault.lock().unwrap();

    let domains = vault.list_domains(restriction_uuid).unwrap_or_default();

    let items: Vec<DomainItem> = domains
        .iter()
        .map(|d| {
            let restriction_name = vault
                .get_restriction(d.restriction_uuid)
                .map(|r| r.name.clone())
                .unwrap_or_default();

            DomainItem {
                uuid:             d.uuid.to_string().into(),
                identifier:       d.identifier_canonical.clone().into(),
                active_variation: d.active_variation as i32,
                compromise_count: d.compromise_history.len() as i32,
                restriction_uuid: d.restriction_uuid.to_string().into(),
                restriction_name: restriction_name.into(),
            }
        })
        .collect();

    let selected_index = match s.selected_domain_uuid {
        Some(uuid) => domains
            .iter()
            .position(|d| d.uuid == uuid)
            .map(|i| i as i32)
            .unwrap_or(-1),
        None => -1,
    };

    let restriction = vault.get_restriction(restriction_uuid).ok();

    let restriction_name = restriction
        .as_ref()
        .map(|r| r.name.clone())
        .unwrap_or_default();

    let has_format = restriction
        .as_ref()
        .map(|r| r.generation.format_sequence.as_ref().is_some_and(|seq| !seq.is_empty()))
        .unwrap_or(false);

    let device_name = restriction
        .as_ref()
        .and_then(|r| vault.get_device(r.device_uuid).ok())
        .map(|d| d.name.clone())
        .unwrap_or_default();

    drop(vault);
    drop(s);

    ui.set_domains(ModelRc::new(Rc::new(VecModel::from(items))));
    ui.set_domains_selected_index(selected_index);
    ui.set_domains_restriction_name(restriction_name.into());
    ui.set_domains_device_name(device_name.into());
    ui.set_domains_restriction_uuid(restriction_uuid.to_string().into());
    ui.set_domains_restriction_has_format(has_format);

    if selected_index >= 0 {
        refresh_domain_detail(ui, state);
    }
}

fn refresh_domain_detail<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let domain_uuid = match state.lock().unwrap().selected_domain_uuid {
        Some(u) => u,
        None    => return,
    };

    let s     = state.lock().unwrap();
    let vault = s.vault.lock().unwrap();

    let domain = match vault.get_domain(domain_uuid) {
        Ok(d)  => d,
        Err(_) => return,
    };

    let restriction_name = vault
        .get_restriction(domain.restriction_uuid)
        .map(|r| r.name.clone())
        .unwrap_or_default();

    let selected_item = DomainItem {
        uuid:             domain.uuid.to_string().into(),
        identifier:       domain.identifier_canonical.clone().into(),
        active_variation: domain.active_variation as i32,
        compromise_count: domain.compromise_history.len() as i32,
        restriction_uuid: domain.restriction_uuid.to_string().into(),
        restriction_name: restriction_name.into(),
    };

    // Versões comprometidas
    let versions: Vec<CompromisedVersionItem> = {
        let mut hist = domain.compromise_history.clone();
        hist.sort_by_key(|r| std::cmp::Reverse(r.timestamp));
        hist.iter()
            .map(|r| CompromisedVersionItem {
                uuid:      r.uuid.to_string().into(),
                variation: r.variation as i32,
                timestamp: helpers::format_timestamp(&r.timestamp).into(),
                frozen_id: r.frozen_config.identifier_frozen.clone().into(),
            })
            .collect()
    };

    // Restrições disponíveis para mudar
    let device_uuid = vault
        .get_restriction(domain.restriction_uuid)
        .map(|r| r.device_uuid)
        .unwrap_or_default();

    let available_restrictions: Vec<RestrictionChoiceItem> = vault
        .list_restrictions(device_uuid)
        .unwrap_or_default()
        .iter()
        .map(|r| RestrictionChoiceItem {
            uuid:       r.uuid.to_string().into(),
            name:       r.name.clone().into(),
            is_current: r.uuid == domain.restriction_uuid,
        })
        .collect();

    drop(vault);
    drop(s);

    ui.set_domains_selected_domain(selected_item);
    ui.set_domains_compromised_versions(
        ModelRc::new(Rc::new(VecModel::from(versions)))
    );
    ui.set_domains_available_restrictions(
        ModelRc::new(Rc::new(VecModel::from(available_restrictions)))
    );
    ui.set_domains_selected_version_index(-1);
    ui.set_domains_show_password_card(false);
    ui.set_domains_password_visible(false);
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

    ui.on_on_domains_select(move |uuid_str| {
        let ui = ui_handle.unwrap();

        if uuid_str.is_empty() {
            state.lock().unwrap().selected_domain_uuid = None;
            ui.set_domains_selected_index(-1);
            return;
        }

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                helpers::toast_error(&ui, &state, "UUID de domínio inválido.");
                return;
            }
        };

        {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            if let Err(e) = vault.select_domain(uuid) {
                helpers::toast_error(
                    &ui, &state,
                    &format!("Erro ao selecionar domínio: {}", e),
                );
                return;
            }
        }

        state.lock().unwrap().selected_domain_uuid = Some(uuid);

        ui.set_domains_show_password_card(false);
        ui.set_domains_password_visible(false);
        ui.set_domains_error_generate("".into());
        ui.set_domains_error_compromise("".into());
        ui.set_domains_error_restriction("".into());

        refresh_domain_list(&ui, &state);
    });
}

fn register_add<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_domains_add(move |identifier| {
        let ui = ui_handle.unwrap();

        if identifier.trim().is_empty() {
            ui.set_domains_error_add("O identificador não pode estar vazio.".into());
            return;
        }

        let restriction_uuid = match state.lock().unwrap().selected_restriction_uuid {
            Some(u) => u,
            None    => {
                ui.set_domains_error_add("Nenhuma restrição seleccionada.".into());
                return;
            }
        };

        {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            let has_format = vault
                .get_restriction(restriction_uuid)
                .map(|r| r.generation.format_sequence.as_ref().is_some_and(|seq| !seq.is_empty()))
                .unwrap_or(false);

            if !has_format {
                ui.set_domains_error_add(
                    "Esta restrição não tem formato definido. Defina-o (\"Gerar novo formato\") antes de criar domínios.".into()
                );
                return;
            }
        }

        let result = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.add_domain(identifier.as_str(), restriction_uuid)
                .map_err(|e| format!("{}", e))
        };

        match result {
            Ok(uuid) => {
                state.lock().unwrap().selected_domain_uuid = Some(uuid);
                refresh_domain_list(&ui, &state);
                ui.set_domains_show_add_form(false);
                ui.set_domains_error_add("".into());
                helpers::toast_success(
                    &ui, &state,
                    &format!("Domínio criado: {}", identifier),
                );
            }
            Err(e) => {
                ui.set_domains_error_add(e.into());
            }
        }
    });
}

fn register_view_password<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_domains_view_password(move |domain_uuid_str, k1, k2| {
        let ui = ui_handle.unwrap();

        let domain_uuid = match uuid::Uuid::parse_str(domain_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_domains_error_generate("UUID inválido.".into());
                return;
            }
        };

        if k1.is_empty() || k2.is_empty() {
            ui.set_domains_error_generate("K1 e K2 são obrigatórios.".into());
            return;
        }

        let k1    = k1.to_string();
        let k2    = k2.to_string();
        let state = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::show_loading(&ui, "A gerar senha...");
        ui.set_domains_error_generate("".into());

        helpers::spawn_async(move || {
            let result = run_generate_password(&state, domain_uuid, &k1, &k2);

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok(item) => {
                        ui.set_domains_password_result(item.into_item());
                        ui.set_domains_password_visible(true);
                        ui.set_domains_show_password_card(true);
                        ui.set_domains_error_generate("".into());
                    }
                    Err(e) => {
                        ui.set_domains_error_generate(e.into());
                        ui.set_domains_show_password_card(false);
                    }
                }
            }).unwrap();
        });
    });
}

fn register_copy_password<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_domains_copy_password(move |domain_uuid_str, k1, k2| {
        let ui = ui_handle.unwrap();

        let domain_uuid = match uuid::Uuid::parse_str(domain_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_domains_error_generate("UUID inválido.".into());
                return;
            }
        };

        if k1.is_empty() && k2.is_empty() {
            let current = ui.get_domains_password_result();
            if !current.password.is_empty() {
                helpers::copy_to_clipboard_with_toast(
                    &ui, &state,
                    current.password.as_str(),
                    "Senha",
                );
            }
            return;
        }

        helpers::show_loading(&ui, "A derivar...");

        let k1        = k1.to_string();
        let k2        = k2.to_string();
        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let result = run_generate_password(&state, domain_uuid, &k1, &k2);

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok(item) => {
                        let password = item.password.clone();
                        ui.set_domains_password_result(item.into_item());
                        ui.set_domains_show_password_card(true);
                        ui.set_domains_password_visible(false); // não exibe - só copia
                        ui.set_domains_error_generate("".into());

                        helpers::copy_to_clipboard_with_toast(
                            &ui, &state,
                            &password,
                            "Senha",
                        );
                    }
                    Err(e) => {
                        ui.set_domains_error_generate(e.into());
                    }
                }
            }).unwrap();
        });
    });
}

/// Gera a senha para o domínio usando as chaves fornecidas.
pub fn handle_view_password<C, G, F>(
    ui:          &AppWindow,
    state:       &Arc<Mutex<AppState<C, G, F>>>,
    domain_uuid: uuid::Uuid,
    k1:          slint::SharedString,
    k2:          slint::SharedString,
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

    helpers::show_loading(ui, "A gerar senha...");

    helpers::spawn_async(move || {
        let result = run_generate_password(&state, domain_uuid, &k1, &k2);

        slint::invoke_from_event_loop(move || {
            let ui = ui_handle.unwrap();
            helpers::hide_loading(&ui);

            match result {
                Ok(item) => {
                    ui.set_domains_password_result(item.into_item());
                    ui.set_domains_password_visible(true);
                    ui.set_domains_show_password_card(true);
                }
                Err(e) => {
                    ui.set_domains_error_generate(e.into());
                }
            }
        }).unwrap();
    });
}

pub fn handle_copy_password<C, G, F>(
    ui:          &AppWindow,
    state:       &Arc<Mutex<AppState<C, G, F>>>,
    domain_uuid: uuid::Uuid,
    k1:          slint::SharedString,
    k2:          slint::SharedString,
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
        let result = run_generate_password(&state, domain_uuid, &k1, &k2);

        slint::invoke_from_event_loop(move || {
            let ui = ui_handle.unwrap();

            match result {
                Ok(item) => {
                    helpers::copy_to_clipboard_with_toast(
                        &ui, &state, &item.password, "Senha",
                    );
                }
                Err(e) => {
                    helpers::toast_error(&ui, &state, &format!("Erro: {}", e));
                }
            }
        }).unwrap();
    });
}

fn register_compromise<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_domains_compromise(move |domain_uuid_str, k1, k2| {
        let ui = ui_handle.unwrap();

        let domain_uuid = match uuid::Uuid::parse_str(domain_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_domains_error_compromise("UUID inválido.".into());
                return;
            }
        };

        if k1.is_empty() || k2.is_empty() {
            ui.set_domains_error_compromise("K1 e K2 são obrigatórios.".into());
            return;
        }

        let k1        = k1.to_string();
        let k2        = k2.to_string();
        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::show_loading(&ui, "A comprometer senha...");
        ui.set_domains_error_compromise("".into());

        helpers::spawn_async(move || {
            let result = {
                let s          = state.lock().unwrap();
                let vault      = s.vault.lock().unwrap();
                let master_key = MasterKeyInput::new(k1, k2);
                vault.rotate_domain_password(domain_uuid, &master_key)
                    .map_err(|e| format!("{}", e))
            };

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok(new_variation) => {
                        refresh_domain_list(&ui, &state);
                        helpers::toast_success(
                            &ui, &state,
                            &format!(
                                "Senha comprometida. Nova variação: {}",
                                new_variation
                            ),
                        );
                    }
                    Err(e) => {
                        ui.set_domains_error_compromise(e.into());
                    }
                }
            }).unwrap();
        });
    });
}

fn register_change_restriction<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_domains_change_restriction(move |domain_uuid_str, restriction_uuid_str| {
        let ui = ui_handle.unwrap();

        let domain_uuid = match uuid::Uuid::parse_str(domain_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_domains_error_restriction("UUID de domínio inválido.".into());
                return;
            }
        };

        let restriction_uuid = match uuid::Uuid::parse_str(restriction_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_domains_error_restriction("UUID de restrição inválido.".into());
                return;
            }
        };

        let result = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.change_domain_restriction(domain_uuid, restriction_uuid)
                .map_err(|e| format!("{}", e))
        };

        match result {
            Ok(()) => {
                refresh_domain_list(&ui, &state);
                ui.set_domains_error_restriction("".into());
                helpers::toast_success(
                    &ui, &state,
                    "Restrição alterada. A senha gerada será diferente.",
                );
            }
            Err(e) => {
                ui.set_domains_error_restriction(e.into());
            }
        }
    });
}

fn register_select_version<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_domains_select_version(move |domain_uuid_str, record_uuid_str| {
        let ui = ui_handle.unwrap();

        let domain_uuid = match uuid::Uuid::parse_str(domain_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => return,
        };

        let record_uuid = match uuid::Uuid::parse_str(record_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => return,
        };

        let s     = state.lock().unwrap();
        let vault = s.vault.lock().unwrap();

        let hist = match vault.get_compromise_history(domain_uuid) {
            Ok(h)  => h,
            Err(_) => return,
        };

        let record = match hist.iter().find(|r| r.uuid == record_uuid) {
            Some(r) => r,
            None    => return,
        };

        let fc = &record.frozen_config;

        let sequence_display = fc
            .format_sequence_snapshot
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .enumerate()
            .map(|(i, item)| match item {
                MaskOrLiteral::Mask(m) => format!(
                    "  {:>3}. máscara {} (bits: {})",
                    i + 1, m, helpers::mask_bits_string(*m)
                ),
                MaskOrLiteral::Literal(t) => format!(
                    "  {:>3}. literal '{}'",
                    i + 1, t
                ),
            })
            .collect::<Vec<_>>()
            .join("\n");

        let char_lists_display = fc
            .char_lists_snapshot
            .iter()
            .map(|cl| format!(
                "  bit {:>2}: {} ({} elementos)",
                cl.bit, cl.name, cl.elements.len()
            ))
            .collect::<Vec<_>>()
            .join("\n");

        let detail = FrozenDetailItem {
            record_uuid:       record.uuid.to_string().into(),
            variation:         record.variation as i32,
            timestamp:         helpers::format_timestamp(&record.timestamp).into(),
            config_version:    fc.config_version as i32,
            kmac_context:      fc.kmac_context.clone().into(),
            identifier_frozen: fc.identifier_frozen.clone().into(),
            default_mask:      fc.default_mask_snapshot as i32,
            hmac_hex:          fc.password_hmac
                                   .map(hex::encode)
                                   .unwrap_or_else(|| "(não disponível)".to_string())
                                   .into(),
            sequence_display:  sequence_display.into(),
            char_lists_display: char_lists_display.into(),
            hmac_status:       "pending".into(),
        };

        let mut sorted_hist = hist.clone();
        sorted_hist.sort_by_key(|r| std::cmp::Reverse(r.timestamp));
        let version_index = sorted_hist
            .iter()
            .position(|r| r.uuid == record_uuid)
            .map(|i| i as i32)
            .unwrap_or(-1);

        drop(vault);
        drop(s);

        ui.set_domains_frozen_detail(detail);
        ui.set_domains_selected_version_index(version_index);
        ui.set_domains_show_password_card(false);
        ui.set_domains_password_visible(false);
    });
}

fn register_view_frozen<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_domains_view_frozen(move |domain_uuid_str, record_uuid_str, k1, k2| {
        let ui = ui_handle.unwrap();

        let domain_uuid = match uuid::Uuid::parse_str(domain_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => return,
        };

        let record_uuid = match uuid::Uuid::parse_str(record_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => return,
        };

        if k1.is_empty() || k2.is_empty() {
            helpers::toast_error(&ui, &state, "K1 e K2 são obrigatórios.");
            return;
        }

        let k1        = k1.to_string();
        let k2        = k2.to_string();
        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::show_loading(&ui, "A gerar senha comprometida...");

        helpers::spawn_async(move || {
            let result = run_generate_frozen(
                &state, domain_uuid, record_uuid, &k1, &k2
            );

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok((item, hmac_status)) => {
                        let mut detail = ui.get_domains_frozen_detail();
                        detail.hmac_status = hmac_status.into();
                        ui.set_domains_frozen_detail(detail);

                        ui.set_domains_password_result(item.into_item());
                        ui.set_domains_password_visible(true);
                        ui.set_domains_show_password_card(true);
                    }
                    Err(e) => {
                        helpers::toast_error(&ui, &state, &format!("Erro: {}", e));
                    }
                }
            }).unwrap();
        });
    });
}

fn register_copy_frozen<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_domains_copy_frozen(move |domain_uuid_str, record_uuid_str, k1, k2| {
        let ui = ui_handle.unwrap();

        let domain_uuid = match uuid::Uuid::parse_str(domain_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => return,
        };

        let record_uuid = match uuid::Uuid::parse_str(record_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => return,
        };

        if k1.is_empty() && k2.is_empty() {
            let current = ui.get_domains_password_result();
            if !current.password.is_empty() {
                helpers::copy_to_clipboard_with_toast(
                    &ui, &state,
                    current.password.as_str(),
                    "Senha comprometida",
                );
            }
            return;
        }

        helpers::show_loading(&ui, "A derivar...");

        let k1        = k1.to_string();
        let k2        = k2.to_string();
        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let result = run_generate_frozen(
                &state, domain_uuid, record_uuid, &k1, &k2
            );

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);

                match result {
                    Ok((item, hmac_status)) => {
                        let mut detail = ui.get_domains_frozen_detail();
                        detail.hmac_status = hmac_status.into();
                        ui.set_domains_frozen_detail(detail);

                        helpers::copy_to_clipboard_with_toast(
                            &ui, &state,
                            &item.password,
                            "Senha comprometida",
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

fn register_delete_frozen<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_domains_delete_frozen(move |domain_uuid_str, record_uuid_str| {
        let ui = ui_handle.unwrap();

        let domain_uuid = match uuid::Uuid::parse_str(domain_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => return,
        };

        let record_uuid = match uuid::Uuid::parse_str(record_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => return,
        };

        helpers::ask_confirm(
            &ui,
            &state,
            "Apagar snapshot comprometido?",
            "Remove permanentemente este registo histórico. Operação irreversível.",
            "danger",
            format!("delete-frozen:{}:{}", domain_uuid, record_uuid),
        );
    });
}

pub fn handle_delete_frozen_confirmed<C, G, F>(
    ui:          &AppWindow,
    state:       &Arc<Mutex<AppState<C, G, F>>>,
    domain_uuid: uuid::Uuid,
    record_uuid: uuid::Uuid,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let result = {
        let s     = state.lock().unwrap();
        let vault = s.vault.lock().unwrap();
        vault.remove_compromise_record(domain_uuid, record_uuid)
            .map_err(|e| format!("{}", e))
    };

    match result {
        Ok(true) => {
            refresh_domain_list(ui, state);
            ui.set_domains_selected_version_index(-1);
            ui.set_domains_show_password_card(false);
            helpers::toast_success(ui, state, "Snapshot removido.");
        }
        Ok(false) => {
            helpers::toast_error(ui, state, "Snapshot não encontrado.");
        }
        Err(e) => {
            helpers::toast_error(ui, state, &format!("Erro ao remover: {}", e));
        }
    }
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

    ui.on_on_domains_remove_request(move |domain_uuid_str| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(domain_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                helpers::toast_error(&ui, &state, "UUID inválido.");
                return;
            }
        };

        let compromise_count = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.get_domain(uuid)
                .map(|d| d.compromise_history.len())
                .unwrap_or(0)
        };

        let message = if compromise_count > 0 {
            format!(
                "Remove o domínio e {} versão(ões) comprometida(s). Operação irreversível.",
                compromise_count
            )
        } else {
            "Remove o domínio permanentemente. Operação irreversível.".to_string()
        };

        helpers::ask_confirm(
            &ui,
            &state,
            "Remover domínio?",
            &message,
            "danger",
            format!("remove-domain:{}", uuid),
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
        vault.remove_domain(uuid).map_err(|e| format!("{}", e))
    };

    match result {
        Ok(()) => {
            {
                let mut s = state.lock().unwrap();
                if s.selected_domain_uuid == Some(uuid) {
                    s.selected_domain_uuid = None;
                }
            }

            refresh_domain_list(ui, state);
            helpers::toast_success(ui, state, "Domínio removido.");
        }
        Err(e) => {
            helpers::toast_error(ui, state, &format!("Erro ao remover: {}", e));
        }
    }
}

fn register_close_password(ui: &AppWindow) {
    let ui_handle = ui.as_weak();

    ui.on_on_domains_close_password(move || {
        let ui = ui_handle.unwrap();
        ui.set_domains_password_visible(false);
        ui.set_domains_password_result(Default::default());
        ui.set_domains_show_password_card(false);
    });
}

fn register_go_back<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_domains_back(move || {
        let ui = ui_handle.unwrap();

        state.lock().unwrap().selected_domain_uuid = None;

        super::restrictions::refresh_restriction_list(&ui, &state);
        ui.set_active_sub_view(1); // 1 = Restrições
    });
}

struct PwGenResult {
    password:           String,
    variation:           i32,
    entropy_display:     String,
    device_uuid:         String,
    restriction_uuid:    String,
    is_frozen:           bool,
}

impl PwGenResult {
    fn into_item(self) -> PasswordResultItem {
        PasswordResultItem {
            password:           self.password.into(),
            variation:          self.variation,
            entropy_display:    self.entropy_display.into(),
            device_uuid:        self.device_uuid.into(),
            restriction_uuid:   self.restriction_uuid.into(),
            is_frozen:          self.is_frozen,
        }
    }
}

/// Gera senha derivada - corre em thread separada.
fn run_generate_password<C, G, F>(
    state:       &Arc<Mutex<AppState<C, G, F>>>,
    domain_uuid: uuid::Uuid,
    k1:          &str,
    k2:          &str,
) -> Result<PwGenResult, String>
where
    C: CryptoService + Clone,
    G: GeneratorService + Clone,
    F: FileService + Clone,
{
    let vault      = helpers::clone_vault(state);
    let master_key = MasterKeyInput::new(k1.to_string(), k2.to_string());

    let result = vault
        .generate_password(
            PasswordRequest { domain_uuid, forced_variation: None },
            &master_key,
        )
        .map_err(|e| format!("{}", e))?;

    Ok(PwGenResult {
        password:           result.password.clone(),
        variation:          result.variation as i32,
        entropy_display:    helpers::format_millibits(result.entropy_millibits),
        device_uuid:        result.device_uuid.to_string(),
        restriction_uuid:   result.restriction_uuid.to_string(),
        is_frozen:          false,
    })
}

/// Gera senha comprometida e verifica o HMAC - corre em thread separada.
fn run_generate_frozen<C, G, F>(
    state:       &Arc<Mutex<AppState<C, G, F>>>,
    domain_uuid: uuid::Uuid,
    record_uuid: uuid::Uuid,
    k1:          &str,
    k2:          &str,
) -> Result<(PwGenResult, String), String>
where
    C: CryptoService + Clone,
    G: GeneratorService + Clone,
    F: FileService + Clone,
{
    let vault      = helpers::clone_vault(state);
    let master_key = MasterKeyInput::new(k1.to_string(), k2.to_string());

    let hist = vault
        .get_compromise_history(domain_uuid)
        .map_err(|e| format!("{}", e))?;

    let record = hist
        .iter()
        .find(|r| r.uuid == record_uuid)
        .ok_or_else(|| "Snapshot não encontrado.".to_string())?;

    let variation = record.variation;

    // Gera a senha E verifica o HMAC numa única desencriptação da seed
    let (result, hmac_match) = vault
        .generate_password_from_frozen_checked(domain_uuid, variation, &master_key)
        .map_err(|e| format!("{}", e))?;

    let hmac_status = match hmac_match {
        Some(true)  => "ok".to_string(),
        Some(false) => "fail".to_string(),
        None        => "unavailable".to_string(),
    };

    let item = PwGenResult {
        password:           result.password.clone(),
        variation:          result.variation as i32,
        entropy_display:    helpers::format_millibits(result.entropy_millibits),
        device_uuid:        "".to_string(),
        restriction_uuid:   "".to_string(),
        is_frozen:          true,
    };

    Ok((item, hmac_status))
}