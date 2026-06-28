use slint::{ComponentHandle, ModelRc, VecModel};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use crate::core::{CryptoService, FileService, GeneratorService};
use crate::models::{GenerationParams, MaskOrLiteral};
use crate::AppWindow;

use crate::ui::{CharListItem, PositionDetail, RestrictionItem, SequenceItem};

use super::{helpers, AppState};

const CARD_WIDTH_MASK: i32 = 44;
const CARD_CHAR_WIDTH: i32 = 9;
const CARD_WIDTH_FIXED_MIN: i32 = 32;
const CARD_GAP: i32 = 14;

pub fn register<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    register_select(ui, Arc::clone(&state));
    register_add(ui, Arc::clone(&state));
    register_rename(ui, Arc::clone(&state));
    register_generate_default_format(ui, Arc::clone(&state));
    register_toggle_mask_list(ui, Arc::clone(&state));
    register_reset_mask_default(ui, Arc::clone(&state));
    register_set_default_mask(ui, Arc::clone(&state));
    register_select_card_kind(ui, Arc::clone(&state));
    register_toggle_card_mask_list(ui, Arc::clone(&state));
    register_clear_card_config(ui, Arc::clone(&state));
    register_clear_sequence(ui, Arc::clone(&state));
    register_view_example(ui, Arc::clone(&state));
    register_insert_positions(ui, Arc::clone(&state));
    register_reorder_position(ui, Arc::clone(&state));
    register_drag_move(ui, Arc::clone(&state));
    register_view_position(ui, Arc::clone(&state));
    register_close_position_detail(ui, Arc::clone(&state));
    register_remove_viewed_position(ui, Arc::clone(&state));
    register_toggle_position_mask_list(ui, Arc::clone(&state));
    register_remove_sequence_item(ui, Arc::clone(&state));
    register_extend_entropy(ui, Arc::clone(&state));
    register_add_charlist(ui, Arc::clone(&state));
    register_edit_charlist_elements(ui, Arc::clone(&state));
    register_remove_charlist(ui, Arc::clone(&state));
    register_remove_request(ui, Arc::clone(&state));
    register_go_domains(ui, Arc::clone(&state));
    register_back(ui, Arc::clone(&state));
}

pub fn refresh_restriction_list<C, G, F>(
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

    let restrictions = vault.list_restrictions(device_uuid).unwrap_or_default();

    let items: Vec<RestrictionItem> = restrictions
        .iter()
        .map(|r| {
            let domain_count = vault
                .list_domains(r.uuid)
                .unwrap_or_default()
                .len();

            let char_lists = vault.list_char_lists(r.uuid).unwrap_or_default();
            let char_list_count = char_lists.len();
            let custom_mask: i32 = char_lists
                .iter()
                .filter(|cl| cl.bit >= crate::core::USER_CHAR_LIST_BIT_MIN)
                .fold(0u32, |acc, cl| acc | (1u32 << cl.bit)) as i32;

            let total_entropy_bits = (vault.restriction_total_entropy_millibits(r.uuid).unwrap_or(0) / 1000) as i32;

            RestrictionItem {
                uuid:               r.uuid.to_string().into(),
                device_uuid:        r.device_uuid.to_string().into(),
                name:               r.name.clone().into(),
                default_mask:       r.generation.effective_default_mask() as i32,
                custom_mask,
                bytes_to_derive:    r.generation.effective_bytes_to_derive() as i32,
                format_visual:      r.generation.format_visual().into(),
                sequence_len:       r.generation.sequence().map(|s| s.len()).unwrap_or(0) as i32,
                char_list_count:    char_list_count as i32,
                domain_count:       domain_count as i32,
                total_entropy_bits,
            }
        })
        .collect();

    let selected_index = match s.selected_restriction_uuid {
        Some(uuid) => restrictions
            .iter()
            .position(|r| r.uuid == uuid)
            .map(|i| i as i32)
            .unwrap_or(-1),
        None => -1,
    };

    let device_name = vault
        .get_device(device_uuid)
        .map(|d| d.name.clone())
        .unwrap_or_default();

    drop(vault);
    drop(s);

    ui.set_restrictions(ModelRc::new(Rc::new(VecModel::from(items))));
    ui.set_restrictions_selected_index(selected_index);
    ui.set_restrictions_device_name(device_name.into());
    ui.set_restrictions_device_uuid(device_uuid.to_string().into());

    if selected_index >= 0 {
        refresh_restriction_detail(ui, state);
    }
}

fn card_width(kind: &str, literal: &str) -> i32 {
    if kind == "fixed" {
        (literal.chars().count() as i32 * CARD_CHAR_WIDTH + 24).max(CARD_WIDTH_FIXED_MIN)
    } else {
        CARD_WIDTH_MASK
    }
}

fn refresh_restriction_detail<C, G, F>(
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

    let mut s = state.lock().unwrap();
    let vault = s.vault.lock().unwrap();

    let restriction = match vault.get_restriction(restriction_uuid) {
        Ok(r)  => r,
        Err(_) => return,
    };

    let mut x_offset = CARD_GAP;
    let mut geometry: Vec<(i32, i32)> = Vec::new();
    let sequence_items: Vec<SequenceItem> = restriction
        .generation
        .sequence()
        .unwrap_or(&[])
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let (kind, code, categories, literal) = match item {
                MaskOrLiteral::Mask(0) => ("default".to_string(), 0, String::new(), String::new()),
                MaskOrLiteral::Mask(mask) => (
                    "custom".to_string(),
                    *mask as i32,
                    helpers::mask_categories_string(*mask, &restriction.char_lists),
                    String::new(),
                ),
                MaskOrLiteral::Literal(lit) => ("fixed".to_string(), 0, String::new(), lit.clone()),
            };

            let effective_mask = if kind == "default" {
                restriction.generation.effective_default_mask()
            } else {
                code as u32
            };

            let entropy_bits = if kind == "fixed" {
                0
            } else {
                vault.entropy_millibits_for_mask(restriction_uuid, effective_mask)
                    .unwrap_or(0) / 1000
            };

            let width = card_width(&kind, &literal);
            let item_x = x_offset;
            x_offset += width + CARD_GAP;
            geometry.push((width, item_x));

            SequenceItem {
                index:        (i + 1) as i32,
                kind:         kind.into(),
                code:         code,
                categories:   categories.into(),
                literal:      literal.into(),
                entropy_bits: entropy_bits as i32,
                width,
                x_offset:     item_x,
            }
        })
        .collect();

    let selected_bits = s.selected_mask_bits.clone();
    let char_list_items: Vec<CharListItem> = restriction
        .char_lists
        .iter()
        .map(|cl| CharListItem {
            uuid:      cl.uuid.to_string().into(),
            bit:       cl.bit as i32,
            slot:      helpers::bit_to_slot(cl.bit) as i32,
            slot_max:  crate::core::USER_CHAR_LIST_SLOT_COUNT as i32,
            name:      cl.name.clone().into(),
            elements:  helpers::format_csv_elements(&cl.elements).into(),
            count:     cl.elements.len() as i32,
            editable:  cl.bit >= crate::core::USER_CHAR_LIST_BIT_MIN,
            selected:  selected_bits.contains(&cl.bit),
        })
        .collect();

    let card_bits = s.card_mask_bits.clone();
    let card_char_list_items: Vec<CharListItem> = restriction
        .char_lists
        .iter()
        .map(|cl| CharListItem {
            uuid:      cl.uuid.to_string().into(),
            bit:       cl.bit as i32,
            slot:      helpers::bit_to_slot(cl.bit) as i32,
            slot_max:  crate::core::USER_CHAR_LIST_SLOT_COUNT as i32,
            name:      cl.name.clone().into(),
            elements:  helpers::format_csv_elements(&cl.elements).into(),
            count:     cl.elements.len() as i32,
            editable:  cl.bit >= crate::core::USER_CHAR_LIST_BIT_MIN,
            selected:  card_bits.contains(&cl.bit),
        })
        .collect();

    let domain_count = vault
        .list_domains(restriction_uuid)
        .unwrap_or_default()
        .len();

    let custom_mask: i32 = restriction
        .char_lists
        .iter()
        .filter(|cl| cl.bit >= crate::core::USER_CHAR_LIST_BIT_MIN)
        .fold(0u32, |acc, cl| acc | (1u32 << cl.bit)) as i32;

    let total_entropy_bits = (vault.restriction_total_entropy_millibits(restriction_uuid).unwrap_or(0) / 1000) as i32;

    let selected_item = RestrictionItem {
        uuid:            restriction.uuid.to_string().into(),
        device_uuid:     restriction.device_uuid.to_string().into(),
        name:            restriction.name.clone().into(),
        default_mask:    restriction.generation.effective_default_mask() as i32,
        custom_mask,
        bytes_to_derive: restriction.generation.effective_bytes_to_derive() as i32,
        format_visual:   restriction.generation.format_visual().into(),
        sequence_len:    sequence_items.len() as i32,
        char_list_count: char_list_items.len() as i32,
        domain_count:    domain_count as i32,
        total_entropy_bits,
    };

    let position_detail = match s.viewing_position_index {
        Some(idx) => sequence_items
            .get(idx)
            .map(|item| PositionDetail {
                visible:      true,
                kind:         item.kind.clone(),
                index:        item.index,
                code:         item.code,
                fixed_value:  item.literal.clone(),
                entropy_bits: item.entropy_bits,
            })
            .unwrap_or_default(),
        None => PositionDetail::default(),
    };

    let position_mask = position_detail.code as u32;
    let position_char_list_items: Vec<CharListItem> = restriction
        .char_lists
        .iter()
        .map(|cl| CharListItem {
            uuid:      cl.uuid.to_string().into(),
            bit:       cl.bit as i32,
            slot:      helpers::bit_to_slot(cl.bit) as i32,
            slot_max:  crate::core::USER_CHAR_LIST_SLOT_COUNT as i32,
            name:      cl.name.clone().into(),
            elements:  helpers::format_csv_elements(&cl.elements).into(),
            count:     cl.elements.len() as i32,
            editable:  cl.bit >= crate::core::USER_CHAR_LIST_BIT_MIN,
            selected:  (position_mask & (1u32 << cl.bit)) != 0,
        })
        .collect();

    let card_kind = s.creating_card_kind.clone().unwrap_or_default();
    let card_preview = if card_kind.is_empty() {
        SequenceItem::default()
    } else if card_kind == "fixed" {
        SequenceItem { kind: card_kind.into(), ..Default::default() }
    } else {
        let mask = if card_kind == "default" {
            restriction.generation.effective_default_mask()
        } else {
            card_bits.iter().fold(0u32, |acc, &b| acc | (1u32 << b))
        };
        let entropy_bits = (vault.entropy_millibits_for_mask(restriction_uuid, mask).unwrap_or(0) / 1000) as i32;
        SequenceItem {
            kind:         card_kind.clone().into(),
            code:         if card_kind == "custom" { mask as i32 } else { 0 },
            entropy_bits,
            ..Default::default()
        }
    };

    drop(vault);
    s.drag_item_geometry  = geometry;
    s.drag_sequence_end_x = x_offset;
    drop(s);

    ui.set_restrictions_selected_restriction(selected_item);
    ui.set_restrictions_sequence(
        ModelRc::new(Rc::new(VecModel::from(sequence_items)))
    );
    ui.set_restrictions_char_lists(
        ModelRc::new(Rc::new(VecModel::from(char_list_items)))
    );
    ui.set_restrictions_card_char_lists(
        ModelRc::new(Rc::new(VecModel::from(card_char_list_items)))
    );
    ui.set_restrictions_position_char_lists(
        ModelRc::new(Rc::new(VecModel::from(position_char_list_items)))
    );
    ui.set_restrictions_position_detail(position_detail);
    ui.set_restrictions_card_preview(card_preview);
    ui.set_restrictions_sequence_end_x(x_offset);
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

    ui.on_on_restrictions_select(move |uuid_str| {
        let ui = ui_handle.unwrap();

        if uuid_str.is_empty() {
            state.lock().unwrap().selected_restriction_uuid = None;
            ui.set_restrictions_selected_index(-1);
            return;
        }

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                helpers::toast_error(&ui, &state, "UUID de restrição inválido.");
                return;
            }
        };

        {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            if let Err(e) = vault.select_restriction(uuid) {
                helpers::toast_error(
                    &ui, &state,
                    &format!("Erro ao selecionar restrição: {}", e)
                );
                return;
            }
        }

        {
            let mut s = state.lock().unwrap();
            s.selected_restriction_uuid = Some(uuid);
            s.selected_domain_uuid      = None;
            s.viewing_position_index   = None;
            s.creating_card_kind       = None;
            s.card_mask_bits.clear();
        }

        let bits = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            default_mask_bits(&vault, uuid)
        };
        state.lock().unwrap().selected_mask_bits = bits;

        refresh_restriction_list(&ui, &state);
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

    ui.on_on_restrictions_add(move |name| {
        let ui = ui_handle.unwrap();

        if name.trim().is_empty() {
            ui.set_restrictions_error_add("O nome não pode estar vazio.".into());
            return;
        }

        let device_uuid = match state.lock().unwrap().selected_device_uuid {
            Some(u) => u,
            None    => {
                ui.set_restrictions_error_add("Nenhum dispositivo selecionado.".into());
                return;
            }
        };

        let result: Result<uuid::Uuid, String> = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.add_restriction(
                name.as_str(),
                device_uuid,
                GenerationParams::default(),
            ).map_err(|e| format!("{}", e))
        };

        match result {
            Ok(uuid) => {
                {
                    let mut s = state.lock().unwrap();
                    s.selected_restriction_uuid = Some(uuid);
                    s.viewing_position_index    = None;
                    s.creating_card_kind        = None;
                    s.card_mask_bits.clear();
                }
                let bits = {
                    let s     = state.lock().unwrap();
                    let vault = s.vault.lock().unwrap();
                    default_mask_bits(&vault, uuid)
                };
                state.lock().unwrap().selected_mask_bits = bits;
                refresh_restriction_list(&ui, &state);
                ui.set_restrictions_show_add_form(false);
                ui.set_restrictions_error_add("".into());
                ui.set_restrictions_format_modal_uuid(uuid.to_string().into());
                ui.set_restrictions_format_modal_replace(false);
                ui.set_restrictions_show_format_modal(true);
                helpers::toast_success(
                    &ui, &state,
                    &format!("Restrição criada: {}", uuid),
                );
            }
            Err(e) => {
                ui.set_restrictions_error_add(e.into());
            }
        }
    });
}

fn register_generate_default_format<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_generate_default_format(move |uuid_str| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => return,
        };

        let result = (|| {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            assert_format_editable(&vault, uuid)?;
            vault.regenerate_default_format(uuid).map_err(|e| format!("{}", e))
        })();

        ui.set_restrictions_show_format_modal(false);

        match result {
            Ok(()) => {
                refresh_restriction_detail(&ui, &state);
                refresh_restriction_list(&ui, &state);
                helpers::toast_success(&ui, &state, "Formato gerado.");
            }
            Err(e) => {
                ui.set_restrictions_error_sequence(e.into());
            }
        }
    });
}

fn register_view_example<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_view_example(move |uuid_str| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => return,
        };

        let result = (|| {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            let restriction = vault.get_restriction(uuid).map_err(|e| format!("{}", e))?;
            let masks = restriction
                .generation
                .resolved_sequence()
                .ok_or_else(|| "Restrição sem formato definido.".to_string())?;
            let bit_lists = restriction.build_bit_lists();
            let bytes     = restriction.generation.effective_bytes_to_derive();
            let entropy   = vec![0xAAu8; bytes];
            crate::generator::generate_password(&entropy, &masks, &bit_lists)
                .map_err(|e| format!("{}", e))
        })();

        match result {
            Ok(r) => {
                ui.set_restrictions_example_length(r.password.chars().count() as i32);
                ui.set_restrictions_example_password(r.password.into());
                ui.set_restrictions_example_entropy(
                    helpers::format_millibits(r.total_entropy_millibits).into(),
                );
                ui.set_restrictions_show_example(true);
            }
            Err(e) => {
                helpers::toast_error(&ui, &state, &format!("Erro ao gerar exemplo: {}", e));
            }
        }
    });
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

    ui.on_on_restrictions_rename(move |uuid_str, name| {
        let ui = ui_handle.unwrap();

        if name.trim().is_empty() {
            ui.set_restrictions_error_rename("O nome não pode estar vazio.".into());
            return;
        }

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_restrictions_error_rename("UUID inválido.".into());
                return;
            }
        };

        let result = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.rename_restriction(uuid, name.as_str())
                .map_err(|e| format!("{}", e))
        };

        match result {
            Ok(()) => {
                refresh_restriction_list(&ui, &state);
                ui.set_restrictions_error_rename("".into());
                helpers::toast_success(&ui, &state, "Restrição renomeada.");
            }
            Err(e) => {
                ui.set_restrictions_error_rename(e.into());
            }
        }
    });
}

fn register_toggle_mask_list<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_toggle_mask_list(move |bit| {
        let ui = ui_handle.unwrap();
        if !(0..=31).contains(&bit) {
            return;
        }
        let bit = bit as u8;

        let uuid = match state.lock().unwrap().selected_restriction_uuid {
            Some(u) => u,
            None    => return,
        };

        let mut s = state.lock().unwrap();

        let mut candidate = s.selected_mask_bits.clone();
        if candidate.contains(&bit) {
            candidate.remove(&bit);
        } else {
            candidate.insert(bit);
        }

        let still_valid = {
            let vault = s.vault.lock().unwrap();
            let existing: std::collections::HashSet<u8> = vault
                .list_char_lists(uuid)
                .unwrap_or_default()
                .iter()
                .map(|cl| cl.bit)
                .collect();
            candidate.iter().any(|b| existing.contains(b))
        };

        if !still_valid {
            drop(s);
            ui.set_restrictions_error_sequence("Selecione pelo menos uma lista.".into());
            return;
        }

        s.selected_mask_bits = candidate;
        drop(s);

        ui.set_restrictions_error_sequence("".into());
        refresh_restriction_detail(&ui, &state);
        ui.invoke_on_restrictions_set_default_mask();
    });
}

fn register_reset_mask_default<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_reset_mask_default(move || {
        let ui = ui_handle.unwrap();
        let uuid = match state.lock().unwrap().selected_restriction_uuid {
            Some(u) => u,
            None    => return,
        };

        const RESET_MASK: u32 = 0b111;

        let result = (|| {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            assert_format_editable(&vault, uuid)?;
            vault.set_default_mask(uuid, RESET_MASK).map_err(|e| format!("{}", e))
        })();

        match result {
            Ok(()) => {
                state.lock().unwrap().selected_mask_bits = (0u8..3).collect();
                ui.set_restrictions_error_sequence("".into());
                refresh_restriction_detail(&ui, &state);
                refresh_restriction_list(&ui, &state);
            }
            Err(e) => {
                helpers::toast_error(&ui, &state, &format!("Erro ao repor padrão: {}", e));
            }
        }
    });
}

fn register_set_default_mask<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_set_default_mask(move || {
        let ui = ui_handle.unwrap();
        let uuid = match state.lock().unwrap().selected_restriction_uuid {
            Some(u) => u,
            None    => return,
        };

        let result = (|| {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            assert_format_editable(&vault, uuid)?;

            let existing: std::collections::HashSet<u8> = vault
                .list_char_lists(uuid)
                .unwrap_or_default()
                .iter()
                .map(|cl| cl.bit)
                .collect();

            let mask: u32 = s
                .selected_mask_bits
                .iter()
                .filter(|b| existing.contains(b))
                .fold(0u32, |acc, &b| acc | (1u32 << b));

            if mask == 0 {
                Err("Selecione pelo menos uma lista para o padrão.".to_string())
            } else {
                vault.set_default_mask(uuid, mask).map_err(|e| format!("{}", e))
            }
        })();

        match result {
            Ok(()) => {
                refresh_restriction_detail(&ui, &state);
                refresh_restriction_list(&ui, &state);
            }
            Err(e) => {
                ui.set_restrictions_error_sequence(e.into());
            }
        }
    });
}

fn register_select_card_kind<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_select_card_kind(move |kind| {
        let ui = ui_handle.unwrap();
        let uuid = match state.lock().unwrap().selected_restriction_uuid {
            Some(u) => u,
            None    => return,
        };

        {
            let mut s = state.lock().unwrap();
            s.creating_card_kind     = if kind.is_empty() { None } else { Some(kind.to_string()) };
            s.viewing_position_index = None;
        }

        if kind.as_str() == "default" {
            let bits = {
                let s     = state.lock().unwrap();
                let vault = s.vault.lock().unwrap();
                default_mask_bits(&vault, uuid)
            };
            state.lock().unwrap().card_mask_bits = bits;
        } else if kind.as_str() == "custom" {
            state.lock().unwrap().card_mask_bits.clear();
        }

        refresh_restriction_detail(&ui, &state);
    });
}

fn register_toggle_card_mask_list<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_toggle_card_mask_list(move |bit| {
        let ui = ui_handle.unwrap();
        if !(0..=31).contains(&bit) {
            return;
        }
        let bit = bit as u8;
        {
            let mut s = state.lock().unwrap();
            if s.card_mask_bits.contains(&bit) {
                s.card_mask_bits.remove(&bit);
            } else {
                s.card_mask_bits.insert(bit);
            }
        }
        refresh_restriction_detail(&ui, &state);
    });
}

fn register_clear_card_config<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_clear_card_config(move || {
        let ui = ui_handle.unwrap();
        {
            let mut s = state.lock().unwrap();
            s.creating_card_kind = None;
            s.card_mask_bits.clear();
        }
        refresh_restriction_detail(&ui, &state);
    });
}

fn register_clear_sequence<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_clear_sequence(move |uuid_str| {
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
            "Limpar sequência?",
            "Remove todas as posições do formato desta restrição. As senhas derivadas mudam.",
            "danger",
            format!("clear-sequence:{}", uuid),
        );
    });
}

pub fn handle_clear_sequence_confirmed<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    uuid:  uuid::Uuid,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let result = (|| {
        let s     = state.lock().unwrap();
        let vault = s.vault.lock().unwrap();
        assert_format_editable(&vault, uuid)?;
        let restriction = vault.get_restriction(uuid).map_err(|e| format!("{}", e))?;
        let mut params         = restriction.generation.clone();
        params.format_sequence = Some(Vec::new());
        vault.update_restriction_generation(uuid, params).map_err(|e| format!("{}", e))
    })();

    match result {
        Ok(()) => {
            state.lock().unwrap().viewing_position_index = None;
            refresh_restriction_detail(ui, state);
            refresh_restriction_list(ui, state);
        }
        Err(e) => {
            helpers::toast_error(ui, state, &format!("Erro ao limpar sequência: {}", e));
        }
    }
}

fn register_insert_positions<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_insert_positions(move |target_index, kind, literal, quantity| {
        let ui = ui_handle.unwrap();

        let uuid = match state.lock().unwrap().selected_restriction_uuid {
            Some(u) => u,
            None    => return,
        };

        if kind.as_str() == "fixed" && literal.is_empty() {
            ui.set_restrictions_error_sequence("O literal não pode estar vazio.".into());
            return;
        }

        let qty = if kind.as_str() == "fixed" { 1 } else { quantity.max(1) as usize };

        let result: Result<(), String> = (|| {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            assert_format_editable(&vault, uuid)?;

            let seq_len = vault
                .get_restriction(uuid)
                .ok()
                .and_then(|r| r.generation.sequence().map(|s| s.len()))
                .unwrap_or(0);
            let mut pos = (target_index as usize).min(seq_len);

            let existing: std::collections::HashSet<u8> = vault
                .list_char_lists(uuid)
                .unwrap_or_default()
                .iter()
                .map(|cl| cl.bit)
                .collect();

            for _ in 0..qty {
                let result = match kind.as_str() {
                    "fixed" => vault
                        .insert_restriction_literal_position(uuid, literal.to_string(), pos)
                        .map_err(|e| format!("{}", e)),
                    "default" => vault
                        .insert_restriction_mask_position(uuid, 0, pos)
                        .map_err(|e| format!("{}", e)),
                    "custom" => {
                        let mask: u32 = s
                            .card_mask_bits
                            .iter()
                            .filter(|b| existing.contains(b))
                            .fold(0u32, |acc, &b| acc | (1u32 << b));
                        if mask == 0 {
                            Err("Selecione pelo menos uma lista.".to_string())
                        } else {
                            vault
                                .insert_restriction_mask_position(uuid, mask, pos)
                                .map_err(|e| format!("{}", e))
                        }
                    }
                    _ => Err("Tipo de card inválido.".to_string()),
                };
                result?;
                pos += 1;
            }
            Ok(())
        })();

        match result {
            Ok(()) => {
                refresh_restriction_detail(&ui, &state);
                refresh_restriction_list(&ui, &state);
                ui.set_restrictions_error_sequence("".into());
            }
            Err(e) => {
                ui.set_restrictions_error_sequence(e.into());
            }
        }
    });
}

fn register_reorder_position<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_reorder_position(move |source_index, target_index| {
        let ui = ui_handle.unwrap();

        let uuid = match state.lock().unwrap().selected_restriction_uuid {
            Some(u) => u,
            None    => return,
        };

        let result: Result<(), String> = (|| {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            assert_format_editable(&vault, uuid)?;

            let restriction = vault.get_restriction(uuid).map_err(|e| format!("{}", e))?;
            let mut seq = restriction
                .generation
                .sequence()
                .unwrap_or(&[])
                .to_vec();

            let src = source_index as usize;
            if src >= seq.len() {
                return Err("Índice de origem fora dos limites.".to_string());
            }

            let item = seq.remove(src);

            let mut dst = (target_index as usize).min(seq.len());
            if dst > src {
                dst -= 1;
            }
            seq.insert(dst.min(seq.len()), item);

            let mut params         = restriction.generation.clone();
            params.format_sequence = Some(seq);

            vault.update_restriction_generation(uuid, params)
                .map_err(|e| format!("{}", e))
        })();

        match result {
            Ok(()) => {
                refresh_restriction_detail(&ui, &state);
            }
            Err(e) => {
                helpers::toast_error(&ui, &state, &format!("Erro ao mover posição: {}", e));
            }
        }
    });
}

fn register_drag_move<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_drag_move(move |local_x| {
        let ui = ui_handle.unwrap();
        let s  = state.lock().unwrap();

        let mut candidates: Vec<(i32, usize)> = s
            .drag_item_geometry
            .iter()
            .enumerate()
            .map(|(i, &(_, x_offset))| (x_offset - CARD_GAP / 2, i))
            .collect();
        candidates.push((s.drag_sequence_end_x - CARD_GAP / 2, s.drag_item_geometry.len()));

        drop(s);

        if let Some((_, gap)) = candidates.into_iter().min_by_key(|(center, _)| (center - local_x).abs()) {
            ui.set_restrictions_drag_target_gap(gap as i32);
        }
    });
}

fn register_view_position<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_view_position(move |index| {
        let ui = ui_handle.unwrap();
        {
            let mut s = state.lock().unwrap();
            s.viewing_position_index = Some(index as usize);
            s.creating_card_kind     = None;
        }
        refresh_restriction_detail(&ui, &state);
    });
}

fn register_close_position_detail<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_close_position_detail(move || {
        let ui = ui_handle.unwrap();
        state.lock().unwrap().viewing_position_index = None;
        refresh_restriction_detail(&ui, &state);
    });
}

fn register_toggle_position_mask_list<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_toggle_position_mask_list(move |bit| {
        let ui = ui_handle.unwrap();
        if !(0..=31).contains(&bit) {
            return;
        }
        let bit = bit as u8;

        let uuid = match state.lock().unwrap().selected_restriction_uuid {
            Some(u) => u,
            None    => return,
        };
        let idx = match state.lock().unwrap().viewing_position_index {
            Some(i) => i,
            None    => return,
        };

        let result = (|| {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            assert_format_editable(&vault, uuid)?;
            let restriction = vault.get_restriction(uuid).map_err(|e| format!("{}", e))?;
            let current_mask = restriction
                .generation
                .sequence()
                .and_then(|seq| seq.get(idx))
                .and_then(|item| item.as_mask())
                .ok_or_else(|| "Posição inválida.".to_string())?;
            let new_mask = current_mask ^ (1u32 << bit);
            if new_mask == 0 {
                return Err("Selecione pelo menos uma lista.".to_string());
            }
            vault
                .update_restriction_position_mask(uuid, idx, new_mask)
                .map_err(|e| format!("{}", e))
        })();

        match result {
            Ok(()) => {
                refresh_restriction_detail(&ui, &state);
                refresh_restriction_list(&ui, &state);
            }
            Err(e) => {
                helpers::toast_error(&ui, &state, &format!("Erro ao editar posição: {}", e));
            }
        }
    });
}

fn register_remove_viewed_position<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_remove_viewed_position(move || {
        let ui = ui_handle.unwrap();
        let uuid = match state.lock().unwrap().selected_restriction_uuid {
            Some(u) => u,
            None    => return,
        };
        let idx = match state.lock().unwrap().viewing_position_index {
            Some(i) => i,
            None    => return,
        };

        let result = (|| {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            assert_format_editable(&vault, uuid)?;
            let restriction = vault.get_restriction(uuid).map_err(|e| format!("{}", e))?;
            let mut seq = restriction.generation.sequence().unwrap_or(&[]).to_vec();
            if idx >= seq.len() {
                return Err("Índice fora dos limites.".to_string());
            }
            seq.remove(idx);
            let mut params         = restriction.generation.clone();
            params.format_sequence = Some(seq);
            vault.update_restriction_generation(uuid, params)
                .map_err(|e| format!("{}", e))
        })();

        match result {
            Ok(()) => {
                let new_len = {
                    let s     = state.lock().unwrap();
                    let vault = s.vault.lock().unwrap();
                    vault
                        .get_restriction(uuid)
                        .map(|r| r.generation.sequence().unwrap_or(&[]).len())
                        .unwrap_or(0)
                };
                state.lock().unwrap().viewing_position_index = if new_len == 0 {
                    None
                } else if idx < new_len {
                    Some(idx)
                } else {
                    Some(new_len - 1)
                };
                refresh_restriction_detail(&ui, &state);
                refresh_restriction_list(&ui, &state);
            }
            Err(e) => {
                helpers::toast_error(&ui, &state, &format!("Erro ao remover posição: {}", e));
            }
        }
    });
}

fn register_remove_sequence_item<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_remove_sequence_item(move |uuid_str, index| {
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
            "Remover posição?",
            "Remove esta posição da sequência de formato. As senhas derivadas mudam.",
            "danger",
            format!("remove-position:{}:{}", uuid, index),
        );
    });
}

pub fn handle_remove_position_confirmed<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    uuid:  uuid::Uuid,
    index: usize,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let result = (|| {
        let s     = state.lock().unwrap();
        let vault = s.vault.lock().unwrap();
        assert_format_editable(&vault, uuid)?;

        let restriction = vault.get_restriction(uuid)
            .map_err(|e| format!("{}", e))?;

        let mut seq = restriction
            .generation
            .sequence()
            .unwrap_or(&[])
            .to_vec();

        if index >= seq.len() {
            return Err("Índice fora dos limites.".to_string());
        }

        seq.remove(index);

        let mut params         = restriction.generation.clone();
        params.format_sequence = Some(seq);

        vault.update_restriction_generation(uuid, params)
            .map_err(|e| format!("{}", e))
    })();

    match result {
        Ok(()) => {
            refresh_restriction_detail(ui, state);
            refresh_restriction_list(ui, state);
        }
        Err(e) => {
            helpers::toast_error(ui, state, &format!("Erro ao remover posição: {}", e));
        }
    }
}

fn register_extend_entropy<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_extend_entropy(move |uuid_str, bits_str| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                helpers::toast_error(&ui, &state, "UUID inválido.");
                return;
            }
        };

        let bits: u32 = match bits_str.trim().parse() {
            Ok(v) if v > 0 => v,
            _ => {
                helpers::toast_error(
                    &ui, &state,
                    "Número de bits inválido (mínimo: 1)."
                );
                return;
            }
        };

        let result = (|| {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            assert_format_editable(&vault, uuid)?;
            vault.extend_restriction_format_to_entropy(uuid, bits)
                .map_err(|e| format!("{}", e))
        })();

        match result {
            Ok(added) => {
                refresh_restriction_detail(&ui, &state);
                refresh_restriction_list(&ui, &state);
                helpers::toast_success(
                    &ui, &state,
                    &format!("{} posição(ões) adicionada(s) para atingir {} bits.", added, bits),
                );
            }
            Err(e) => {
                helpers::toast_error(&ui, &state, &format!("Erro ao estender entropia: {}", e));
            }
        }
    });
}

fn register_add_charlist<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_add_charlist(move |uuid_str, name, elements_csv| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_restrictions_error_charlist("UUID inválido.".into());
                return;
            }
        };

        if name.trim().is_empty() {
            ui.set_restrictions_error_charlist("O nome não pode estar vazio.".into());
            return;
        }

        let elements = match helpers::parse_csv_elements(elements_csv.as_str()) {
            Ok(e)  => e,
            Err(e) => {
                ui.set_restrictions_error_charlist(e.into());
                return;
            }
        };

        let result = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();

            let used: std::collections::HashSet<u8> = vault
                .list_char_lists(uuid)
                .unwrap_or_default()
                .iter()
                .map(|cl| cl.bit)
                .collect();

            let next_bit = (crate::core::USER_CHAR_LIST_BIT_MIN
                ..=crate::core::USER_CHAR_LIST_BIT_MAX)
                .find(|b| !used.contains(b));

            match next_bit {
                Some(bit) => vault
                    .add_char_list_to_restriction(uuid, name.as_str(), bit, elements)
                    .map_err(|e| format!("{}", e)),
                None => Err("Não há slots de lista disponíveis (máximo atingido).".to_string()),
            }
        };

        match result {
            Ok(cl_uuid) => {
                refresh_restriction_detail(&ui, &state);
                refresh_restriction_list(&ui, &state);
                ui.set_restrictions_error_charlist("".into());
                helpers::toast_success(
                    &ui, &state,
                    &format!("Lista de caracteres criada: {}", cl_uuid),
                );
            }
            Err(e) => {
                ui.set_restrictions_error_charlist(e.into());
            }
        }
    });
}

fn register_edit_charlist_elements<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_edit_charlist_elements(move |r_uuid_str, cl_uuid_str, elements_csv| {
        let ui = ui_handle.unwrap();

        let r_uuid = match uuid::Uuid::parse_str(r_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_restrictions_error_charlist("UUID de restrição inválido.".into());
                return;
            }
        };

        let cl_uuid = match uuid::Uuid::parse_str(cl_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                ui.set_restrictions_error_charlist("UUID de lista inválido.".into());
                return;
            }
        };

        let elements = match helpers::parse_csv_elements(elements_csv.as_str()) {
            Ok(e)  => e,
            Err(e) => {
                ui.set_restrictions_error_charlist(e.into());
                return;
            }
        };

        let result = {
            let s     = state.lock().unwrap();
            let vault = s.vault.lock().unwrap();
            vault.update_char_list_elements(r_uuid, cl_uuid, elements)
                .map_err(|e| format!("{}", e))
        };

        match result {
            Ok(()) => {
                refresh_restriction_detail(&ui, &state);
                ui.set_restrictions_error_charlist("".into());
                helpers::toast_success(&ui, &state, "Elementos da lista actualizados.");
            }
            Err(e) => {
                ui.set_restrictions_error_charlist(e.into());
            }
        }
    });
}

fn register_remove_charlist<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_remove_charlist(move |r_uuid_str, cl_uuid_str| {
        let ui = ui_handle.unwrap();

        let r_uuid = match uuid::Uuid::parse_str(r_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                helpers::toast_error(&ui, &state, "UUID de restrição inválido.");
                return;
            }
        };

        let cl_uuid = match uuid::Uuid::parse_str(cl_uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => {
                helpers::toast_error(&ui, &state, "UUID de lista inválido.");
                return;
            }
        };

        helpers::ask_confirm(
            &ui,
            &state,
            "Remover lista de caracteres?",
            "Esta operação é irreversível.",
            "danger",
            format!("remove-charlist:{}:{}", r_uuid, cl_uuid),
        );
    });
}

pub fn handle_remove_charlist_confirmed<C, G, F>(
    ui:      &AppWindow,
    state:   &Arc<Mutex<AppState<C, G, F>>>,
    r_uuid:  uuid::Uuid,
    cl_uuid: uuid::Uuid,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let result = {
        let s     = state.lock().unwrap();
        let vault = s.vault.lock().unwrap();
        vault.remove_char_list_from_restriction(r_uuid, cl_uuid)
            .map_err(|e| format!("{}", e))
    };

    match result {
        Ok(()) => {
            refresh_restriction_detail(ui, state);
            refresh_restriction_list(ui, state);
            helpers::toast_success(ui, state, "Lista de caracteres removida.");
        }
        Err(e) => {
            helpers::toast_error(ui, state, &format!("Erro ao remover lista: {}", e));
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

    ui.on_on_restrictions_remove_request(move |uuid_str| {
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
            "Remover restrição?",
            "Remove esta restrição e todos os domínios associados. Operação irreversível.",
            "danger",
            format!("remove-restriction:{}", uuid),
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
        vault.remove_restriction(uuid).map_err(|e| format!("{}", e))
    };

    match result {
        Ok(()) => {
            {
                let mut s = state.lock().unwrap();
                if s.selected_restriction_uuid == Some(uuid) {
                    s.selected_restriction_uuid = None;
                    s.selected_domain_uuid      = None;
                }
            }

            refresh_restriction_list(ui, state);
            helpers::toast_success(ui, state, "Restrição removida.");
        }
        Err(e) => {
            helpers::toast_error(ui, state, &format!("Erro ao remover: {}", e));
        }
    }
}

fn register_go_domains<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_restrictions_go_domains(move |uuid_str| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => return,
        };

        state.lock().unwrap().selected_restriction_uuid = Some(uuid);
        state.lock().unwrap().selected_domain_uuid      = None;

        super::domains::refresh_domain_list(&ui, &state);
        ui.set_active_sub_view(3); // 3 = Domínios
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

    ui.on_on_restrictions_back(move || {
        let ui = ui_handle.unwrap();

        state.lock().unwrap().selected_restriction_uuid = None;
        state.lock().unwrap().selected_domain_uuid      = None;

        super::devices::refresh_device_list(&ui, &state);
        ui.set_active_sub_view(0); // 0 = Dispositivos
    });
}

/// Garante que a restrição não tem domínios associados antes de qualquer alteração ao formato/listas
fn assert_format_editable<C, G, F>(
    vault: &crate::core::VaultCore<C, G, F>,
    uuid:  uuid::Uuid,
) -> Result<(), String>
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let domain_count = vault.list_domains(uuid).unwrap_or_default().len();
    if domain_count > 0 {
        Err("Esta restrição tem domínios associados. Remova-os primeiro para poder editar o formato.".to_string())
    } else {
        Ok(())
    }
}

fn default_mask_bits<C, G, F>(
    vault: &crate::core::VaultCore<C, G, F>,
    rid:   uuid::Uuid,
) -> std::collections::BTreeSet<u8>
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let mask = vault
        .get_restriction(rid)
        .map(|r| r.generation.effective_default_mask())
        .unwrap_or(0);
    (0u8..32).filter(|b| mask & (1u32 << b) != 0).collect()
}
