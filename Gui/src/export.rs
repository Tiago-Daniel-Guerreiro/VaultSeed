use slint::{ComponentHandle, ModelRc, VecModel};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use crate::core::{CryptoService, FileService, GeneratorService};
use crate::models::ExportFormat;
use crate::AppWindow;

use crate::ui::{TreeNodeItem, ExportSummaryItem, NodeType};

use super::{helpers, AppState};

// Árvore de seleção mantida no lado Rust - a UI recebe uma versão flat
#[derive(Debug, Clone)]
struct TreeNode {
    uuid:       uuid::Uuid,
    label:      String,
    node_type:  InternalNodeType,
    selected:   bool,
    children:   Vec<TreeNode>,
}

#[derive(Debug, Clone, PartialEq)]
enum InternalNodeType {
    Device,
    Restriction,
    Folder,
    DerivedPassword,
    StaticPassword,
}

impl InternalNodeType {
    fn to_slint(&self) -> NodeType {
        match self {
            Self::Device          => NodeType::Device,
            Self::Restriction     => NodeType::Restriction,
            Self::Folder          => NodeType::Folder,
            Self::DerivedPassword => NodeType::DerivedPassword,
            Self::StaticPassword  => NodeType::StaticPassword,
        }
    }
}

#[derive(Default)]
struct ExportState {
    tree: Vec<TreeNode>,
}

type SharedExportState = Arc<Mutex<ExportState>>;

pub fn register<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let export_state: SharedExportState = Arc::new(Mutex::new(ExportState::default()));

    register_toggle_node(ui, Arc::clone(&state), Arc::clone(&export_state));
    register_select_all(ui, Arc::clone(&state), Arc::clone(&export_state));
    register_deselect_all(ui, Arc::clone(&state), Arc::clone(&export_state));
    register_filter_by_device(ui, Arc::clone(&state), Arc::clone(&export_state));
    register_export(ui, Arc::clone(&state), Arc::clone(&export_state));
    register_open(ui, Arc::clone(&state), Arc::clone(&export_state));
    register_back(ui, Arc::clone(&state));
}

fn register_open<C, G, F>(
    ui:           &AppWindow,
    state:        Arc<Mutex<AppState<C, G, F>>>,
    export_state: SharedExportState,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_export_open(move || {
        let ui = ui_handle.unwrap();

        let new_tree = build_tree(&state);
        let merged   = merge_selection(&export_state.lock().unwrap().tree, new_tree);

        let flat    = flatten_tree(&merged);
        let items   = flat_to_slint_items(&flat);
        let summary = compute_summary(&merged);

        export_state.lock().unwrap().tree = merged;

        ui.set_export_tree_nodes(ModelRc::new(Rc::new(VecModel::from(items))));
        ui.set_export_summary(summary);
    });
}

pub fn refresh_export_tree<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let tree = build_tree(state);

    let flat  = flatten_tree(&tree);
    let items = flat_to_slint_items(&flat);
    let summary = compute_summary(&tree);

    ui.set_export_tree_nodes(ModelRc::new(Rc::new(VecModel::from(items))));
    ui.set_export_summary(summary);
}

#[allow(dead_code)]
fn refresh_with_state<C, G, F>(
    ui:           &AppWindow,
    state:        &Arc<Mutex<AppState<C, G, F>>>,
    export_state: &SharedExportState,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let new_tree   = build_tree(state);
    let merged     = merge_selection(&export_state.lock().unwrap().tree, new_tree);

    let flat    = flatten_tree(&merged);
    let items   = flat_to_slint_items(&flat);
    let summary = compute_summary(&merged);

    export_state.lock().unwrap().tree = merged;

    ui.set_export_tree_nodes(ModelRc::new(Rc::new(VecModel::from(items))));
    ui.set_export_summary(summary);
}

fn register_toggle_node<C, G, F>(
    ui:           &AppWindow,
    _state:       Arc<Mutex<AppState<C, G, F>>>,
    export_state: SharedExportState,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_export_toggle(move |flat_index| {
        let ui  = ui_handle.unwrap();
        let idx = flat_index as usize;

        {
            let mut es = export_state.lock().unwrap();
            toggle_by_flat_index(&mut es.tree, idx);
        }

        let es      = export_state.lock().unwrap();
        let flat    = flatten_tree(&es.tree);
        let items   = flat_to_slint_items(&flat);
        let summary = compute_summary(&es.tree);
        drop(es);

        ui.set_export_tree_nodes(ModelRc::new(Rc::new(VecModel::from(items))));
        ui.set_export_summary(summary);
    });
}

fn register_select_all<C, G, F>(
    ui:           &AppWindow,
    state:        Arc<Mutex<AppState<C, G, F>>>,
    export_state: SharedExportState,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_export_select_all(move || {
        let ui = ui_handle.unwrap();

        {
            let mut es = export_state.lock().unwrap();
            if es.tree.is_empty() {
                es.tree = build_tree(&state);
            }
            set_all_selected(&mut es.tree, true);
        }

        let es      = export_state.lock().unwrap();
        let flat    = flatten_tree(&es.tree);
        let items   = flat_to_slint_items(&flat);
        let summary = compute_summary(&es.tree);
        drop(es);

        ui.set_export_tree_nodes(ModelRc::new(Rc::new(VecModel::from(items))));
        ui.set_export_summary(summary);
    });
}

fn register_deselect_all<C, G, F>(
    ui:           &AppWindow,
       _state:       Arc<Mutex<AppState<C, G, F>>>,
    export_state: SharedExportState,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_export_deselect_all(move || {
        let ui = ui_handle.unwrap();

        {
            let mut es = export_state.lock().unwrap();
            set_all_selected(&mut es.tree, false);
        }

        let es      = export_state.lock().unwrap();
        let flat    = flatten_tree(&es.tree);
        let items   = flat_to_slint_items(&flat);
        let summary = compute_summary(&es.tree);
        drop(es);

        ui.set_export_tree_nodes(ModelRc::new(Rc::new(VecModel::from(items))));
        ui.set_export_summary(summary);
    });
}

fn register_filter_by_device<C, G, F>(
    ui:           &AppWindow,
        _state:      Arc<Mutex<AppState<C, G, F>>>,
    export_state: SharedExportState,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_export_filter_device(move |device_flat_index| {
        let ui = ui_handle.unwrap();

        {
            let mut es = export_state.lock().unwrap();

            if device_flat_index < 0 {
                set_all_selected(&mut es.tree, true);
            } else {
                let idx = device_flat_index as usize;
                if idx < es.tree.len() {
                    set_all_selected(&mut es.tree, false);
                    es.tree[idx].selected = true;
                    set_all_selected(&mut es.tree[idx].children, true);
                }
            }
        }

        let es      = export_state.lock().unwrap();
        let flat    = flatten_tree(&es.tree);
        let items   = flat_to_slint_items(&flat);
        let summary = compute_summary(&es.tree);
        drop(es);

        ui.set_export_tree_nodes(ModelRc::new(Rc::new(VecModel::from(items))));
        ui.set_export_summary(summary);
    });
}

fn register_export<C, G, F>(
    ui:           &AppWindow,
    state:        Arc<Mutex<AppState<C, G, F>>>,
    export_state: SharedExportState,
)
where
    C: CryptoService + Send + Clone + 'static,
    G: GeneratorService + Send + Clone + 'static,
    F: FileService + Send + Clone + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_export(move |file_name, folder_path, format_str, inc_comp, inc_meta, k1, k2| {
        let ui = ui_handle.unwrap();

        if file_name.trim().is_empty() {
            ui.set_export_error("O nome do ficheiro não pode estar vazio.".into());
            return;
        }
        if folder_path.trim().is_empty() {
            ui.set_export_error("A pasta de destino não pode estar vazia.".into());
            return;
        }
        if k1.is_empty() || k2.is_empty() {
            ui.set_export_error(
                "K1 e K2 são obrigatórios para desencriptar as seeds dos dispositivos.".into()
            );
            return;
        }

        let summary = ui.get_export_summary();
        if summary.domain_count + summary.static_count == 0 {
            ui.set_export_error(
                "Selecione pelo menos um domínio ou senha estática.".into()
            );
            return;
        }

        let path = format!(
            "{}/{}.{}",
            folder_path.trim_end_matches('/'),
            file_name.trim(),
            format_str.as_str()
        );

        let (device_uuids, restriction_uuids, domain_uuids, static_uuids) = {
            let es = export_state.lock().unwrap();
            extract_selected_uuids(&es.tree)
        };

        let format = match format_str.as_str() {
            "json" => ExportFormat::Json,
            "txt"  => ExportFormat::Txt,
            _      => ExportFormat::Csv,
        };

        helpers::show_loading(&ui, "A exportar senhas...");
        ui.set_export_error("".into());
        ui.set_export_is_exporting(true);

        let k1        = k1.to_string();
        let k2        = k2.to_string();
        let state     = Arc::clone(&state);
        let ui_handle = ui.as_weak();

        helpers::spawn_async(move || {
            let result = run_export(
                &state,
                &device_uuids,
                &restriction_uuids,
                &domain_uuids,
                &static_uuids,
                inc_comp,
                inc_meta,
                format,
                &path,
                &k1,
                &k2,
            );

            slint::invoke_from_event_loop(move || {
                let ui = ui_handle.unwrap();
                helpers::hide_loading(&ui);
                ui.set_export_is_exporting(false);

                match result {
                    Ok(bytes_written) => {
                        ui.set_export_error("".into());
                        helpers::toast_success(
                            &ui,
                            &state,
                            &format!(
                                "Exportado: {} ({} bytes)",
                                path, bytes_written
                            ),
                        );
                    }
                    Err(e) => {
                        let error_message = e.clone();
                        ui.set_export_error(error_message.into());
                        helpers::toast_error(
                            &ui,
                            &state,
                            &format!("Erro ao exportar: {}", e),
                        );
                    }
                }
            }).unwrap();
        });
    });
}

fn register_back<C, G, F>(
    ui:    &AppWindow,
    _state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_export_back(move || {
        let ui = ui_handle.unwrap();
        ui.set_active_view(1);
    });
}

fn build_tree<C, G, F>(state: &Arc<Mutex<AppState<C, G, F>>>) -> Vec<TreeNode>
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let s     = state.lock().unwrap();
    let vault = s.vault.lock().unwrap();

    let devices = vault.list_devices().unwrap_or_default();
    let mut tree = Vec::new();

    for device in &devices {
        let mut device_node = TreeNode {
            uuid:      device.uuid,
            label:     device.name.clone(),
            node_type: InternalNodeType::Device,
            selected:  false,
            children:  Vec::new(),
        };

        for restriction in vault.list_restrictions(device.uuid).unwrap_or_default() {
            let mut restriction_node = TreeNode {
                uuid:      restriction.uuid,
                label:     restriction.name.clone(),
                node_type: InternalNodeType::Restriction,
                selected:  false,
                children:  Vec::new(),
            };

            for domain in vault.list_domains(restriction.uuid).unwrap_or_default() {
                restriction_node.children.push(TreeNode {
                    uuid:      domain.uuid,
                    label:     domain.identifier_canonical.clone(),
                    node_type: InternalNodeType::DerivedPassword,
                    selected:  false,
                    children:  Vec::new(),
                });
            }

            device_node.children.push(restriction_node);
        }

        let static_pws = vault
            .list_static_passwords(device.uuid)
            .unwrap_or_default();

        let mut folders: Vec<String> = Vec::new();
        for sp in &static_pws {
            if !folders.contains(&sp.folder_path) {
                folders.push(sp.folder_path.clone());
            }
        }

        for folder in &folders {
            let folder_label = if folder.is_empty() {
                "(estáticas - raiz)".to_string()
            } else {
                format!("(estáticas - {})", folder)
            };

            let mut folder_node = TreeNode {
                uuid:      uuid::Uuid::new_v4(),
                label:     folder_label,
                node_type: InternalNodeType::Folder,
                selected:  false,
                children:  Vec::new(),
            };

            for sp in static_pws
                .iter()
                .filter(|sp| &sp.folder_path == folder)
            {
                let label = if sp.compromised {
                    format!("{} (comprometida)", sp.label)
                } else {
                    sp.label.clone()
                };

                folder_node.children.push(TreeNode {
                    uuid:      sp.uuid,
                    label,
                    node_type: InternalNodeType::StaticPassword,
                    selected:  false,
                    children:  Vec::new(),
                });
            }

            device_node.children.push(folder_node);
        }

        tree.push(device_node);
    }

    tree
}

struct FlatNode<'a> {
    node:   &'a TreeNode,
    indent: usize,
}

fn flatten_tree(tree: &[TreeNode]) -> Vec<FlatNode<'_>> {
    let mut result = Vec::new();
    flatten_recursive(tree, 0, &mut result);
    result
}

fn flatten_recursive<'a>(
    nodes:  &'a [TreeNode],
    indent: usize,
    result: &mut Vec<FlatNode<'a>>,
) {
    for node in nodes {
        result.push(FlatNode { node, indent });
        flatten_recursive(&node.children, indent + 1, result);
    }
}

fn flat_to_slint_items(flat: &[FlatNode<'_>]) -> Vec<TreeNodeItem> {
    flat.iter()
        .map(|f| TreeNodeItem {
            uuid:         f.node.uuid.to_string().into(),
            label:        f.node.label.clone().into(),
            node_type:    f.node.node_type.to_slint(),
            selected:     f.node.selected,
            indent:       f.indent as i32,
            has_children: !f.node.children.is_empty(),
        })
        .collect()
}

fn toggle_by_flat_index(tree: &mut [TreeNode], target: usize) {
    let mut counter = 0usize;
    toggle_recursive(tree, target, &mut counter);
    propagate_child_selection_up(tree);
}

fn propagate_child_selection_up(tree: &mut [TreeNode]) {
    for node in tree.iter_mut() {
        propagate_child_selection_up(&mut node.children);

        let should_select = match node.node_type {
            InternalNodeType::Restriction | InternalNodeType::Folder => {
                node.children.iter().any(|c| c.selected)
            }
            InternalNodeType::Device => {
                node.children.iter().any(|c| c.selected)
            }
            _ => false,
        };

        if should_select {
            node.selected = true;
        }
    }
}

fn toggle_recursive(
    nodes:   &mut [TreeNode],
    target:  usize,
    counter: &mut usize,
) -> bool {
    for node in nodes.iter_mut() {
        if *counter == target {
            let new_state = !node.selected;
            node.selected = new_state;
            set_all_selected(&mut node.children, new_state);
            return true;
        }
        *counter += 1;

        if toggle_recursive(&mut node.children, target, counter) {
            return true;
        }
    }
    false
}

fn set_all_selected(tree: &mut [TreeNode], selected: bool) {
    for node in tree.iter_mut() {
        node.selected = selected;
        set_all_selected(&mut node.children, selected);
    }
}

fn compute_summary(tree: &[TreeNode]) -> ExportSummaryItem {
    let mut device_count      = 0i32;
    let mut restriction_count = 0i32;
    let mut domain_count      = 0i32;
    let mut static_count      = 0i32;

    for device in tree {
        if device.selected {
            device_count += 1;
        }
        for group in &device.children {
            match group.node_type {
                InternalNodeType::Restriction => {
                    if group.selected {
                        restriction_count += 1;
                    }
                    for entry in &group.children {
                        if entry.selected {
                            domain_count += 1;
                        }
                    }
                }
                InternalNodeType::Folder => {
                    for entry in &group.children {
                        if entry.selected {
                            static_count += 1;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    ExportSummaryItem {
        device_count,
        restriction_count,
        domain_count,
        static_count,
    }
}

fn extract_selected_uuids(
    tree: &[TreeNode],
) -> (
    Vec<uuid::Uuid>, // device_uuids
    Vec<uuid::Uuid>, // restriction_uuids
    Vec<uuid::Uuid>, // domain_uuids
    Vec<uuid::Uuid>, // static_uuids
) {
    let mut device_uuids      = Vec::new();
    let mut restriction_uuids = Vec::new();
    let mut domain_uuids      = Vec::new();
    let mut static_uuids      = Vec::new();

    for device in tree {
        if !device.selected {
            continue;
        }
        device_uuids.push(device.uuid);

        for group in &device.children {
            match group.node_type {
                InternalNodeType::Restriction => {
                    if group.selected {
                        restriction_uuids.push(group.uuid);
                    }
                    for entry in &group.children {
                        if entry.selected {
                            domain_uuids.push(entry.uuid);
                        }
                    }
                }
                InternalNodeType::Folder => {
                    for entry in &group.children {
                        if entry.selected {
                            static_uuids.push(entry.uuid);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    (device_uuids, restriction_uuids, domain_uuids, static_uuids)
}

// Preserva as selecções do utilizador quando a árvore é reconstruída
#[allow(dead_code)]
fn merge_selection(old_tree: &[TreeNode], mut new_tree: Vec<TreeNode>) -> Vec<TreeNode> {
    for new_node in new_tree.iter_mut() {
        if let Some(old_node) = old_tree.iter().find(|n| n.uuid == new_node.uuid) {
            new_node.selected = old_node.selected;
            new_node.children = merge_selection(&old_node.children, new_node.children.clone());
        }
    }
    new_tree
}

#[allow(clippy::too_many_arguments)]
fn run_export<C, G, F>(
    state:            &Arc<Mutex<AppState<C, G, F>>>,
    device_uuids:     &[uuid::Uuid],
    restriction_uuids: &[uuid::Uuid],
    domain_uuids:     &[uuid::Uuid],
    static_uuids:     &[uuid::Uuid],
    inc_compromised:  bool,
    inc_metadata:     bool,
    format:           ExportFormat,
    path:             &str,
    k1:               &str,
    k2:               &str,
) -> Result<usize, String>
where
    C: CryptoService + Clone,
    G: GeneratorService + Clone,
    F: FileService + Clone,
{
    let vault = helpers::clone_vault(state);

    let prep = vault
        .prepare_export(
            device_uuids,
            restriction_uuids,
            domain_uuids,
            static_uuids,
            inc_compromised,
            inc_metadata,
        )
        .map_err(|e| format!("Erro ao preparar exportação: {}", e))?;

    // Requer a master key para desencriptar as seeds dos dispositivos e derivar as senhas
    let master_key = crate::core::MasterKeyInput::new(k1.to_string(), k2.to_string());
    let (data, _generation_duration) = vault
        .execute_export(&prep, &master_key)
        .map_err(|e| format!("Erro ao executar exportação: {}", e))?;

    let content = match format {
        ExportFormat::Csv  => data.to_csv(),
        ExportFormat::Json => data.to_json(),
        ExportFormat::Txt  => data.to_txt(),
    };

    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Erro ao criar pasta: {}", e))?;
    }

    // BOM UTF-8 (EF BB BF)
    let mut bytes = Vec::with_capacity(content.len() + 3);
    if matches!(format, ExportFormat::Csv | ExportFormat::Txt) {
        bytes.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    }
    bytes.extend_from_slice(content.as_bytes());

    std::fs::write(path, &bytes)
        .map_err(|e| format!("Erro ao escrever ficheiro: {}", e))?;

    Ok(bytes.len())
}