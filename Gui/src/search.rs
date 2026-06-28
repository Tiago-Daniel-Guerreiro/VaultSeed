use slint::{ComponentHandle, ModelRc, VecModel};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use crate::core::{CryptoService, FileService, GeneratorService};
use crate::AppWindow;

use crate::ui::SearchResultItem;

use super::{helpers, AppState};

const MAX_RESULTS: usize = 10;

pub fn register<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    register_query(ui, Arc::clone(&state));
    register_select(ui, Arc::clone(&state));
}

fn register_query<C, G, F>(
    ui:    &AppWindow,
    state: Arc<Mutex<AppState<C, G, F>>>,
)
where
    C: CryptoService + Send + 'static,
    G: GeneratorService + Send + 'static,
    F: FileService + Send + 'static,
{
    let ui_handle = ui.as_weak();

    ui.on_on_search_query(move |query| {
        let ui = ui_handle.unwrap();

        ui.set_search_query(query.clone());

        if query.trim().is_empty() {
            ui.set_search_results(ModelRc::new(Rc::new(VecModel::from(Vec::new()))));
            return;
        }

        let s     = state.lock().unwrap();
        let vault = s.vault.lock().unwrap();
        let domain_results = vault.search_domains(query.as_str()).unwrap_or_default();
        let static_results = vault.search_static_passwords(query.as_str()).unwrap_or_default();
        drop(vault);
        drop(s);

        let mut items: Vec<(u32, SearchResultItem)> = Vec::with_capacity(
            domain_results.len() + static_results.len(),
        );

        for r in domain_results {
            items.push((r.score, SearchResultItem {
                kind:        "domain".into(),
                uuid:        r.domain_uuid.to_string().into(),
                label:       r.identifier.into(),
                subtitle:    format!("{} › {}", r.device_name, r.restriction_name).into(),
                compromised: false,
            }));
        }

        for r in static_results {
            let folder = if r.folder_path.is_empty() { "(raiz)".to_string() } else { r.folder_path };
            items.push((r.score, SearchResultItem {
                kind:        "static".into(),
                uuid:        r.uuid.to_string().into(),
                label:       r.label.into(),
                subtitle:    format!("{} > {}", r.device_name, folder).into(),
                compromised: r.compromised,
            }));
        }

        items.sort_by_key(|(score, _)| *score);

        let items: Vec<SearchResultItem> = items
            .into_iter()
            .take(MAX_RESULTS)
            .map(|(_, item)| item)
            .collect();

        ui.set_search_results(ModelRc::new(Rc::new(VecModel::from(items))));
    });
}

/// Ao seleccionar um resultado, navega para o domínio em Dispositivos › Domínios, ou para a senha estática na respectiva pasta.
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

    ui.on_on_search_select(move |kind, uuid_str| {
        let ui = ui_handle.unwrap();

        let uuid = match uuid::Uuid::parse_str(uuid_str.as_str()) {
            Ok(u)  => u,
            Err(_) => return,
        };

        match kind.as_str() {
            "domain" => select_domain_result(&ui, &state, uuid),
            "static" => select_static_result(&ui, &state, uuid),
            _        => {}
        }
    });
}

fn select_domain_result<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    domain_uuid: uuid::Uuid,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let domain = {
        let s     = state.lock().unwrap();
        let vault = s.vault.lock().unwrap();
        vault.get_domain(domain_uuid).ok()
    };

    let domain = match domain {
        Some(d) => d,
        None    => {
            helpers::toast_error(ui, state, "Domínio não encontrado.");
            return;
        }
    };

    {
        let mut s = state.lock().unwrap();
        s.selected_device_uuid      = None;
        s.selected_restriction_uuid = Some(domain.restriction_uuid);
        s.selected_domain_uuid      = Some(domain.uuid);
    }

    super::domains::refresh_domain_list(ui, state);
    ui.set_active_view(0);
    ui.set_active_sub_view(3); // 3 = Domínios
}

fn select_static_result<C, G, F>(
    ui:    &AppWindow,
    state: &Arc<Mutex<AppState<C, G, F>>>,
    static_uuid: uuid::Uuid,
)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let sp = {
        let s     = state.lock().unwrap();
        let vault = s.vault.lock().unwrap();
        vault.get_static_password_entry(static_uuid).ok()
    };

    let sp = match sp {
        Some(sp) => sp,
        None     => {
            helpers::toast_error(ui, state, "Senha estática não encontrada.");
            return;
        }
    };

    {
        let mut s = state.lock().unwrap();
        s.selected_device_uuid = Some(sp.device_uuid);
        s.selected_folder      = Some(sp.folder_path.clone());
        s.selected_static_uuid = Some(sp.uuid);
    }

    super::static_passwords::refresh_folder_list(ui, state);
    ui.set_active_view(0);
    ui.set_active_sub_view(2); // 2 = Senhas estáticas
}
