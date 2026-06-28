// Integrações nativas de Android via JNI. Compilado só em Android.
#![cfg(target_os = "android")]

use std::sync::{Mutex, OnceLock};

use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jint, JavaVM as RawJavaVM};
use jni::JavaVM;

// Handles globais para o seletor de ficheiros: a AndroidApp (para lançar a Activity auxiliar) e um weak da janela (para entregar o resultado à UI).
static APP: OnceLock<slint::android::AndroidApp> = OnceLock::new();
static UI: OnceLock<Mutex<slint::Weak<crate::AppWindow>>> = OnceLock::new();

/// Guarda os handles. Chamar em `android_main` depois de criar a janela.
pub fn store_handles(app: slint::android::AndroidApp, ui: slint::Weak<crate::AppWindow>) {
    let _ = APP.set(app);
    let _ = UI.set(Mutex::new(ui));
}

/// Devolve o caminho REAL da pasta privada da app (`getExternalFilesDir(null)`, com fallback para `getFilesDir()`). 
/// Porque o SAF (content://) não expõe caminhos reais para escrita.
pub fn app_files_dir() -> String {
    match try_app_files_dir() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[android] app_files_dir falhou: {:?}", e);
            String::new()
        }
    }
}

fn try_app_files_dir() -> Result<String, jni::errors::Error> {
    let app = match APP.get() {
        Some(a) => a,
        None => return Ok(String::new()),
    };
    let vm = unsafe { JavaVM::from_raw(app.vm_as_ptr() as *mut RawJavaVM)? };
    let mut env = vm.attach_current_thread()?;
    let activity = unsafe { JObject::from_raw(app.activity_as_ptr() as jni::sys::jobject) };

    let null_arg = JObject::null();
    let dir = env
        .call_method(
            &activity,
            "getExternalFilesDir",
            "(Ljava/lang/String;)Ljava/io/File;",
            &[(&null_arg).into()],
        )?
        .l()?;

    // Fallback: se o externo for null, usa getFilesDir() (sempre disponível).
    let dir = if dir.is_null() {
        env.call_method(&activity, "getFilesDir", "()Ljava/io/File;", &[])?
            .l()?
    } else {
        dir
    };

    if dir.is_null() {
        return Ok(String::new());
    }

    let path_obj = env
        .call_method(&dir, "getAbsolutePath", "()Ljava/lang/String;", &[])?
        .l()?;
    let jstr = JString::from(path_obj);
    let path: String = env.get_string(&jstr)?.into();
    Ok(path)
}

/// Copia texto para a clipboard do sistema via `ClipboardManager`
pub fn set_clipboard_text(text: &str) -> Result<(), String> {
    if APP.get().is_none() {
        return Err("Aplicação Android não inicializada".to_string());
    }
    try_set_clipboard_text(text).map_err(|e| e.to_string())
}

fn try_set_clipboard_text(text: &str) -> Result<(), jni::errors::Error> {
    let app = APP.get().expect("APP verificado em set_clipboard_text");
    let vm = unsafe { JavaVM::from_raw(app.vm_as_ptr() as *mut RawJavaVM)? };
    let mut env = vm.attach_current_thread()?;
    let activity = unsafe { JObject::from_raw(app.activity_as_ptr() as jni::sys::jobject) };

    let service_name = env.new_string("clipboard")?;
    let clipboard_manager = env
        .call_method(
            &activity,
            "getSystemService",
            "(Ljava/lang/String;)Ljava/lang/Object;",
            &[(&service_name).into()],
        )?
        .l()?;

    if clipboard_manager.is_null() {
        return Err(jni::errors::Error::NullPtr("ClipboardManager"));
    }

    let clip_data_class = env.find_class("android/content/ClipData")?;
    let label = env.new_string("VaultSeed")?;
    let value = env.new_string(text)?;
    let clip = env
        .call_static_method(
            &clip_data_class,
            "newPlainText",
            "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;",
            &[(&label).into(), (&value).into()],
        )?
        .l()?;

    env.call_method(
        &clipboard_manager,
        "setPrimaryClip",
        "(Landroid/content/ClipData;)V",
        &[(&clip).into()],
    )?;

    Ok(())
}

/// Lança o seletor de ficheiros do Android (SAF, ACTION_OPEN_DOCUMENT) através da Activity auxiliar. 
pub fn launch_picker(kind: &str) {
    if let Err(e) = try_launch_picker(kind) {
        eprintln!("[android] launch_picker falhou: {:?}", e);
        deliver_to_ui(String::new());
    }
}

fn try_launch_picker(kind: &str) -> Result<(), jni::errors::Error> {
    let app = match APP.get() {
        Some(a) => a,
        None => return Ok(()),
    };
    let vm = unsafe { JavaVM::from_raw(app.vm_as_ptr() as *mut RawJavaVM)? };
    let mut env = vm.attach_current_thread()?;
    let activity = unsafe { JObject::from_raw(app.activity_as_ptr() as jni::sys::jobject) };

    let picker_class = env.find_class("com/projetopap/vaultseed/FilePickerActivity")?;
    let intent_class = env.find_class("android/content/Intent")?;

    let intent = env.new_object(
        &intent_class,
        "(Landroid/content/Context;Ljava/lang/Class;)V",
        &[(&activity).into(), (&picker_class).into()],
    )?;

    let key = env.new_string("kind")?;
    let val = env.new_string(kind)?;
    env.call_method(
        &intent,
        "putExtra",
        "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;",
        &[(&key).into(), (&val).into()],
    )?;

    env.call_method(
        &activity,
        "startActivity",
        "(Landroid/content/Intent;)V",
        &[(&intent).into()],
    )?;

    Ok(())
}

/// Entrega o caminho escolhido à UI (no event loop do Slint)
fn deliver_to_ui(path: String) {
    let weak = match UI.get() {
        Some(m) => m.lock().unwrap().clone(),
        None => return,
    };
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_picked_path(path.clone().into());
            ui.set_pick_seq(ui.get_pick_seq() + 1);
        }
    });
}

/// Método nativo chamado pela FilePickerActivity (Java) com o caminho real do ficheiro copiado para a cache (ou "" se cancelado/erro).
#[no_mangle]
pub extern "system" fn Java_com_projetopap_vaultseed_FilePickerActivity_nativeDeliverPickedPath(
    mut env: jni::JNIEnv,
    _class: JClass,
    path: JString,
) {
    let p: String = env
        .get_string(&path)
        .map(|s| s.into())
        .unwrap_or_default();
    deliver_to_ui(p);
}

/// Ativa o modo de ecrã inteiro imersivo (esconde a barra de estado e a barra de navegação, com "immersive sticky")
pub fn enable_fullscreen(app: &slint::android::AndroidApp) {
    if let Err(e) = try_enable_fullscreen(app) {
        eprintln!("[android] enable_fullscreen falhou: {:?}", e);
    }
}

fn try_enable_fullscreen(app: &slint::android::AndroidApp) -> Result<(), jni::errors::Error> {
    // Flags View.SYSTEM_UI_FLAG_*: esconde as barras do sistema (imersivo)
    //   FULLSCREEN(0x4) | HIDE_NAVIGATION(0x2) | LAYOUT_STABLE(0x100) | IMMERSIVE_STICKY(0x1000)
    let flags: jint = 0x4 | 0x2 | 0x100 | 0x1000;

    let vm = unsafe { JavaVM::from_raw(app.vm_as_ptr() as *mut RawJavaVM)? };
    let mut env = vm.attach_current_thread()?;

    let activity = unsafe { JObject::from_raw(app.activity_as_ptr() as jni::sys::jobject) };

    let window = env
        .call_method(&activity, "getWindow", "()Landroid/view/Window;", &[])?
        .l()?;

    let decor = env
        .call_method(&window, "getDecorView", "()Landroid/view/View;", &[])?
        .l()?;

    env.call_method(
        &decor,
        "setSystemUiVisibility",
        "(I)V",
        &[JValue::Int(flags)],
    )?;

    Ok(())
}
