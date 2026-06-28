fn main() {
    slint_build::compile("ui/app_window.slint")
        .unwrap_or_else(|e| panic!("Erro ao compilar ficheiros .slint: {}", e));
}
