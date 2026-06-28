fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("assets/icons/app.rc", embed_resource::NONE)
            .manifest_required()
            .unwrap_or_else(|e| panic!("Erro ao compilar recurso Windows: {}", e));
    }
}