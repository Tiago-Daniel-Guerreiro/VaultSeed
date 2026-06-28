# VaultSeed - extensão de browser (popup)

> **Estado:** Experimental

A extensão mostra a GUI Slint do VaultSeed (login, gerar senhas, cofre, etc.) num popup, compilada para `wasm32-unknown-unknown` via `wasm-bindgen`. A configuração local é guardada num cookie e a sessão em `localStorage`.

## Compilar
Requer [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/).

A partir da raiz do repositório:

```sh
wasm-pack build --target web --release --no-default-features --features extension --out-dir Wasm/extension/pkg
```

Isto gera `Wasm/extension/pkg/vaultseed.js` e `Wasm/extension/pkg/vaultseed_bg.wasm`, usados por `popup.html`.

## Carregar no browser (modo developer)
1. Abrir `chrome://extensions` (ou `edge://extensions`).
2. Ativar "Modo de desenvolvedor".
3. "Carregar sem empacotar" → selecionar a pasta `Wasm/extension/`.
4. Clicar no ícone da extensão para abrir o popup.