# Wasm/static/ - snapshot manual do site compilado, para GitHub Pages

Esta pasta **não é gerada nem tocada pelos scripts de `Build/`** - é uma
cópia exacta do conteúdo do zip de release do site (`VaultSeed-site.zip`),
atualizada manualmente, e versionada (ao contrário de `Wasm/site/pkg/`,
que está no `.gitignore` por ser sempre regenerado pela build). Existe
para que o GitHub Pages (a servir a partir da raiz do repositório) consiga
mostrar a app a funcionar sem ninguém ter de correr nenhum build - só
visitar o link. O `index.html` da raiz do repositório só redireciona para
aqui.

## O que deve estar aqui

Exactamente o que sai do zip de release do site (`Wasm/site/*` + o `pkg/`
copiado da extensão, tal como a build já faz para gerar esse zip):

```
Wasm/static/
├── index.html
├── index.js
├── warning-modal.js
├── icon.png
└── pkg/
    ├── vaultseed.js
    └── vaultseed_bg.wasm
```

## Como atualizar

Depois de uma build normal que inclua o alvo `wasm32-extension` (gera
`artefacts/wasm/VaultSeed-site.zip`), extrai esse zip directamente para
aqui:

```sh
# A partir da raiz do repositório, com o zip de release do site à mão:
rm -rf Wasm/static
mkdir Wasm/static
unzip -o VaultSeed-site.zip -d Wasm/static
```

Ou, sem fazer build, copiando à mão a partir de `Wasm/site/` (depois de
`Wasm/site/pkg/` existir, preenchido por um build local):

```sh
rm -rf Wasm/static
cp -r Wasm/site Wasm/static
```

Faz commit de `Wasm/static/` normalmente.
