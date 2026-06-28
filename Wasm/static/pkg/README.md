# VaultSeed

**O gestor de senhas que não guarda as senhas que gera - calcula-as.**

O VaultSeed é uma aplicação para criar e gerir as senhas dos teus serviços (email, redes sociais, banco, etc.). Funciona totalmente **offline**, em computador ou telemóvel, **sem nuvem e sem conta** para criar.

> **Nota honesta:** o VaultSeed prioriza a **segurança** acima da conveniência.
> A experiência de utilização é mais **crua e exigente** do que a das apps comerciais, pede decisões explícitas, não esconde os mecanismos e não tem os automatismos habituais. É um compromisso assumido: menos "polido", mas com o controlo e a segurança no centro de tudo.

---

## Conceito

O VaultSeed trabalha com dois tipos de senhas:
- **Senhas existentes** as que já existentes (códigos, PINs, chaves  de recuperação). O VaultSeed permite **adicioná-las** ao cofre, onde ficam **guardadas encriptadas**.
- **Senhas derivadas** as que o VaultSeed cria a partir de um domínio. Estas **não ficam guardadas**: são **recalculadas** sempre que necessário, a partir de duas chaves que só o utilizador conhece. Para o mesmo serviço, com as mesmas chaves, obténs **sempre a mesma senha** (variam com os uuids e a seed).

> **O utilizador introduz as duas chaves → o VaultSeed reconstrói a senha certa  para cada serviço.**

É como ter uma **fórmula secreta** em vez de uma lista de senhas. Quem obtiver o ficheiro do VaultSeed não consegue absolutamente nada sem as chaves.

---

## O que o VaultSeed faz por ti

- **Senhas fortes e únicas** para cada serviço, recalculadas quando precisares, sem as decorar e sem ficarem guardadas.
- **Controlo total do formato** de cada senha: comprimento, tipos de caracteres e partes fixas.
- **Trocar a senha de um serviço** sem afetar as outras.
- **Cofre encriptado** para guardar senhas existentes que não podem ser geradas.
- **Exportar tudo em segundos** tanto as senhas geradas e existentes para um ficheiro (CSV, JSON ou TXT), por exemplo para migrar para outra ferramenta.
- **Proteção extra opcional** com um ficheiro-chave físico (ex.: numa pen).
- **Funciona offline, em Windows, macOS, Linux e Android.**

O que é necessário: ter o único ficheiro (encriptado) e as chaves (memorizáveis). Se chaves forem perdidas, não é possivél recuperar o conteúdo (sem as ter em ficheiros xor pcomo backup). É precisamente itso que o torna seguro.

---

## Para quem é técnico

O VaultSeed é um gestor de credenciais **determinístico**, escrito em **Rust**, offline e sem servidor. O princípio central é separar a **proteção** do segredo da **geração**:

- Duas chaves humanas (**K1 + K2**) servem apenas para **desencriptar uma seed** (32 bytes por dispositivo); **nunca geram senhas diretamente**.
- A **seed** é a única fonte de entropia: cada senha derivada é calculada de forma determinística a partir dela e de um contexto fixo (domínio, variação, dispositivo, restrição). Estas senhas **não são armazenadas**.
- As **senhas estáticas** (segredos que não podem ser gerados) são a exceção: são **guardadas encriptadas**, com uma chave derivada da seed.
- Rodar a proteção (mudar K1/K2 ou o fator físico) **não altera as senhas**; só mudar a seed é que o faz (ou mudar a restrição de um domínio).

**Algoritmos usados:**

- **Argon2id**: deriva as chaves de encriptação a partir de K1+K2 (memory-hard).
- **KMAC256 (XOF)**: gera a entropia de cada senha derivada (chave = seed).
- **XChaCha20-Poly1305 (AEAD)**: encriptação autenticada; deteta chaves erradas antes de gerar qualquer senha.
- **HKDF-SHA256**: combina o fator físico e finaliza a chave da sessão.
- **HMAC-SHA256**: integridade do ficheiro e verificação de senhas congeladas.

Só seeds e metadados são guardados, sempre encriptados, num ficheiro de sessão que não pode ser desencriptado sem K1/K2. O mesmo input produz sempre o mesmo output em qualquer plataforma.

Modos de utilização: interface gráfica (predefinição), consola interativa (`--cli`) e comandos técnicos para as primitivas (`--generate`, `--kmac`, …; ver `--help`).

---

## Plataformas suportadas

| Plataforma  | Compila | CI automático | Scripts `Build/` | Testado pessoalmente |
|-------------|:-------:|:--------------:|:----------------:|:---------------------:|
| Windows     | ✅      | ✅              | ✅                | ✅                     |
| Linux       | ✅      | ✅              | ✅                | ✅                     |
| Android     | ✅      | ✅              | ✅                | ✅                     |
| macOS       | ✅      | ✅              | ❌                | ❌                     |
| iOS         | ✅ (experimental) | ✅ | ❌          | ❌                     |
| WASM (lib)  | ✅      | ✅ (`check`)    | ✅                | ❌                     |
| Extensão de browser (popup, WASM) | ✅ (experimental) | ❌ | ✅ | ✅ |
| Site estático (página web, WASM)  | ✅ (experimental) | ❌ | ✅ | ❌ |

> **iOS:** compila e passa `cargo check --features desktop` na CI, mas só o clipboard tem código específico para iOS (`UIPasteboard`, não testado), a GUI em si não tem projeto Xcode/empacotamento, por isso não produz um executável iOS.
> **Extensão de browser:** ver [`Wasm/extension/README.md`](Wasm/extension/README.md) para instruções de build (`wasm-pack`) e carregamento no browser. Os scripts `Build/` já compilam e empacotam a extensão (zip pronto para instalação).
> **Site estático:** a mesma build WASM da extensão é reutilizada para gerar um site estático (`Wasm/site/`), incluído no zip de release como `artefacts_*/wasm/VaultSeed-site.zip`. Pode ser hospedado em qualquer servidor de ficheiros estáticos (GitHub Pages, Netlify, etc.). Ao abrir, ambas as versões (extensão e site) mostram um aviso sobre os riscos de usar o gestor de senhas no browser, com opção de continuar ou sair.
> **Pré-visualização sem build (GitHub Pages):** `index.html` na raiz do repositório redireciona para `Wasm/static/`, uma cópia do zip de release do site já compilada, mantida manualmente (não gerada pelos scripts de `Build/`), permite testar a app diretamente do GitHub Pages sem correr nenhum build. Ver `Wasm/static/README.md`.

---

## Segurança, sem rodeios

**Protege bem contra** roubo do ficheiro, acesso físico ao aparelho desligado, adulteração do ficheiro e erros de digitação das chaves.
**Não protege contra** malware ativo no teu sistema, leitura da memória com a sessão aberta, ou phishing, e a exportação de senhas é em **texto claro** (só para migração). Nenhuma ferramenta resolve tudo; o VaultSeed é forte exatamente naquilo a que se propõe: manter os segredos fora do alcance de quem não tem as chaves.
