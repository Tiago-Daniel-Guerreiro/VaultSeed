// Aviso de versão browser. Exibido na primeira visita (sem cookie).
// Exporta showWarningIfNeeded({ onContinue, onCancel }).

const COOKIE     = "vs_no_browser_warning";
const RELEASES   = "https://github.com/Tiago-Daniel-Guerreiro/VaultSeed/releases";

function hasCookie() {
  return document.cookie.split(";").some(c => c.trim().startsWith(COOKIE + "=1"));
}

function saveCookie() {
  const d = new Date();
  d.setFullYear(d.getFullYear() + 10);
  document.cookie = `${COOKIE}=1; expires=${d.toUTCString()}; path=/; SameSite=Lax`;
}

const STYLES = `
#vs-warn-overlay {
  position: fixed; inset: 0; z-index: 9999;
  background: rgba(0,0,0,0.75);
  display: flex; align-items: center; justify-content: center;
  font-family: system-ui, sans-serif;
}
#vs-warn-box {
  background: #1a1a1a; color: #e8e8e8;
  border: 1px solid #333; border-radius: 10px;
  padding: 24px 28px; max-width: 370px; width: 90%;
  box-shadow: 0 8px 32px rgba(0,0,0,0.6);
}
#vs-warn-box h2 {
  margin: 0 0 12px; font-size: 1.1rem; color: #f5c542;
  display: flex; align-items: center; gap: 8px;
}
#vs-warn-box p {
  margin: 0 0 14px; font-size: 0.9rem; line-height: 1.55;
  color: #ccc;
}
#vs-warn-box a {
  color: #7bb3ff; word-break: break-all; font-size: 0.85rem;
}
#vs-warn-check {
  display: flex; align-items: center; gap: 8px;
  margin: 16px 0; font-size: 0.85rem; color: #aaa; cursor: pointer;
}
#vs-warn-check input { cursor: pointer; accent-color: #7bb3ff; }
#vs-warn-btns {
  display: flex; gap: 10px; justify-content: flex-end; margin-top: 4px;
}
#vs-warn-btns button {
  padding: 8px 20px; border: none; border-radius: 6px;
  font-size: 0.9rem; cursor: pointer; font-weight: 500;
}
#vs-btn-cancel   { background: #2d2d2d; color: #ccc; }
#vs-btn-cancel:hover { background: #3a3a3a; }
#vs-btn-continue { background: #2a6e2a; color: #fff; }
#vs-btn-continue:hover { background: #358035; }
`;

export function showWarningIfNeeded({ onContinue, onCancel }) {
  if (hasCookie()) { onContinue(); return; }

  const style = document.createElement("style");
  style.textContent = STYLES;
  document.head.appendChild(style);

  const el = document.createElement("div");
  el.id = "vs-warn-overlay";
  el.innerHTML = `
    <div id="vs-warn-box">
      <h2>Aviso Importante</h2>
      <p>
        Esta é uma versão para browser. O recomendado é usar a versão de
        aplicativo que suporta Android, Windows e Linux, pois esta versão
        pode ter riscos quanto a extensões maliciosas e outros.
      </p>
      <p>
        <a href="${RELEASES}" target="_blank" rel="noopener noreferrer">
          Link: ${RELEASES}
        </a>
      </p>
      <label id="vs-warn-check">
        <input type="checkbox" id="vs-no-warn">
        Não ver novamente
      </label>
      <div id="vs-warn-btns">
        <button id="vs-btn-cancel">Cancelar</button>
        <button id="vs-btn-continue">Continuar</button>
      </div>
    </div>
  `;
  document.body.appendChild(el);

  el.querySelector("#vs-btn-continue").onclick = () => {
    if (el.querySelector("#vs-no-warn").checked) saveCookie();
    el.remove();
    onContinue();
  };

  el.querySelector("#vs-btn-cancel").onclick = () => {
    el.remove();
    onCancel();
  };
}
