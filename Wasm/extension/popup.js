import init from "./pkg/vaultseed.js";
import { showWarningIfNeeded } from "./warning-modal.js";

// WASM inicia em background enquanto o modal está visível.
init();

showWarningIfNeeded({
  onContinue: () => { },
  onCancel: () => {
    const canvas = document.getElementById("canvas");
    if (canvas) canvas.style.display = "none";
    document.body.style.background = "#000";
  },
});
