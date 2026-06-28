import init from "./pkg/vaultseed.js";
import { showWarningIfNeeded } from "./warning-modal.js";

init();

showWarningIfNeeded({
  onContinue: () => { },
  onCancel: () => { window.location.href = "https://github.com/Tiago-Daniel-Guerreiro/VaultSeed/"; },
});
