"""SourceSync: compacta e envia o código-fonte para um Servidor"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path

from .remote_op import sync_source, sync_source_windows
from .server import Server

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

EXCLUDE_DIRS  = {".git", "target", "result", "ignore", "tools", "ignorar", "nao_usar"}
EXCLUDE_NAMES = {".ds_store", "thumbs.db", "vaultseed_source.zip", ".git"}

class SourceSync:
    def __init__(self, server: Server):
        self.server = server

    @property
    def is_windows(self) -> bool:
        return self.server.profile.os == "windows"

    @property
    def remote_home(self) -> str:
        if self.server.is_local:
            return str(Path.home()).replace("\\", "/")
        user = self.server.profile.user or "user"
        if self.is_windows:
            return f"C:/Users/{user}"
        return f"/home/{user}"

    @property
    def remote_appdata(self) -> str:
        """Raiz de dados da aplicação no servidor Windows."""
        if self.server.is_local:
            appdata = os.environ.get("APPDATA")
            base = appdata.replace("\\", "/") if appdata else f"{self.remote_home}/AppData/Roaming"
            return f"{base}/VaultSeed"
        return f"C:/Users/{self.server.profile.user or 'user'}/AppData/Roaming/VaultSeed"

    @property
    def remote_project_dir(self) -> str:
        if self.is_windows:
            return f"{self.remote_appdata}/source"
        return f"{self.remote_home}/VaultSeed"

    @staticmethod
    def make_source_zip(dest: Path) -> Path:
        dest.unlink(missing_ok=True)
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(REPO_ROOT):
                dirs[:] = [d for d in dirs if d.lower() not in EXCLUDE_DIRS]
                for name in files:
                    if name.lower() in EXCLUDE_NAMES:
                        continue
                    abs_path = Path(root) / name
                    if abs_path == dest:
                        continue
                    zf.write(abs_path, abs_path.relative_to(REPO_ROOT).as_posix())
        return dest

    def sync_to_server(self, zip_path: Path) -> None:
        """Envia o zip e substitui a pasta do projecto, preservando as caches de build (.targets/, target/) entre execuções."""
        if self.is_windows:
            remote_zip = f"{self.remote_appdata}/VaultSeed_source.zip"
            sync_source_windows(self.server, zip_path, remote_zip, self.remote_project_dir, self.remote_appdata)
        else:
            remote_zip = f"{self.remote_home}/VaultSeed_source.zip"
            sync_source(self.server, zip_path, remote_zip, self.remote_project_dir, self.remote_home)
