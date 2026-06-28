"""Server - abstração única para correr comandos, local ou remotamente."""

from __future__ import annotations

import base64
import os
import platform
import subprocess
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

from .config import ServerProfile

def _stream(line_iter) -> None:
    for line in line_iter:
        if line:
            print("    " + line.rstrip(), flush=True)

class Server(ABC):
    def __init__(self, profile: ServerProfile, port: int = 22):
        self.profile = profile
        self.port = port

    @property
    def label(self) -> str:
        return self.profile.label

    @property
    def is_local(self) -> bool:
        return self.profile.local

    def __enter__(self) -> "Server":
        return self

    def __exit__(self, *_exc) -> None:
        pass

    @abstractmethod
    def run(self, command: str, timeout: int = 600, sudo: bool = False) -> int:
        """Corre `command` e faz stream do output. Devolve o exit code."""

    @abstractmethod
    def capture(self, command: str, timeout: int = 60) -> str:
        """Corre `command` e devolve o stdout (sem o imprimir)."""

    @abstractmethod
    def upload(self, local: Path, remote: str) -> None: ...

    @abstractmethod
    def download(self, remote: str, local: Path) -> None: ...

    def run_checked(self, command: str, timeout: int = 600, sudo: bool = False) -> None:
        rc = self.run(command, timeout=timeout, sudo=sudo)
        if rc != 0:
            display = command if len(command) <= 200 else command[:200] + "…"
            raise RuntimeError(f"Comando falhou (exit {rc}): {display}")

    def run_fire_and_forget(self, command: str, timeout: int = 600) -> None:
        self.run_checked(command, timeout=timeout)

class SshServer(Server):
    """Servidor remoto via SSH (paramiko)."""
    def __init__(self, profile: ServerProfile, port: int = 22):
        super().__init__(profile, port)
        self.client = None
        self._sftp = None

    def __enter__(self) -> "SshServer":
        import paramiko
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            self.profile.host, port=self.port, username=self.profile.user,
            password=self.profile.password, timeout=30,
        )
        return self

    def __exit__(self, *_exc) -> None:
        if self._sftp is not None:
            self._sftp.close()
        if self.client is not None:
            self.client.close()

    @property
    def sftp(self):
        if self._sftp is None:
            self._sftp = self.client.open_sftp()
        return self._sftp

    def _wrap_sudo(self, command: str) -> str:
        b64 = base64.b64encode(command.encode("utf-8")).decode("ascii")
        return (
            f'echo "{self.profile.password}" | '
            f'sudo -S bash -c "echo {b64} | base64 -d | bash"'
        )

    def run(self, command: str, timeout: int = 600, sudo: bool = False) -> int:
        if sudo:
            command = self._wrap_sudo(command)
        _, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        _stream(iter(stdout.readline, ""))
        rc = stdout.channel.recv_exit_status()
        err = stderr.read().decode(errors="replace").strip()
        if err:
            print("    [stderr] " + err.replace("\n", "\n    [stderr] "), flush=True)
        return rc

    def capture(self, command: str, timeout: int = 60) -> str:
        _, stdout, _ = self.client.exec_command(command, timeout=timeout)
        data = stdout.read().decode(errors="replace")
        stdout.channel.recv_exit_status()
        return data.strip()

    def upload(self, local: Path, remote: str) -> None:
        print(f"    upload {Path(local).name} -> {remote}", flush=True)
        self.sftp.put(str(local), remote)

    def download(self, remote: str, local: Path) -> None:
        print(f"    download {remote} -> {local}", flush=True)
        self.sftp.get(remote, str(local))

class LocalServer(Server):
    """Corre os comandos nesta máquina - bash (Linux/nixos) ou PowerShell (Windows)."""

    def __init__(self, profile: ServerProfile, port: int = 22):
        super().__init__(profile, port)
        self._is_windows = profile.os == "windows"

    def _script_file(self, command: str) -> str:
        """Escreve `command` num .ps1 temporário (com BOM UTF-8) e devolve o caminho"""
        fd, path = tempfile.mkstemp(suffix=".ps1", prefix="vs_")
        with os.fdopen(fd, "w", encoding="utf-8-sig") as f:
            f.write("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n")
            f.write(command)
        return path

    def _cleanup_script(self, script_path: str) -> None:
        try:
            os.remove(script_path)
        except OSError:
            pass

    def _ps(self, script_path: str) -> list:
        return ["powershell.exe", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-File", script_path]

    def _run_windows(self, command: str, timeout: int) -> int:
        script_path = self._script_file(command)
        try:
            proc = subprocess.Popen(
                self._ps(script_path),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                encoding="utf-8", errors="replace",
            )
            assert proc.stdout is not None
            _stream(iter(proc.stdout.readline, ""))
            proc.wait(timeout=timeout)
            return proc.returncode
        finally:
            self._cleanup_script(script_path)

    def _capture_windows(self, command: str, timeout: int) -> str:
        script_path = self._script_file(command)
        try:
            out = subprocess.run(
                self._ps(script_path),
                capture_output=True, encoding="utf-8", errors="replace",
                timeout=timeout,
            )
            return out.stdout.strip()
        finally:
            self._cleanup_script(script_path)

    def _fire_and_forget_windows(self, command: str, timeout: int) -> None:
        script_path = self._script_file(command)
        try:
            proc = subprocess.run(
                self._ps(script_path),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"Comando falhou (exit {proc.returncode})")
        finally:
            self._cleanup_script(script_path)

    def _run_unix(self, command: str, timeout: int, sudo: bool) -> int:
        if sudo:
            proc = subprocess.Popen(
                ["sudo", "-S", "bash", "-c", command],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True,
            )
            assert proc.stdin is not None
            proc.stdin.write(self.profile.password + "\n")
            proc.stdin.flush()
            proc.stdin.close()
        else:
            proc = subprocess.Popen(
                ["bash", "-c", command],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
        assert proc.stdout is not None
        _stream(iter(proc.stdout.readline, ""))
        proc.wait(timeout=timeout)
        return proc.returncode

    def _capture_unix(self, command: str, timeout: int) -> str:
        out = subprocess.run(
            ["bash", "-c", command],
            capture_output=True, text=True, timeout=timeout,
        )
        return out.stdout.strip()

    def run(self, command: str, timeout: int = 600, sudo: bool = False) -> int:
        if self._is_windows:
            return self._run_windows(command, timeout)
        return self._run_unix(command, timeout, sudo)

    def capture(self, command: str, timeout: int = 60) -> str:
        if self._is_windows:
            return self._capture_windows(command, timeout)
        return self._capture_unix(command, timeout)

    def run_fire_and_forget(self, command: str, timeout: int = 600) -> None:
        if self._is_windows:
            self._fire_and_forget_windows(command, timeout)
        else:
            self.run_checked(command, timeout=timeout)

    def upload(self, local: Path, remote: str) -> None:
        import shutil
        print(f"    copy {Path(local).name} -> {remote}", flush=True)
        shutil.copy(str(local), remote)

    def download(self, remote: str, local: Path) -> None:
        import shutil
        print(f"    copy {remote} -> {local}", flush=True)
        shutil.copy(remote, str(local))

def make_server(config) -> Server:
    profile = config.server()
    if profile.local:
        return LocalServer(profile, config.port())
    return SshServer(profile, config.port())

def real_os() -> str: # Não diferencia entre Linux e NixOS, apenas Windows vs Linux
    return "windows" if platform.system() == "Windows" else "linux"

def os_mismatch(profile: ServerProfile) -> bool:
    detected = real_os()
    if detected == "windows":
        return profile.os != "windows"
    return profile.os == "windows"
