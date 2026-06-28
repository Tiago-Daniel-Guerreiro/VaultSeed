from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..core.job import CheckTestsEnv, ReleaseEnv
from ..core.job import BashReleaseBuilder, PowerShellReleaseBuilder, ReleaseBuilder
from ..core.setup_job import LinuxSetupBuilder, NixosSetupBuilder, SetupBuilder, WindowsSetupBuilder
from ..core.component import Component
from ..linux import components as _linux_components, env as _linux_env
from ..nixos import components as _nixos_components, env as _nixos_env
from ..windows import components as _windows_components, env as _windows_env

PLATFORMS = ("linux", "windows", "nixos")

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_WINDOWS_BAT_DIR = _REPO_ROOT / "Build" / "windows"

@dataclass
class PlatformData:
    name: str
    env_module: object
    components_module: object
    native_windows: bool   # PowerShell + targets *-pc-windows-msvc nativos

_DATA = {
    "linux":   PlatformData("linux",   _linux_env,   _linux_components, native_windows=False),
    "nixos":   PlatformData("nixos",   _nixos_env,   _nixos_components, native_windows=False),
    "windows": PlatformData("windows", _windows_env, _windows_components, native_windows=True),
}

def for_os(os_name: str) -> PlatformData:
    if os_name not in _DATA:
        raise ValueError(f"Plataforma desconhecida: {os_name!r} (esperado um de {PLATFORMS})")
    return _DATA[os_name]

def check_tests_env(os_name: str) -> CheckTestsEnv:
    m = for_os(os_name).env_module
    return CheckTestsEnv(
        check_env=m.CHECK_ENV,
        tests_env=m.TESTS_ENV,
        native_target=m.NATIVE_TARGET,
        check_variants=m.CHECK_VARIANTS,
    )

def release_env(os_name: str) -> ReleaseEnv:
    m = for_os(os_name).env_module
    return ReleaseEnv(
        env_snippet=m.RELEASE_ENV_SNIPPET,
        env_prefix=getattr(m, "RELEASE_ENV_PREFIX", {}),
        build_timeout=m.RELEASE_BUILD_TIMEOUT,
        apk_timeout=m.RELEASE_APK_TIMEOUT,
        poll_interval=m.RELEASE_POLL_INTERVAL,
    )

def release_builder(os_name: str) -> ReleaseBuilder:
    return PowerShellReleaseBuilder() if for_os(os_name).native_windows else BashReleaseBuilder()

def setup_builder(os_name: str, *, sudo_pass: str = "") -> SetupBuilder:
    if os_name == "linux":
        return LinuxSetupBuilder(sudo_pass)
    if os_name == "nixos":
        return NixosSetupBuilder()
    if os_name == "windows":
        return WindowsSetupBuilder()
    raise ValueError(f"Plataforma desconhecida: {os_name!r}")

_WINDOWS_BAT_NAMES = (
    "setup_admin.bat", "uninstall_msvc_buildtools.bat",
    "uninstall_jdk17.bat", "disable_dev_mode.bat",
)

def upload_windows_bats(server) -> dict[str, str]:
    from ..core.source_sync import SourceSync

    remote_dir = f"{SourceSync(server).remote_project_dir}/Build/windows"
    server.run_checked(f'New-Item -ItemType Directory -Force -Path "{remote_dir}" | Out-Null')

    paths: dict[str, str] = {}
    for name in _WINDOWS_BAT_NAMES:
        remote_path = f"{remote_dir}/{name}"
        server.upload(_WINDOWS_BAT_DIR / name, remote_path)
        paths[name] = remote_path
    return paths

def uninstall_components(os_name: str, bat_paths: dict[str, str] | None = None) -> list[Component]:
    m = for_os(os_name).components_module
    if os_name == "windows":
        bat_paths = bat_paths or {}
        return m.components(
            bat_paths.get(
                "uninstall_msvc_buildtools.bat",
                str(_WINDOWS_BAT_DIR / "uninstall_msvc_buildtools.bat").replace("\\", "/"),
            ),
            bat_paths.get(
                "uninstall_jdk17.bat",
                str(_WINDOWS_BAT_DIR / "uninstall_jdk17.bat").replace("\\", "/"),
            ),
            bat_paths.get(
                "disable_dev_mode.bat",
                str(_WINDOWS_BAT_DIR / "disable_dev_mode.bat").replace("\\", "/"),
            ),
        )
    return m.components()
