from __future__ import annotations

import base64
import os
import re
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from .action import Action, stamp_from_id
from .remote_op import RC_DETACHED, RemoteOp, _ts
from .server import Server
from .source_sync import SourceSync
from .target import GROUP_ANDROID, GROUP_LINUX, GROUP_WASM, GROUP_WINDOWS, TargetRegistry

# CheckJob / TestsJob: check + clippy + testes
@dataclass
class CheckTestsEnv: 
    check_env: str
    tests_env: str
    native_target: str
    check_variants: list[tuple[str, str, str]]  # (nome, target, flags)

class CheckJob:
    def __init__(
        self,
        server: Server,
        env: CheckTestsEnv,
        registry: TargetRegistry,
        build_jobs: int | None = None,
        release: bool = True,
        variant_filter: list[str] | None = None,
    ):
        self.server = server
        self.env    = env
        self.registry = registry
        self.build_jobs = build_jobs
        self.release = release
        
        self.variants = (
            env.check_variants if variant_filter is None
            else [v for v in env.check_variants if v[0] in variant_filter]
        )

    def _check_log_name(self, name: str, target: str) -> str:
        return f"check-{name}-{target}"

    def _script(self, op: RemoteOp, project_dir: str) -> str:
        is_windows = self.server.profile.os == "windows"
        lines: list[str] = [op.preamble()]
        if not is_windows:
            lines.insert(0, "#!/usr/bin/env bash\nset -u\n")
        lines.append(self.env.check_env)
        if is_windows:
            lines.append(f'Set-Location "{project_dir}"')
            lines.append('rustup target add wasm32-unknown-unknown 2>$null | Out-Null')
            if self.build_jobs is not None:
                lines.append(f"$env:CARGO_BUILD_JOBS='{self.build_jobs}'")
        else:
            lines.append(f'cd {project_dir} || exit 97')
            lines.append('rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true')
            if self.build_jobs is not None:
                lines.append(f"export CARGO_BUILD_JOBS={self.build_jobs}")
        lines.append("")

        release_flag = "--release " if self.release else ""
        for name, target, flags in self.variants:
            log = self._check_log_name(name, target)
            if is_windows:
                cmd = (
                    f"cargo check {release_flag}--target {target} {flags} "
                    f'--message-format=short *> "$CARGO_LOGS/{log}.log"'
                )
                lines += [
                    f'_fase "cargo check {target} ({name})"',
                    cmd,
                    'if ($LASTEXITCODE -eq 0) {',
                    f'    _ok "cargo check {name} OK"',
                    '} else {',
                    f'    _fail "cargo check {name} FALHOU - ver log"',
                    f'    Select-String -Path "$CARGO_LOGS/{log}.log" -Pattern "^error" '
                    f'-ErrorAction SilentlyContinue | Select-Object -First 20 | '
                    f'ForEach-Object {{ _info $_.Line }}',
                    '    Set-Content -Path $OP_STATUS -Value 1 -NoNewline',
                    '    exit 1',
                    '}',
                    '',
                ]
            else:
                lines += [
                    f'_fase "cargo check {target} ({name})"',
                    f"if cargo check {release_flag}--target {target} {flags} --message-format=short "
                    f'> "$CARGO_LOGS/{log}.log" 2>&1; then',
                    f'    _ok "cargo check {name} OK"',
                    "else",
                    f'    _fail "cargo check {name} FALHOU - ver log"',
                    f"    grep '^error' \"$CARGO_LOGS/{log}.log\" 2>/dev/null | head -20 | "
                    'while IFS= read -r l; do _info "$l"; done',
                    '    echo 1 > "$OP_STATUS"',
                    "    exit 1",
                    "fi",
                    "",
                ]

        lines.append('Set-Content -Path $OP_STATUS -Value 0 -NoNewline' if is_windows else 'echo 0 > "$OP_STATUS"')
        return "\n".join(lines)

    def run(self, op_type: str) -> int:
        with self.server as server:
            _ts(f"Conectado a {server.label}")
            op = RemoteOp(server, op_type)
            sync = SourceSync(server)

            _ts("A enviar o código …")
            zip_path = sync.make_source_zip(op.local_dir / "source.zip")
            sync.sync_to_server(zip_path)

            op.launch(self._script(op, sync.remote_project_dir))
            rc = op.monitor(timeout=3600, poll=30)

            if rc == RC_DETACHED:
                _ts("Monitor desligado - o check continua a correr no servidor.")
            elif rc != 0:
                _ts("Erros do cargo check:")
                for name, target, _flags in self.variants:
                    log_name = self._check_log_name(name, target)
                    log = op.fetch_cargo_log(log_name)
                    errors = [line for line in log.splitlines() if line.startswith("error")]
                    if errors:
                        _ts(f"  {name} ({target}):")
                        for line in errors:
                            print(f"    {line}", flush=True)
                        _ts(f"  Log completo: {op.local_cargo / f'{log_name}.log'}")
        return rc

class TestsJob:
    def __init__(self, server: Server, env: CheckTestsEnv, registry: TargetRegistry):
        self.server = server
        self.env    = env
        self.registry = registry

    def _to_check_cmd(self, triple: str, windows_native: bool) -> str:
        tdef = self.registry.get(triple)
        if tdef.check_cmd:
            return tdef.check_cmd
        cmd = tdef.native_windows_cmd() if windows_native else tdef.base_cmd
        cmd = re.sub(r'\bbuild\b', 'check', cmd, count=1)
        cmd = re.sub(r'\s*--timings(?:=\S+)?\b', '', cmd)
        return cmd

    def _test_step_bash(self, lines: list, step: int, total: int, name: str, cmd: str, log_name: str) -> None:
        lines += [
            f'_fase "Passo {step}/{total}: {name}"',
            f'_prog "{step}" "{total}"',
            f"if {cmd} 2>&1 | tee $CARGO_LOGS/{log_name}.log | grep -E '^error' | head -5; then",
            "  true",
            "fi",
            "rc=${PIPESTATUS[0]}",
            "if [ $rc -ne 0 ]; then",
            f'  _fail "{name} falhou (exit $rc)"',
            "  exit $rc",
            "fi",
            f'_ok "{name} passou"',
            "",
        ]

    def _test_step_ps(self, lines: list, step: int, total: int, name: str, cmd: str, log_name: str) -> None:
        lines += [
            f'_fase "Passo {step}/{total}: {name}"',
            f'_prog {step} {total}',
            f'{cmd} *> "$CARGO_LOGS/{log_name}.log"',
            '$rc = $LASTEXITCODE',
            'if ($rc -ne 0) {',
            f'    _fail "{name} falhou (exit $rc)"',
            f'    Select-String -Path "$CARGO_LOGS/{log_name}.log" -Pattern "^error" '
            f'-ErrorAction SilentlyContinue | Select-Object -First 5 | '
            f'ForEach-Object {{ _info $_.Line }}',
            '    Set-Content -Path $OP_STATUS -Value $rc -NoNewline',
            '    exit $rc',
            '}',
            f'_ok "{name} passou"',
            '',
        ]

    def _script(self, op: RemoteOp, project_dir: str, profile_triples: list[str]) -> str:
        is_windows = self.server.profile.os == "windows"
        total = len(profile_triples) + 2

        lines: list[str] = []
        if is_windows:
            lines.append(op.preamble())
            lines.append(self.env.tests_env)
            lines.append(f'Set-Location "{project_dir}"')
            lines.append('')
        else:
            lines.append(op.preamble())
            lines.append('trap \'echo $? > "$OP_STATUS"\' EXIT\n')
            lines.append(self.env.tests_env)
            lines.append(f"cd {project_dir}")
            lines.append(f"CARGO_LOGS={op.r_cargo}")
            lines.append('')

        step = 0
        for triple in profile_triples:
            step += 1
            cmd = self._to_check_cmd(triple, windows_native=is_windows)
            step_fn = self._test_step_ps if is_windows else self._test_step_bash
            step_fn(lines, step, total, f"check {triple}", cmd, f"check_{triple}")

        step += 1
        clippy_cmd = (
            f"cargo clippy --release --target {self.env.native_target} "
            f"--workspace --features desktop -- -D warnings"
        )
        (self._test_step_ps if is_windows else self._test_step_bash)(
            lines, step, total, "clippy", clippy_cmd, "clippy")

        step += 1
        tests_cmd = f"cargo test --release --target {self.env.native_target} -p vaultseed-core --lib"
        (self._test_step_ps if is_windows else self._test_step_bash)(
            lines, step, total, "tests", tests_cmd, "tests")

        lines.append('_ok "Todos os testes passaram"')
        if is_windows:
            lines.append('Set-Content -Path $OP_STATUS -Value 0 -NoNewline')
        return "\n".join(lines)

    def run(self, op_type: str, profile_triples: list[str], profile_name: str) -> int:
        op_id = Action.create(op_type).id
        print(f"\n  ID da operação: {op_id}")
        print(f"  Perfil de targets: {profile_name} ({len(profile_triples)} targets)")
        print(f"  Pasta local:    result/{op_id}/\n")

        with self.server as server:
            print(f"Ligado a {server.label}\n")
            sync = SourceSync(server)

            print("A criar source.zip...")
            action = Action.load(op_id)
            zip_path = sync.make_source_zip(action.local_dir / "source.zip")
            print(f"  {zip_path.name}  ({zip_path.stat().st_size / 1048576:.1f} MB)\n")

            op = RemoteOp(server, op_type, action_id=op_id)
            print("A enviar código para o servidor...")
            sync.sync_to_server(zip_path)
            print("  Código enviado.\n")

            op.launch(self._script(op, sync.remote_project_dir, profile_triples))
            op.action.save_meta(status="running", started_at=datetime.now().isoformat(), profile=profile_name)

            print("Processo lançado. A monitorizar (poll a cada 30 segundos)...\n")
            rc = op.monitor(timeout=3600, poll=30)

        if rc == 0:
            op.action.save_meta(status="ok")
            print("\n  Todos os testes passaram.")
        elif rc == 130:
            op.action.save_meta(status="cancelled")
            print("\n  Cancelado.")
        elif rc == RC_DETACHED:
            op.action.save_meta(status="running")
            print("\n  Monitor desligado - os testes continuam a correr no servidor.")
        else:
            op.action.save_meta(status="failed")
            print(f"\n  Falhou (exit {rc}).")
            for log in sorted(op.local_cargo.glob("*.log")):
                errors = [line for line in log.read_text("utf-8", errors="replace").splitlines()
                          if line.startswith("error")][:10]
                if errors:
                    print(f"\n  {log.name}:")
                    for e in errors:
                        print(f"    {e}")

        return rc if rc != 130 else 1

@dataclass
class BuildConfig:
    env_snippet:     str
    targets:         "OrderedDict[str, str]"   # triple -> comando completo
    linux_targets:   list = field(default_factory=list)
    windows_targets: list = field(default_factory=list)
    wasm_targets:    list = field(default_factory=list)
    android_abi:     "OrderedDict[str, str]" = field(default_factory=OrderedDict)
    excluded:        list = field(default_factory=list)
    profile:         str  = "full"
    build_timeout:   int  = 3600
    apk_timeout:     int  = 900
    poll_interval:   int  = 30
    release_mode:    bool = True

@dataclass
class ReleaseEnv:
    env_snippet:   str
    env_prefix:    dict
    build_timeout: int
    apk_timeout:   int
    poll_interval: int

def resolve_release_targets( registry: TargetRegistry, triples: list[str], env: ReleaseEnv, config, *, native_windows: bool, ) -> "OrderedDict[str, str]":
    cmds: "OrderedDict[str, str]" = OrderedDict()
    timings   = config.timings_enabled()
    backtrace = config.backtrace_value()
    lto_value = config.cargo_lto_value()
    slint_opt = config.slint_opt_level()
    codegen_units = config.codegen_units()
    build_jobs = config.build_jobs()
    release_mode = config.build_release()

    for triple in triples:
        tdef = registry.get(triple)
        cmd  = tdef.native_windows_cmd() if native_windows else tdef.base_cmd
        if not release_mode:
            cmd = re.sub(r"\s--release\b", "", cmd)
        if timings and tdef.timings:
            cmd += " --timings"
        if release_mode and slint_opt is not None:
            cmd += f' --config "profile.release.package.vaultseed-slint.opt-level={slint_opt}"'

        if native_windows:
            if backtrace != "0":
                cmd = f"$env:RUST_BACKTRACE='{backtrace}'; {cmd}"
            if build_jobs is not None:
                cmd = f"$env:CARGO_BUILD_JOBS='{build_jobs}'; {cmd}"
            if release_mode:
                cmd = (f"$env:CARGO_PROFILE_RELEASE_LTO='{lto_value}'; "
                       f"$env:CARGO_PROFILE_RELEASE_CODEGEN_UNITS='{codegen_units}'; {cmd}")
        else:
            if backtrace != "0":
                cmd = f"RUST_BACKTRACE={backtrace} {cmd}"
            if build_jobs is not None:
                cmd = f"CARGO_BUILD_JOBS={build_jobs} {cmd}"
            if release_mode:
                cmd = f"CARGO_PROFILE_RELEASE_LTO={lto_value} {cmd}"
            prefix = env.env_prefix.get(triple, "")
            if prefix:
                cmd = f"{prefix} {cmd}"
        cmds[triple] = cmd
    return cmds

def build_config_for( registry: TargetRegistry, profile_triples: list[str], profile_name: str, env: ReleaseEnv, config, *, native_windows: bool, ) -> BuildConfig:
    if native_windows:
        kept = set(registry.windows_native_triples(profile_triples))
        excluded = [t for t in profile_triples if t not in kept]
        triples = [t for t in profile_triples if t in kept]
    else:
        triples, excluded = profile_triples, []

    cmds   = resolve_release_targets(registry, triples, env, config, native_windows=native_windows)
    groups = registry.group_lists(triples)

    return BuildConfig(
        env_snippet     = env.env_snippet,
        targets         = cmds,
        linux_targets   = groups[GROUP_LINUX],
        windows_targets = groups[GROUP_WINDOWS],
        wasm_targets    = groups[GROUP_WASM],
        android_abi     = groups["android_abi"],
        excluded        = excluded,
        profile         = profile_name,
        build_timeout   = env.build_timeout,
        apk_timeout     = env.apk_timeout,
        poll_interval   = env.poll_interval,
        release_mode    = config.build_release(),
    )

class ReleaseBuilder(ABC):
    GROUP_SERVICE_INFO = {
        GROUP_LINUX:   ("linux",   "VaultSeed",        lambda t: f"VaultSeed-{t}"),
        GROUP_WINDOWS: ("windows", "VaultSeed.exe",    lambda t: f"VaultSeed-{t}.exe"),
        GROUP_ANDROID: ("android", "libvaultseed.so",  lambda t: f"libvaultseed-{t}.so"),
        GROUP_WASM:    ("wasm",    "vaultseed.wasm",   lambda t: f"vaultseed-{t}.wasm"),
    }

    @abstractmethod
    def home_dir(self, server: Server) -> str: ... # "..." Impede a instanciação e cada classe que herdar é obrigada a reescrever este método
    """Devolve o caminho remoto do home do utilizador (ex: /home/user ou C:\\Users\\user)."""
    
    @abstractmethod
    def build_script(self, op: RemoteOp, home: str, cfg: BuildConfig) -> str:
        """Devolve o script completo."""

    @abstractmethod
    def paths_for(self, op: RemoteOp, home: str, release: bool = True):
        """Caminhos remotos desta operação - objecto com pelo menos `.logs` e `.stamped_zip` (ver _LinuxPaths/_WindowsPaths)."""

def _pq_ps(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"

def _sq_bash(text: str) -> str:
    return "'" + text.replace("'", "'\\''") + "'"

class _LinuxPaths:
    def __init__(self, home: str, op: RemoteOp, release: bool = True):
        stamp = op.id and stamp_from_id(op.id)
        self.stamp        = stamp
        self.project       = f"{home}/VaultSeed"
        self.release       = f"{home}/VaultSeed_Release"
        self.logs          = f"{self.release}/logs_{stamp}"
        self.art           = f"{self.release}/artefacts_{stamp}"
        self.stamped_zip   = f"{self.release}/VaultSeed_Release_{stamp}.zip"
        self.latest_zip    = f"{self.release}/VaultSeed_Release_latest.zip"
        self._cargo_subdir = "release" if release else "debug"

    def target_dir(self, name: str) -> str:
        return f"{self.project}/.targets/{name}"

    def out_dir(self, name: str) -> str:
        return f"{self.target_dir(name)}/{name}/{self._cargo_subdir}"

class BashReleaseBuilder(ReleaseBuilder):
    _EXTENSION_VERSION_SYNC_PY = (
        "import json, re\n"
        "cargo = open('Cargo.toml').read()\n"
        "version = re.search(r'(?m)^version\\s*=\\s*\"([^\"]+)\"', cargo).group(1)\n"
        "with open('Wasm/extension/manifest.json') as f:\n"
        "    manifest = json.load(f)\n"
        "manifest['version'] = version\n"
        "with open('Wasm/extension/manifest.json', 'w') as f:\n"
        "    json.dump(manifest, f, indent=2)\n"
        "    f.write('\\n')\n"
    )

    _ZIPPER_PY = (
        "import os, sys, zipfile\n"
        "out, *dirs = sys.argv[1:]\n"
        "with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zf:\n"
        "    for d in dirs:\n"
        "        for root, _, files in os.walk(d):\n"
        "            for f in files:\n"
        "                p = os.path.join(root, f)\n"
        "                zf.write(p, os.path.relpath(p, os.path.dirname(d)))\n"
    )

    def home_dir(self, server: Server) -> str:
        if server.is_local:
            return str(Path.home()).replace("\\", "/")
        return f"/home/{server.profile.user or 'user'}"

    def paths_for(self, op: RemoteOp, home: str, release: bool = True) -> _LinuxPaths:
        return _LinuxPaths(home, op, release)

    def _setup_script(self, paths: _LinuxPaths, cfg: BuildConfig) -> str:
        rustup_targets = dict.fromkeys(
            "wasm32-unknown-unknown" if t == "wasm32-extension" else t
            for t in cfg.targets
        )
        return (
            f"{cfg.env_snippet}"
            'source "$HOME/.cargo/env" 2>/dev/null || true\n'
            'rustup default stable 2>/dev/null || true\n'
            f'cd "{paths.project}" || exit 97\n'
            f'mkdir -p "{paths.logs}" "{paths.art}/linux" "{paths.art}/android" '
            f'"{paths.art}/wasm" "{paths.art}/windows" "{paths.art}/timings"\n'
            '\n_fase "preparar ambiente"\n'
            'rustup target add ' + " ".join(rustup_targets) + ' >/dev/null 2>&1 || true\n'
            '_fase "cargo fetch"\n'
            'cargo fetch >/dev/null 2>&1 || true\n'
        )

    def _compile_script(self, paths: _LinuxPaths, cfg: BuildConfig) -> str:
        total = len(cfg.targets)
        names_arr = " ".join(_sq_bash(n) for n in cfg.targets)
        cmds_arr  = " ".join(_sq_bash(c) for c in cfg.targets.values())
        lines = [
            f'_fase "compilar {total} targets"',
            f'TOTAL_TARGETS={total}',
            f'BUILD_TIMEOUT={cfg.build_timeout}',
            f'TARGET_NAMES=({names_arr})',
            f'TARGET_CMDS=({cmds_arr})',
            '',
            '_run_target() {',
            '    local name="$1" cmd="$2"',
            '    local log="$CARGO_LOGS/$name.log"',
            '    export CARGO_TARGET_DIR="' + paths.project + '/.targets/$name"',
            '    { echo "=== $name ==="; echo "Comando: $cmd"; echo; } > "$log"',
            '    local _t0=$(date +%s)',
            '    if timeout "$BUILD_TIMEOUT" bash -c "$cmd" >> "$log" 2>&1; then',
            '        echo OK > "' + paths.logs + '/${name}_status.txt"',
            '        _ok "$name"',
            '    else',
            '        echo FAILED > "' + paths.logs + '/${name}_status.txt"',
            '        tail -60 "$log" > "' + paths.logs + '/${name}_error.log"',
            '        _fail "$name"',
            '    fi',
            '    echo $(( $(date +%s) - _t0 )) > "' + paths.logs + '/${name}_time.txt"',
            '}',
            '',
            'STARTED=0',
            'for i in "${!TARGET_NAMES[@]}"; do',
            '    name="${TARGET_NAMES[$i]}"',
            '    cmd="${TARGET_CMDS[$i]}"',
            '    STARTED=$((STARTED+1))',
            f'    _fase "$name iniciado ($STARTED/{total})"',
            '    _run_target "$name" "$cmd"',
            f'    _prog "$STARTED" "{total}"',
            'done',
            '_fase "builds concluídos"',
        ]
        return "\n".join(lines) + "\n"

    def _collect_script(self, paths: _LinuxPaths, cfg: BuildConfig) -> str:
        lines = [
            '_fase "recolher artefactos"',
            'find "' + paths.project + '/.targets" -maxdepth 4 '
            r'\( -name "VaultSeed" -o -name "VaultSeed.exe" -o -name "libvaultseed.so" -o -name "*.wasm" \) '
            '2>/dev/null | sort',
        ]
        group_triples = {
            GROUP_LINUX: cfg.linux_targets, GROUP_WINDOWS: cfg.windows_targets,
            GROUP_ANDROID: list(cfg.android_abi.keys()), GROUP_WASM: cfg.wasm_targets,
        }
        for group, triples in group_triples.items():
            subdir, binary_name, artifact_name = self.GROUP_SERVICE_INFO[group]
            for t in triples:
                src = f"{paths.out_dir(t)}/{binary_name}"
                dst = f"{paths.art}/{subdir}/{artifact_name(t)}"
                lines.append(
                    'src="' + src + '"; '
                    '[ -f "$src" ] && cp "$src" "' + dst + '" '
                    '&& _info "' + group + ': ' + t + '" || _info "[miss] ' + group + ': ' + t + '"'
                )
        return "\n".join(lines) + "\n"

    def _timings_script(self, paths: _LinuxPaths, cfg: BuildConfig) -> str:
        lines = ['_fase "recolher relatórios de timings"']
        for name in cfg.targets:
            cache = f"{paths.target_dir(name)}/cargo-timings"
            dst   = f"{paths.art}/timings/{name}.html"
            lines.append(
                f'f=$(find "{cache}" -maxdepth 1 -name "cargo-timing-*.html" 2>/dev/null | sort | tail -1); '
                f'[ -n "$f" ] && cp "$f" "{dst}" || true'
            )
        return "\n".join(lines) + "\n"

    def _apk_script(self, paths: _LinuxPaths, cfg: BuildConfig) -> str:
        log_file = f"{paths.logs}/android_apk_build.log"
        jni = f"{paths.project}/android/app/src/main/jniLibs"
        copy_so = "\n".join(
            'so="' + paths.out_dir(t) + '/libvaultseed.so"; '
            '[ -f "$so" ] && mkdir -p "' + jni + '/' + abi + '" && cp "$so" "' + jni + '/' + abi + '/libvaultseed.so"'
            for t, abi in cfg.android_abi.items()
        )
        lines = [
            '_fase "construir apk"', copy_so, '(',
            '    cd "' + paths.project + '/android" || exit 1',
            '    sed -i "s/\\r$//" gradlew 2>/dev/null || true',
            '    chmod +x gradlew 2>/dev/null || true',
            '    SDKM="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"',
            '    [ -f "$SDKM" ] && yes | "$SDKM" --licenses >/dev/null 2>&1 || true',
            '    if timeout ' + str(cfg.apk_timeout) + ' ./gradlew assembleRelease > "' + log_file + '" 2>&1; then',
            '        apk="$(find . -name *.apk | head -n 1)"',
            '        if [ -n "$apk" ]; then',
            '            cp "$apk" "' + paths.art + '/android/VaultSeed.apk" && exit 0',
            '        fi', '    fi', '    exit 1', ')',
            'if [ $? -eq 0 ]; then',
            '    echo OK > "' + paths.logs + '/android-apk_status.txt"', '    _ok "android-apk"',
            'else',
            '    echo FAILED > "' + paths.logs + '/android-apk_status.txt"',
            '    tail -60 "' + log_file + '" > "' + paths.logs + '/android-apk_error.log" 2>/dev/null || true',
            '    _fail "android-apk"', 'fi',
        ]
        return "\n".join(lines) + "\n"

    def _extension_script(self, paths: _LinuxPaths, cfg: BuildConfig) -> str:
        out_zip, status = f"{paths.art}/wasm/VaultSeed-extension.zip", f"{paths.logs}/extension-zip_status.txt"
        b64 = __import__("base64").b64encode
        lines = [
            '_fase "empacotar extensão"', '(', '    set -e', f'    cd "{paths.project}"',
            '    echo ' + b64(self._EXTENSION_VERSION_SYNC_PY.encode()).decode() + ' | base64 -d > "$OP_DIR/_ext_version.py"',
            '    python3 "$OP_DIR/_ext_version.py"',
            '    echo ' + b64(self._ZIPPER_PY.encode()).decode() + ' | base64 -d > "$OP_DIR/_ext_zip.py"',
            f'    python3 "$OP_DIR/_ext_zip.py" "{out_zip}" Wasm/extension',
            '    rm -f "$OP_DIR/_ext_version.py" "$OP_DIR/_ext_zip.py"', ')',
            'if [ $? -eq 0 ]; then', f'    echo OK > "{status}"', '    _ok "extension-zip"',
            'else', f'    echo FAILED > "{status}"', '    _fail "extension-zip"', 'fi',
        ]
        return "\n".join(lines) + "\n"

    def _site_script(self, paths: _LinuxPaths, cfg: BuildConfig) -> str:
        out_zip, status = f"{paths.art}/wasm/VaultSeed-site.zip", f"{paths.logs}/site-zip_status.txt"
        b64 = __import__("base64").b64encode
        lines = [
            '_fase "empacotar site"', '(', '    set -e', f'    cd "{paths.project}"',
            '    mkdir -p Wasm/site/pkg', '    cp -r Wasm/extension/pkg/. Wasm/site/pkg/',
            '    cp assets/icons/Icon.png Wasm/site/icon.png',
            '    echo ' + b64(self._ZIPPER_PY.encode()).decode() + ' | base64 -d > "$OP_DIR/_site_zip.py"',
            f'    python3 "$OP_DIR/_site_zip.py" "{out_zip}" Wasm/site',
            '    rm -f "$OP_DIR/_site_zip.py"', ')',
            'if [ $? -eq 0 ]; then', f'    echo OK > "{status}"', '    _ok "site-zip"',
            'else', f'    echo FAILED > "{status}"', '    _fail "site-zip"', 'fi',
        ]
        return "\n".join(lines) + "\n"

    def _summary_script(self, paths: _LinuxPaths, cfg: BuildConfig) -> str:
        build_apk = bool(cfg.android_abi)
        build_extension = "wasm32-extension" in cfg.targets
        build_site = build_extension

        lines = [
            '_fase "escrever summary"', '{',
            '    echo "=== VaultSeed Release ==="',
            '    echo "Timestamp: ' + paths.stamp + '"',
            '    echo "Perfil: ' + cfg.profile + ' (' + str(len(cfg.targets)) + ' targets)"',
            '    echo ""', '    echo "=== Estado dos builds ==="',
        ]
        for name in cfg.targets:
            lines.append(
                '    printf "  %-35s %s\\n" "' + name + '" '
                '"$(cat \'' + paths.logs + '/' + name + '_status.txt\' 2>/dev/null || echo UNKNOWN)"'
            )
        for flag, label, fname in (
            (build_apk, "android-apk", "android-apk"),
            (build_extension, "extension-zip", "extension-zip"),
            (build_site, "site-zip", "site-zip"),
        ):
            if flag:
                lines.append(
                    '    printf "  %-35s %s\\n" "' + label + '" '
                    '"$(cat \'' + paths.logs + '/' + fname + '_status.txt\' 2>/dev/null || echo UNKNOWN)"'
                )

        names_list = " ".join(_sq_bash(n) for n in cfg.targets)
        lines += [
            '    echo ""', '    echo "=== Tempos de compilação ==="',
            f'    for _n in {names_list}; do',
            '        _t=$(cat "' + paths.logs + '/${_n}_time.txt" 2>/dev/null || echo 0)',
            '        printf "%06d %s\\n" "$_t" "$_n"',
            '    done | sort -rn | while read -r _secs _n; do',
            '        printf "  %-35s %dm%02ds\\n" "$_n" $((_secs/60)) $((_secs%60))',
            '    done',
            '    echo ""', '    echo "=== Artefactos ==="',
            '    find "' + paths.art + '" -type f -printf "  %p (%s bytes)\\n" 2>/dev/null',
            '    echo ""', '    echo "=== Erros ==="',
            '} >> "$SUMMARY"', '', 'FOUND_ERRORS=0',
        ]
        names_for_errors = (
            list(cfg.targets)
            + (["android-apk"] if build_apk else [])
            + (["extension-zip"] if build_extension else [])
            + (["site-zip"] if build_site else [])
        )
        for name in names_for_errors:
            status_file = f"{paths.logs}/{name}_status.txt"
            error_file  = f"{paths.logs}/{name}_error.log"
            lines += [
                'if [ "$(cat \'' + status_file + '\' 2>/dev/null)" != "OK" ]; then',
                '    FOUND_ERRORS=1', '    {', '        echo ""', '        echo "--- ' + name + ' ---"',
                '        if [ -f "' + error_file + '" ]; then',
                '            sed "s/^/    /" "' + error_file + '"',
                '        else',
                '            echo "    (sem log de erro; ver ' + name + '_build.log)"',
                '        fi', '    } >> "$SUMMARY"', 'fi',
            ]
        lines.append('[ "$FOUND_ERRORS" -eq 0 ] && echo "  (nenhum)" >> "$SUMMARY"')
        lines.append('')
        lines.append('OK_COUNT=0')
        for name in cfg.targets:
            status_file = f"{paths.logs}/{name}_status.txt"
            lines.append('[ "$(cat \'' + status_file + '\' 2>/dev/null)" = "OK" ] && OK_COUNT=$((OK_COUNT+1))')

        def _status_expr(flag, fname):
            return ('"$(cat \'' + paths.logs + '/' + fname + '_status.txt\' 2>/dev/null || echo UNKNOWN)"'
                    if flag else '"SKIPPED"')

        lines += [
            f'TOTAL_TARGETS={len(cfg.targets)}',
            'APK_STATUS=' + _status_expr(build_apk, "android-apk"),
            'EXTENSION_STATUS=' + _status_expr(build_extension, "extension-zip"),
            'SITE_STATUS=' + _status_expr(build_site, "site-zip"),
            'if [ "$OK_COUNT" -eq "$TOTAL_TARGETS" ]; then RC=0; else RC=1; fi',
            '{', '    echo "targets_ok=$OK_COUNT"', '    echo "targets_total=$TOTAL_TARGETS"',
            '    echo "apk=$APK_STATUS"', '    echo "extension=$EXTENSION_STATUS"',
            '    echo "site=$SITE_STATUS"', '} > "$OP_DIR/result_meta.txt"',
        ]
        return "\n".join(lines) + "\n"

    def _compress_script(self, paths: _LinuxPaths) -> str:
        b64 = __import__("base64").b64encode
        lines = [
            '_fase "comprimir"',
            'echo ' + b64(self._ZIPPER_PY.encode()).decode() + ' | base64 -d > "$OP_DIR/_zip.py"',
            'cd "' + paths.release + '" && python3 "$OP_DIR/_zip.py" "' + paths.stamped_zip
                + '" "logs_' + paths.stamp + '" "artefacts_' + paths.stamp + '"',
            'cp -f "' + paths.stamped_zip + '" "' + paths.latest_zip + '"',
            'rm -f "$OP_DIR/_zip.py"',
            'SIZE=$(du -h "' + paths.stamped_zip + '" 2>/dev/null | cut -f1)',
            '_info "zip criado: ' + paths.stamped_zip + ' ($SIZE)"',
        ]
        return "\n".join(lines) + "\n"

    def build_script(self, op: RemoteOp, home: str, cfg: BuildConfig) -> str:
        paths = self.paths_for(op, home, cfg.release_mode)
        return (
            "#!/usr/bin/env bash\nset -u\n"
            + op.preamble()
            + 'trap \'rc=$?; [ -z "${RC:-}" ] && echo "$rc" > "$OP_STATUS"\' EXIT\n'
            + self._setup_script(paths, cfg)
            + self._compile_script(paths, cfg)
            + self._collect_script(paths, cfg)
            + self._timings_script(paths, cfg)
            + (self._apk_script(paths, cfg) if cfg.android_abi else "")
            + (self._extension_script(paths, cfg) if "wasm32-extension" in cfg.targets else "")
            + (self._site_script(paths, cfg) if "wasm32-extension" in cfg.targets else "")
            + self._summary_script(paths, cfg)
            + self._compress_script(paths)
            + 'echo "$RC" > "$OP_STATUS"\n'
        )

class _WindowsPaths:
    def __init__(self, home: str, op: RemoteOp, release: bool = True):
        from .action import stamp_from_id
        stamp = stamp_from_id(op.id)
        self.stamp        = stamp
        self.project      = f"{home}/source"
        self.release      = f"{home}/release"
        self.logs         = f"{self.release}/logs_{stamp}"
        self.art          = f"{self.release}/artefacts_{stamp}"
        self.stamped_zip  = f"{self.release}/VaultSeed_Release_{stamp}.zip"
        self.latest_zip   = f"{self.release}/VaultSeed_Release_latest.zip"
        self._cargo_subdir = "release" if release else "debug"

    def target_dir(self, name: str) -> str:
        return "$env:APPDATA/VaultSeed/cache/.cargo-target"

    def out_dir(self, name: str) -> str:
        return f"{self.target_dir(name)}/{name}/{self._cargo_subdir}"

class PowerShellReleaseBuilder(ReleaseBuilder):
    def home_dir(self, server: Server) -> str:
        if server.is_local:
            appdata = os.environ.get("APPDATA")
            if appdata:
                return f"{appdata.replace(chr(92), '/')}/VaultSeed"
            return f"{str(Path.home()).replace(chr(92), '/')}/AppData/Roaming/VaultSeed"
        return f"C:/Users/{server.profile.user or 'user'}/AppData/Roaming/VaultSeed"

    def paths_for(self, op: RemoteOp, home: str, release: bool = True) -> _WindowsPaths:
        return _WindowsPaths(home, op, release)

    @staticmethod
    def _pq(text: str) -> str:
        return _pq_ps(text)

    def _setup_script(self, paths: _WindowsPaths, cfg: BuildConfig) -> str:
        rustup_targets = dict.fromkeys(
            "wasm32-unknown-unknown" if t == "wasm32-extension" else t
            for t in cfg.targets
        )
        lines = [
            cfg.env_snippet,
            f'Set-Location "{paths.project}"',
            f'New-Item -ItemType Directory -Force -Path '
            f'"{paths.logs}", "{paths.art}/windows", "{paths.art}/android", '
            f'"{paths.art}/wasm", "{paths.art}/timings" | Out-Null',
            '', '_fase "preparar ambiente"',
        ]
        for t in rustup_targets:
            lines.append(f'rustup target add {t} 2>$null | Out-Null')
        lines += ['_fase "cargo fetch"', 'cargo fetch 2>$null | Out-Null']
        return "\n".join(lines) + "\n"

    def _compile_script(self, paths: _WindowsPaths, cfg: BuildConfig) -> str:
        total = len(cfg.targets)
        lines = [
            f'_fase "compilar {total} targets"',
            f'$TOTAL_TARGETS = {total}',
            f'$BUILD_TIMEOUT = {cfg.build_timeout}',
            '$PROJECT = ' + self._pq(paths.project), '',
            '$TARGET_NAMES = @(' + ", ".join(self._pq(n) for n in cfg.targets) + ')',
            '$TARGET_CMDS  = @(' + ", ".join(self._pq(c) for c in cfg.targets.values()) + ')',
            '', 'Set-Location $PROJECT',
            '$env:CARGO_TARGET_DIR = "$env:APPDATA\\VaultSeed\\cache\\.cargo-target"',
            '', '$started = 0',
            'for ($i = 0; $i -lt $TARGET_NAMES.Count; $i++) {',
            '    $name = $TARGET_NAMES[$i]', '    $cmd  = $TARGET_CMDS[$i]', '    $started++',
            f'    _fase "$name iniciado ($started/{total})"',
            '    $log = "$CARGO_LOGS/$name.log"',
            '    $statusFile = "' + paths.logs + '/${name}_status.txt"',
            '    $timeFile   = "' + paths.logs + '/${name}_time.txt"',
            '    Set-Content -Path $log -Value "=== $name ===" -Encoding utf8',
            '    Add-Content -Path $log -Value "Comando: $cmd" -Encoding utf8',
            '    Add-Content -Path $log -Value "" -Encoding utf8',
            '    $t0 = Get-Date',
            '    $fullCmd = $cmd + \' *>> "\' + $log + \'"\'',
            '    Invoke-Expression $fullCmd',
            '    $secs = [int]((Get-Date) - $t0).TotalSeconds',
            '    Set-Content -Path $timeFile -Value $secs -NoNewline',
            '    if ($LASTEXITCODE -eq 0) {',
            '        Set-Content -Path $statusFile -Value "OK" -NoNewline', '        _ok $name',
            '    } else {',
            '        Set-Content -Path $statusFile -Value "FAILED" -NoNewline',
            '        Get-Content $log -Tail 60 -Encoding utf8 | '
            'Set-Content "' + paths.logs + '/${name}_error.log" -Encoding utf8',
            '        _fail $name', '    }',
            f'    _prog $started {total}', '}', '_fase "builds concluídos"',
        ]
        return "\n".join(lines) + "\n"

    def _collect_script(self, paths: _WindowsPaths, cfg: BuildConfig) -> str:
        lines = ['_fase "recolher artefactos"']
        group_triples = {
            GROUP_WINDOWS: cfg.windows_targets,
            GROUP_ANDROID: list(cfg.android_abi.keys()),
            GROUP_WASM:    cfg.wasm_targets,
        }
        for group, triples in group_triples.items():
            subdir, binary_name, artifact_name = self.GROUP_SERVICE_INFO[group]
            for t in triples:
                src = f"{paths.out_dir(t)}/{binary_name}"
                dst = f"{paths.art}/{subdir}/{artifact_name(t)}"
                lines.append(
                    f'if (Test-Path "{src}") {{ '
                    f'Copy-Item "{src}" {self._pq(dst)} -Force; '
                    f'_info "{group}: {t}" '
                    f'}} else {{ _info "[miss] {group}: {t}" }}'
                )
        return "\n".join(lines) + "\n"

    def _timings_script(self, paths: _WindowsPaths, cfg: BuildConfig) -> str:
        lines = ['_fase "recolher relatórios de timings"']
        for name in cfg.targets:
            cache = "$env:CARGO_TARGET_DIR/cargo-timings"
            dst   = f"{paths.art}/timings/{name}.html"
            lines.append(
                f'$f = Get-ChildItem -Path "{cache}" -Filter "cargo-timing-*.html" '
                f'-ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1; '
                f'if ($f) {{ Copy-Item $f.FullName {self._pq(dst)} -Force }}'
            )
        return "\n".join(lines) + "\n"

    def _apk_script(self, paths: _WindowsPaths, cfg: BuildConfig) -> str:
        log_file = f"{paths.logs}/android_apk_build.log"
        jni = f"{paths.project}/android/app/src/main/jniLibs"
        status = f"{paths.logs}/android-apk_status.txt"
        lines = ['_fase "construir apk"']
        for t, abi in cfg.android_abi.items():
            so = f"{paths.out_dir(t)}/libvaultseed.so"
            dst_dir = f"{jni}/{abi}"
            lines.append(
                f'if (Test-Path "{so}") {{ '
                f'New-Item -ItemType Directory -Force -Path {self._pq(dst_dir)} | Out-Null; '
                f'Copy-Item "{so}" {self._pq(dst_dir + "/libvaultseed.so")} -Force }}'
            )
        wrapper_jar = f"{paths.project}/android/gradle/wrapper/gradle-wrapper.jar"
        lines += [
            f'if (-not (Test-Path {self._pq(wrapper_jar)})) {{',
            f'    $gradleHome = Get-ChildItem "$HOME" -Filter "gradle-*" -Directory '
            f'-ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1',
            f'    if ($gradleHome) {{',
            f'        _info "A gerar gradle-wrapper.jar via $($gradleHome.Name)…"',
            f'        Push-Location {self._pq(paths.project + "/android")}',
            f'        & "$($gradleHome.FullName)/bin/gradle.bat" wrapper '
            f'--gradle-version 8.10.2 --distribution-type bin 2>&1 | '
            f'Out-File -FilePath {self._pq(paths.logs + "/android-apk_build.log")} -Append -Encoding utf8',
            f'        Pop-Location', f'    }}',
            f'    if (-not (Test-Path {self._pq(wrapper_jar)})) {{',
            f'        Set-Content -Path {self._pq(status)} -Value "SKIPPED" -NoNewline',
            f'        Set-Content -Path "{paths.logs}/android-apk_error.log" '
            f'-Value "gradle-wrapper.jar nao encontrado e nao foi possivel gerar '
            f'(Gradle nao instalado ou falhou o bootstrap)"',
            f'        _warn "android-apk (sem gradle-wrapper.jar, ignorado)"',
            f'        $wrapperMissing = $true', f'    }}',
            '} else { $wrapperMissing = $false }',
            'if (-not $wrapperMissing) {', 'try {',
            f'    Set-Location "{paths.project}/android"',
            '    $sdkm = "$env:ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager.bat"',
            '    if (Test-Path $sdkm) { "y" * 20 | & $sdkm --licenses *> $null }',
            f'    $job = Start-Job -ScriptBlock {{ param($d) Set-Location $d; '
            f'& java -cp "$d/gradle/wrapper/gradle-wrapper.jar" '
            f'org.gradle.wrapper.GradleWrapperMain assembleRelease 2>&1 | '
            f'Out-File -FilePath {self._pq(log_file)} -Encoding utf8 }} -ArgumentList "{paths.project}/android"',
            f'    if (Wait-Job $job -Timeout {cfg.apk_timeout}) {{',
            '        Receive-Job $job *> $null',
            '        $apk = Get-ChildItem -Recurse -Filter *.apk | Select-Object -First 1',
            '        if ($apk) {',
            f'            Copy-Item $apk.FullName "{paths.art}/android/VaultSeed.apk" -Force',
            f'            Set-Content -Path {self._pq(status)} -Value "OK" -NoNewline',
            '            _ok "android-apk"', '        } else { throw "sem apk" }',
            '    } else {', '        Stop-Job $job', '        throw "timeout"', '    }',
            '    Remove-Job $job -Force -ErrorAction SilentlyContinue',
            '} catch {',
            f'    Set-Content -Path {self._pq(status)} -Value "FAILED" -NoNewline',
            f'    if (Test-Path "{log_file}") {{ Get-Content "{log_file}" -Tail 60 -Encoding utf8 | '
            f'Set-Content "{paths.logs}/android-apk_error.log" -Encoding utf8 }}',
            '    _fail "android-apk"', '}', '}',
            f'Set-Location "{paths.project}"',
        ]
        return "\n".join(lines) + "\n"

    _EXTENSION_VERSION_SYNC_PS = """\
$cargo = Get-Content "Cargo.toml" -Raw
if ($cargo -match '(?m)^version\\s*=\\s*"([^"]+)"') {{
    $version = $Matches[1]
    $manifest = Get-Content "Wasm/extension/manifest.json" -Raw | ConvertFrom-Json
    $manifest.version = $version
    $manifest | ConvertTo-Json -Depth 10 | Set-Content "Wasm/extension/manifest.json"
}}
"""

    def _extension_script(self, paths: _WindowsPaths, cfg: BuildConfig) -> str:
        out_zip  = f"{paths.art}/wasm/VaultSeed-extension.zip"
        status   = f"{paths.logs}/extension-zip_status.txt"
        lines = ['_fase "empacotar extensão"', 'try {', f'    Set-Location "{paths.project}"']
        for ln in self._EXTENSION_VERSION_SYNC_PS.splitlines():
            lines.append("    " + ln)
        lines += [
            f'    if (Test-Path {self._pq(out_zip)}) {{ Remove-Item {self._pq(out_zip)} -Force }}',
            f'    Compress-Archive -Path "Wasm/extension/*" -DestinationPath {self._pq(out_zip)} -Force',
            f'    Set-Content -Path {self._pq(status)} -Value "OK" -NoNewline',
            '    _ok "extension-zip"', '} catch {',
            f'    Set-Content -Path {self._pq(status)} -Value "FAILED" -NoNewline',
            '    _fail "extension-zip"', '}',
        ]
        return "\n".join(lines) + "\n"

    def _site_script(self, paths: _WindowsPaths, cfg: BuildConfig) -> str:
        out_zip = f"{paths.art}/wasm/VaultSeed-site.zip"
        status  = f"{paths.logs}/site-zip_status.txt"
        lines = [
            '_fase "empacotar site"', 'try {', f'    Set-Location "{paths.project}"',
            '    New-Item -ItemType Directory -Force -Path "Wasm/site/pkg" | Out-Null',
            '    Copy-Item "Wasm/extension/pkg/*" "Wasm/site/pkg/" -Recurse -Force',
            '    Copy-Item "assets/icons/Icon.png" "Wasm/site/icon.png" -Force',
            f'    if (Test-Path {self._pq(out_zip)}) {{ Remove-Item {self._pq(out_zip)} -Force }}',
            f'    Compress-Archive -Path "Wasm/site/*" -DestinationPath {self._pq(out_zip)} -Force',
            f'    Set-Content -Path {self._pq(status)} -Value "OK" -NoNewline',
            '    _ok "site-zip"', '} catch {',
            f'    Set-Content -Path {self._pq(status)} -Value "FAILED" -NoNewline',
            '    _fail "site-zip"', '}',
        ]
        return "\n".join(lines) + "\n"

    def _summary_script(self, paths: _WindowsPaths, cfg: BuildConfig) -> str:
        build_apk = bool(cfg.android_abi)
        build_extension = "wasm32-extension" in cfg.targets
        build_site = build_extension

        lines = [
            '_fase "escrever summary"', '$summaryLines = @()',
            '$summaryLines += "=== VaultSeed Release ==="',
            f'$summaryLines += "Timestamp: {paths.stamp}"',
            f'$summaryLines += "Perfil: {cfg.profile} ({len(cfg.targets)} targets)"', '$summaryLines += ""',
        ]
        if cfg.excluded:
            lines += ['$summaryLines += "=== Targets excluídos (sem suporte neste host) ==="']
            for t in cfg.excluded:
                lines.append(
                    f'$summaryLines += "  {t}: SKIPPED - cross-compilação Linux a partir de '
                    f'Windows precisa de WSL/cross-toolchain (não configurado). '
                    f'Correr Build/linux/release.py num host Linux para este target."'
                )
            lines += ['$summaryLines += ""']
        if build_extension or build_site:
            lines += [
                '$summaryLines += "=== Nota sobre wasm ==="',
                '$summaryLines += "  artefacts/wasm/ tem os builds genéricos '
                '(wasm32-unknown-unknown, wasm32-wasip1) e os zips prontos a usar da '
                'extensão (VaultSeed-extension.zip) e do site (VaultSeed-site.zip)."',
                '$summaryLines += ""',
            ]
        lines += ['$summaryLines += "=== Estado dos builds ==="']
        for name in cfg.targets:
            status_file = f"{paths.logs}/{name}_status.txt"
            lines.append(
                f'$st = if (Test-Path {self._pq(status_file)}) {{ Get-Content {self._pq(status_file)} -Raw }} else {{ "UNKNOWN" }}; '
                f'$summaryLines += ("  {{0,-35}} {{1}}" -f "{name}", $st)'
            )
        for flag, label, fname in (
            (build_apk, "android-apk", "android-apk"),
            (build_extension, "extension-zip", "extension-zip"),
            (build_site, "site-zip", "site-zip"),
        ):
            if flag:
                status_file = f"{paths.logs}/{fname}_status.txt"
                lines.append(
                    f'$st = if (Test-Path {self._pq(status_file)}) {{ Get-Content {self._pq(status_file)} -Raw }} else {{ "UNKNOWN" }}; '
                    f'$summaryLines += ("  {{0,-35}} {{1}}" -f "{label}", $st)'
                )

        lines += ['$summaryLines += ""', '$summaryLines += "=== Tempos de compilação ==="', '$timings = @()']
        for name in cfg.targets:
            time_file = f"{paths.logs}/{name}_time.txt"
            lines.append(
                f'$secs = if (Test-Path {self._pq(time_file)}) {{ [int](Get-Content {self._pq(time_file)} -Raw) }} else {{ 0 }}; '
                f'$timings += [PSCustomObject]@{{ Name = "{name}"; Secs = $secs }}'
            )
        lines += [
            'foreach ($t in ($timings | Sort-Object Secs -Descending)) {',
            '    $summaryLines += ("  {0,-35} {1}m{2:D2}s" -f $t.Name, [int]($t.Secs/60), ($t.Secs%60))',
            '}', '$summaryLines += ""', '$summaryLines += "=== Artefactos ==="',
            f'Get-ChildItem -Recurse -File -Path "{paths.art}" -ErrorAction SilentlyContinue | '
            'ForEach-Object { $summaryLines += ("  {0} ({1} bytes)" -f $_.FullName, $_.Length) }',
            '$summaryLines += ""', '$summaryLines += "=== Erros ==="',
        ]
        names_for_errors = (
            list(cfg.targets)
            + (["android-apk"] if build_apk else [])
            + (["extension-zip"] if build_extension else [])
            + (["site-zip"] if build_site else [])
        )
        lines.append('$foundErrors = $false')
        for name in names_for_errors:
            status_file = f"{paths.logs}/{name}_status.txt"
            error_file  = f"{paths.logs}/{name}_error.log"
            lines += [
                f'$st = if (Test-Path {self._pq(status_file)}) {{ Get-Content {self._pq(status_file)} -Raw }} else {{ "" }}; '
                f'if ($st -ne "OK") {{',
                '    $foundErrors = $true', f'    $summaryLines += ""', f'    $summaryLines += "--- {name} ---"',
                f'    if (Test-Path {self._pq(error_file)}) {{',
                f'        Get-Content {self._pq(error_file)} | ForEach-Object {{ $summaryLines += "    $_" }}',
                '    } else {', f'        $summaryLines += "    (sem log de erro; ver {name}.log)"', '    }', '}',
            ]
        lines += [
            'if (-not $foundErrors) { $summaryLines += "  (nenhum)" }',
            '$summaryLines | Add-Content -Path $SUMMARY -Encoding UTF8', '', '$okCount = 0',
        ]
        for name in cfg.targets:
            status_file = f"{paths.logs}/{name}_status.txt"
            lines.append(
                f'if ((Test-Path {self._pq(status_file)}) -and (Get-Content {self._pq(status_file)} -Raw) -eq "OK") {{ $okCount++ }}'
            )

        def _status_expr(flag, fname):
            return (f'if (Test-Path {self._pq(paths.logs + "/" + fname + "_status.txt")}) '
                    f'{{ Get-Content {self._pq(paths.logs + "/" + fname + "_status.txt")} -Raw }} else {{ "UNKNOWN" }}'
                    if flag else '"SKIPPED"')

        lines += [
            f'$totalTargets = {len(cfg.targets)}',
            f'$apkStatus = {_status_expr(build_apk, "android-apk")}',
            f'$extStatus = {_status_expr(build_extension, "extension-zip")}',
            f'$siteStatus = {_status_expr(build_site, "site-zip")}',
            'if ($okCount -eq $totalTargets) { $RC = 0 } else { $RC = 1 }',
            '@(', '    "targets_ok=$okCount"', '    "targets_total=$totalTargets"',
            '    "apk=$apkStatus"', '    "extension=$extStatus"', '    "site=$siteStatus"',
            ') | Set-Content "$OP_DIR/result_meta.txt"',
        ]
        return "\n".join(lines) + "\n"

    def _compress_script(self, paths: _WindowsPaths) -> str:
        lines = [
            '_fase "comprimir"',
            f'if (Test-Path {self._pq(paths.stamped_zip)}) {{ Remove-Item {self._pq(paths.stamped_zip)} -Force }}',
            f'Compress-Archive -Path {self._pq(paths.logs)}, {self._pq(paths.art)} '
            f'-DestinationPath {self._pq(paths.stamped_zip)} -Force',
            f'Copy-Item {self._pq(paths.stamped_zip)} {self._pq(paths.latest_zip)} -Force',
            f'$size = "{{0:N1}} MB" -f ((Get-Item {self._pq(paths.stamped_zip)}).Length / 1MB)',
            f'_info "zip criado: {paths.stamped_zip} ($size)"',
        ]
        return "\n".join(lines) + "\n"

    def build_script(self, op: RemoteOp, home: str, cfg: BuildConfig) -> str:
        paths = self.paths_for(op, home, cfg.release_mode)
        return (
            op.preamble()
            + self._setup_script(paths, cfg)
            + self._compile_script(paths, cfg)
            + self._collect_script(paths, cfg)
            + self._timings_script(paths, cfg)
            + (self._apk_script(paths, cfg) if cfg.android_abi else "")
            + (self._extension_script(paths, cfg) if "wasm32-extension" in cfg.targets else "")
            + (self._site_script(paths, cfg) if "wasm32-extension" in cfg.targets else "")
            + self._summary_script(paths, cfg)
            + self._compress_script(paths)
            + 'Set-Content -Path $OP_STATUS -Value $RC -NoNewline\n'
        )

class ReleaseJob:
    def __init__(self, server: Server, builder: ReleaseBuilder):
        self.server  = server
        self.builder = builder

    def run(self, op_type: str, cfg: BuildConfig) -> Optional[str]:
        with self.server as server:
            home  = self.builder.home_dir(server)
            op    = RemoteOp(server, op_type)
            paths = self.builder.paths_for(op, home, cfg.release_mode)

            _ts(f"=== VaultSeed Release (perfil: {cfg.profile}) ===")
            _ts(f"    ID da operação: {op.id}")
            op.action.save_meta(type=op_type, status="running", server=server.label, profile=cfg.profile)

            sync = SourceSync(server)
            zip_path = sync.make_source_zip(op.local_dir / "source.zip")
            sync.sync_to_server(zip_path)

            script = self.builder.build_script(op, home, cfg)
            op.launch(script)

            timeout = len(cfg.targets) * cfg.build_timeout + cfg.apk_timeout + 1800
            rc = op.monitor(timeout=timeout, poll=cfg.poll_interval)

            if rc == 130:
                _ts("Cancelado - processo remoto terminado.")
                return None
            if rc == RC_DETACHED:
                _ts("Monitor desligado (Ctrl+C) - a pipeline continua a correr no servidor.")
                return None
            if rc == 2:
                _ts("Timeout local - a pipeline pode continuar a correr no servidor.")
                return None
            if rc != 0:
                _ts(f"FALHOU (exit {rc}) - release não foi gerada nesta execução. "
                    f"Ver logs em {paths.logs}.")
                return None

            meta = op.read_result_meta()
            n_ok = n_tot = 0
            apk_status = extension_status = "UNKNOWN"
            if meta:
                n_ok = int(meta.get("targets_ok", 0))
                n_tot = int(meta.get("targets_total", len(cfg.targets)))
                apk_status = meta.get("apk", "UNKNOWN")
                extension_status = meta.get("extension", "UNKNOWN")
                op.action.save_meta(
                    status="ok" if n_ok == n_tot else "partial",
                    targets_ok=n_ok, targets_total=n_tot, apk=apk_status, extension=extension_status,
                )

            try:
                summary_txt = op.local_summary.read_text("utf-8", errors="replace")
            except OSError:
                summary_txt = ""

            apk_failed = bool(cfg.android_abi) and apk_status != "OK"
            extension_failed = ("wasm32-extension" in cfg.targets) and extension_status != "OK"
            if meta and (n_ok < n_tot or apk_failed or extension_failed):
                _ts(f"AVISO: {n_ok}/{n_tot} targets compilaram com sucesso"
                    + (f"; APK: {apk_status}" if cfg.android_abi else "")
                    + (f"; Extensão: {extension_status}" if "wasm32-extension" in cfg.targets else "") + ".")
                erros = summary_txt.split("=== Erros ===", 1)
                if len(erros) == 2:
                    for line in erros[1].strip().splitlines():
                        print(line, flush=True)

            local_zip = op.local_dir / Path(paths.stamped_zip).name
            try:
                _ts(f"A descarregar zip: {paths.stamped_zip} …")
                server.download(paths.stamped_zip, local_zip)
                _ts(f"Zip guardado em: {local_zip}")
            except Exception as exc:
                _ts(f"AVISO: falha ao descarregar o zip ({exc}). "
                    f"Caminho remoto: {paths.stamped_zip}")
                local_zip = None

            _ts("=== Release terminada ===")
            return str(local_zip) if local_zip else paths.stamped_zip

class UninstallJob:
    def __init__(self, server: Server):
        self.server = server

    @staticmethod
    def revert_nixos_module(server: Server) -> None:
        _ts("A reverter módulo NixOS (vaultseed.nix) …")

        has_backup = server.capture(
            "[ -f /etc/nixos/configuration.nix.bak-vaultseed ] && echo yes || echo no",
            timeout=10,
        ).strip()

        if has_backup == "yes":
            _ts("  Backup configuration.nix.bak-vaultseed encontrado - a restaurar …")
            server.run_checked(
                "cp /etc/nixos/configuration.nix.bak-vaultseed /etc/nixos/configuration.nix "
                "&& rm -f /etc/nixos/configuration.nix.bak-vaultseed",
                sudo=True,
            )
        else:
            _ts("  Sem backup - a remover './vaultseed.nix' dos imports via regex …")
            py_script = (
                "import re\n"
                "p = '/etc/nixos/configuration.nix'\n"
                "t = open(p).read()\n"
                "new = re.sub(r'\\s*\\./vaultseed\\.nix', '', t)\n"
                "open(p, 'w').write(new)\n"
                "print('OK')\n"
            )
            py_b64 = base64.b64encode(py_script.encode()).decode()
            server.run_checked(f"echo {py_b64} | base64 -d | python3", timeout=15, sudo=True)

        server.run_checked("rm -f /etc/nixos/vaultseed.nix", sudo=True)

        _ts("nixos-rebuild switch … (a aplicar reversão, pode demorar)")
        rc = server.run("nixos-rebuild switch 2>&1", timeout=5400, sudo=True)
        if rc != 0:
            raise RuntimeError(
                f"nixos-rebuild switch falhou (exit {rc}) ao reverter o módulo VaultSeed."
            )
        _ts("Módulo NixOS revertido.")

    @staticmethod
    def ask_components(components: list) -> list:
        print("\n  Para cada componente instalado pelo setup, indique pretende removê-lo (limpeza completa) ou mantê-lo.")
        selected = []
        for c in components:
            print()
            if c.note:
                print(f"  [!] {c.label}")
                print(f"      {c.note}")
            else:
                print(f"  {c.label}")
            while True:
                ans = input("      Apagar? (s/N): ").strip().lower()
                if ans in ("", "n", "nao", "não", "s", "sim"):
                    break
                print("      Responda 's' (apagar) ou 'n' (manter).")
            if ans in ("s", "sim"):
                selected.append(c)
        return selected

    @staticmethod
    def confirm_local_results() -> bool:
        print("\n  Histórico local de acções (pasta result/ deste repositório)")
        ans = input("      Apagar todo o histórico local? (s/N): ").strip().lower()
        return ans in ("s", "sim")

    @staticmethod
    def clean_local_results() -> int:
        import shutil
        from .action import RESULT_ROOT
        if not RESULT_ROOT.exists():
            return 0
        n = 0
        for d in RESULT_ROOT.iterdir():
            if d.is_dir():
                shutil.rmtree(d, ignore_errors=True)
                n += 1
        return n

    def execute( self, op_type: str, env_block: str, selected: list,
        nixos: bool = False, sudo_preamble: str = "", extra_script: str = "",
        wipe_local: bool = False,
    ) -> int:
        is_windows = self.server.profile.os == "windows"
        if not selected and not extra_script:
            print("\n  Nenhum componente seleccionado para apagar - só a cache será limpa.")

        print()
        with self.server as server:
            op = RemoteOp(server, op_type)
            print(f"  ID da operação: {op.id}\n")
            _ts(f"Conectado a {server.label}")

            preamble = op.preamble()
            cache    = op.shell.cache_cleanup(nixos=nixos)
            if is_windows:
                body   = "".join(c.ps for c in selected)
                script = (preamble + env_block + cache + body + extra_script + 'Set-Content -Path $OP_STATUS -Value 0 -NoNewline\n')
            else:
                body   = "".join(c.bash for c in selected)
                script = ("#!/usr/bin/env bash\nset -u\n" + preamble + env_block + sudo_preamble + cache + body + extra_script + 'echo 0 > "$OP_STATUS"\n')

            op.action.save_meta(type=op_type, status="running", server=server.label, started_at=datetime.now().isoformat())
            op.launch(script)
            print("Processo lançado. A monitorizar (poll a cada 15 segundos)...\n")
            rc = op.monitor(timeout=3600, poll=15)

        if wipe_local:
            n = self.clean_local_results()
            print(f"\n  Histórico local limpo ({n} pastas removidas em result/).")

        if rc == 0:
            op.action.save_meta(status="ok")
            print("\n  Desinstalação concluída.")
        elif rc == RC_DETACHED:
            op.action.save_meta(status="running")
            print("\n  Monitor desligado - a desinstalação continua no servidor.")
        elif rc == 130:
            op.action.save_meta(status="cancelled")
            print("\n  Cancelado.")
        else:
            op.action.save_meta(status="failed")
            print(f"\n  Terminou com avisos/erros (exit {rc}) - ver summary.log em "
                  f"result/{op.id}/.")

        return rc if rc != 130 else 1

    def run(
        self, op_type: str, env_block: str, components: list,
        nixos: bool = False, sudo_preamble: str = "",
    ) -> int:
        selected = self.ask_components(components)
        wipe_local = self.confirm_local_results()
        return self.execute(
            op_type, env_block, selected,
            nixos=nixos, sudo_preamble=sudo_preamble, wipe_local=wipe_local,
        )
