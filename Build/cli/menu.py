from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path

_REPO_ROOT_BOOTSTRAP = str(Path(__file__).resolve().parent.parent.parent)
if _REPO_ROOT_BOOTSTRAP not in sys.path:
    sys.path.insert(0, _REPO_ROOT_BOOTSTRAP)

from Build.core.action import Action
from Build.core.config import Config, ServerProfile
from Build.core.job import CheckJob, ReleaseJob, TestsJob, UninstallJob, build_config_for
from Build.core.remote_op import RemoteOp, RC_DETACHED, _ts
from Build.core.server import make_server, os_mismatch, real_os
from Build.core.setup_job import SetupJob
from Build.core.target import ProfileStore, TargetRegistry
from Build.cli import platform_data as pdata

_UNINSTALL_ENV_BLOCK = {
    "linux":   "source ~/.cargo/env 2>/dev/null || true\n",
    "nixos": (
        'export PATH="/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin'
        ':$HOME/.nix-profile/bin:$HOME/.cargo/bin:$PATH"\n'
        "source ~/.cargo/env 2>/dev/null || true\n"
    ),
    "windows": '$env:Path = "$HOME/.cargo/bin;" + $env:Path\n',
}

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ENV_FILE  = REPO_ROOT / "Build" / ".env"
UTILS_DIR = REPO_ROOT / "Build" / "utils"
PROFILES_JSON = REPO_ROOT / "Build" / "profiles.json"

W = 100

def _cls() -> None:
    os.system("cls" if os.name == "nt" else "clear")

def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (KeyboardInterrupt, EOFError):
        return "q"

def _top(title: str) -> None:
    print("╔" + "═" * (W - 2) + "╗")
    pad = (W - 2 - len(title)) // 2
    print("║" + " " * pad + title + " " * (W - 2 - pad - len(title)) + "║")


def _sep() -> None:
    print("╠" + "═" * (W - 2) + "╣")

def _bot() -> None:
    print("╚" + "═" * (W - 2) + "╝")

def _row(text: str = "") -> None:
    print(f"║  {text:<{W - 4}}║")

def _run_script(path: Path, args: list | None = None) -> int:
    proc = subprocess.Popen([sys.executable, str(path)] + (args or []))
    while True:
        try:
            return proc.wait()
        except KeyboardInterrupt:
            continue

def _status_icon(status: str) -> str:
    return {
        "ok": "✓", "running": "↻", "failed": "✗",
        "cancelled": "✕", "partial": "~",
    }.get(status, "?")

def menu_edit_server(config: Config, n: int) -> None:
    profile = config.server(n)
    while True:
        _cls()
        _top(f"Servidor {n}")
        _sep()
        _row(f"  Host:  {profile.host or '(vazio)'}")
        _row(f"  User:  {profile.user or '(vazio)'}")
        _row(f"  Pass:  {'*' * len(profile.password) if profile.password else '(vazio)'}")
        _row(f"  OS:    {profile.os}")
        _row(f"  Local: {'sim' if profile.local else 'não'}")
        _sep()
        _row("  1) Host   2) User   3) Pass   4) OS   5) Local on/off")
        _row("  0) Voltar")
        _bot()
        c = _ask("Escolha: ")
        if c == "0" or c == "q":
            return
        if c == "1":
            config.set(f"VS_HOST_{n}", _ask("Novo host: "))
        elif c == "2":
            config.set(f"VS_USER_{n}", _ask("Novo user: "))
        elif c == "3":
            config.set(f"VS_PASS_{n}", _ask("Nova password: "))
        elif c == "4":
            new_os = _ask("Novo OS (linux/windows/nixos): ").strip().lower()
            if new_os in pdata.PLATFORMS:
                config.set(f"VS_OS_{n}", new_os)
            else:
                _ask(f"  OS inválido ({new_os!r}). [Enter]")
                continue
        elif c == "5":
            new_local = not profile.local
            if new_local:
                candidate = ServerProfile(
                    n=n, host=profile.host, user=profile.user,
                    password=profile.password, os=profile.os, local=True,
                )
                if os_mismatch(candidate):
                    _ask(
                        f"  Aviso: este servidor está configurado como '{profile.os}', "
                        f"mas esta máquina parece ser '{real_os()}'. [Enter para continuar]"
                    )
                    ans = _ask("  Activar modo local mesmo assim? (s/N): ").strip().lower()
                    if ans not in ("s", "sim"):
                        continue
            config.set(f"VS_LOCAL_{n}", "true" if new_local else "false")
        config.save()
        profile = config.server(n)

def menu_config(config: Config) -> None:
    while True:
        _cls()
        _top("Configuração (Build/.env)")
        _sep()

        max_n   = config.max_server_n()
        active  = config.active_server_n
        profile = config.server()

        _row("  Servidores:")
        for n in range(1, max_n + 1):
            p = config.server(n)
            marker = ">" if n == active else " "
            _row(f"  {marker} {n}) {p.label}")
        if max_n == 0:
            _row("    (nenhum - usa 'n' para criar o primeiro)")
        _sep()

        store = ProfileStore(TargetRegistry(), PROFILES_JSON)
        profile_name = config.profile_name()
        n_targets = len(store.triples_for(profile_name))
        modo = f"LOCAL  [{profile.os}]" if profile.local else f"REMOTO via SSH  [{profile.os}]"

        _row(f"  Modo:          {modo}")
        _row(f"  Perfil:        {profile_name} ({n_targets} targets)")
        _row(f"  --timings:     {'ligado' if config.timings_enabled() else 'desligado'}")
        _row(f"  RUST_BACKTRACE: {config.backtrace_value()}")
        _row(f"  Fast optimize: {'ligado (LTO desligado, build rápida)' if config.fast_lto() else 'desligado (LTO=thin, build otimizada)'}")
        _row(f"  Codegen units: {config.codegen_units()}")
        slint_opt = config.slint_opt_level()
        _row(f"  Slint opt-level: {slint_opt if slint_opt is not None else '(default do Cargo.toml)'}")
        build_jobs = config.build_jobs()
        _row(f"  CARGO_BUILD_JOBS: {build_jobs if build_jobs is not None else '(default = nº de CPUs)'}")
        _row(f"  Build mode:    {'--release (optimizado, lento)' if config.build_release() else 'debug (sem optimização, build rápida)'}")
        _sep()
        _row("  s) Trocar servidor activo   n) Novo servidor")
        _row("  d) Editar servidor          l) Alternar local/SSH (servidor activo)")
        _row("  t) Alternar perfil targets  i) Alternar --timings")
        _row("  b) Ciclar RUST_BACKTRACE    o) Alternar Fast optimize (lto)")
        _row("  c) Codegen units            v) Slint opt-level")
        _row("  j) CARGO_BUILD_JOBS         r) Alternar --release/debug")
        _row("  q) Voltar")
        _bot()
        c = _ask("Escolha: ").lower()

        if c in ("q", "0"):
            return

        elif c == "s":
            n = _ask("  Número do servidor a activar: ")
            if n.isdigit() and 1 <= int(n) <= max_n:
                config.set_active_server(int(n))
                config.save()
            else:
                _ask("  Opção inválida. [Enter]")

        elif c == "n":
            n = max_n + 1
            config.set_many({
                f"VS_HOST_{n}": "", f"VS_USER_{n}": "", f"VS_PASS_{n}": "",
                f"VS_OS_{n}": "linux", f"VS_LOCAL_{n}": "false",
            })
            config.save()
            menu_edit_server(config, n)

        elif c == "d":
            n = _ask("  Número do servidor a editar: ")
            if n.isdigit() and 1 <= int(n) <= max_n:
                menu_edit_server(config, int(n))
            else:
                _ask("  Opção inválida. [Enter]")

        elif c == "l":
            new_local = not profile.local
            if new_local:
                candidate = ServerProfile(
                    n=active, host=profile.host, user=profile.user,
                    password=profile.password, os=profile.os, local=True,
                )
                if os_mismatch(candidate):
                    _ask(
                        f"  Aviso: este servidor está configurado como '{profile.os}', "
                        f"mas esta máquina parece ser '{real_os()}'. [Enter para continuar]"
                    )
                    if _ask("  Activar modo local mesmo assim? (s/N): ").strip().lower() not in ("s", "sim"):
                        continue
            config.set(f"VS_LOCAL_{active}", "true" if new_local else "false")
            config.save()

        elif c == "t":
            new_name = store.next(profile_name)
            config.set("VS_PROFILE", new_name)
            config.save()

        elif c == "i":
            config.set("VS_TIMINGS", "false" if config.timings_enabled() else "true")
            config.save()

        elif c == "b":
            cycle = {"0": "1", "1": "full", "full": "0"}
            config.set("VS_BACKTRACE", cycle.get(config.backtrace_value(), "0"))
            config.save()

        elif c == "o":
            config.set("VS_LTO", "false" if config.fast_lto() else "true")
            config.save()

        elif c == "c":
            val = _ask(f"  Codegen units (Enter=manter {config.codegen_units()}): ").strip()
            if val:
                if val.isdigit() and int(val) > 0:
                    config.set("VS_CODEGEN_UNITS", val)
                    config.save()
                else:
                    _ask("  Valor inválido - tem de ser um número inteiro positivo. [Enter]")

        elif c == "v":
            val = _ask("  Slint opt-level (0,1,2,3,s,z; vazio = default): ").strip()
            config.set("VS_SLINT_OPT_LEVEL", val)
            config.save()

        elif c == "j":
            val = _ask("  CARGO_BUILD_JOBS (vazio = default, nº de CPUs): ").strip()
            if not val or (val.isdigit() and int(val) > 0):
                config.set("VS_BUILD_JOBS", val)
                config.save()
            else:
                _ask("  Valor inválido - tem de ser um número inteiro positivo ou vazio. [Enter]")

        elif c == "r":
            config.set("VS_BUILD_RELEASE", "false" if config.build_release() else "true")
            config.save()


_ACTIONS_PAGE_SIZE = 10
def menu_actions(config: Config) -> None:
    actions = Action.list_recent(200)
    page = 0
    n_pages = max(1, (len(actions) + _ACTIONS_PAGE_SIZE - 1) // _ACTIONS_PAGE_SIZE)

    while True:
        _cls()
        _top(f"Acções recentes (página {page + 1}/{n_pages})")
        _sep()
        start = page * _ACTIONS_PAGE_SIZE
        chunk = actions[start:start + _ACTIONS_PAGE_SIZE]
        if not chunk:
            _row("  (sem histórico em result/)")
        for i, a in enumerate(chunk, start + 1):
            icon   = _status_icon(a.meta.get("status", "?"))
            status = a.meta.get("status", "?")
            _row(f"  [{i}] {icon} {a.id}  {status}")
        _sep()
        nav = []
        if page > 0:
            nav.append("p) Página anterior")
        if page < n_pages - 1:
            nav.append("n) Página seguinte")
        if nav:
            _row("  " + "   ".join(nav))
        _row("  <n>) Ver detalhe de uma acção")
        _row("  q) Voltar")
        _bot()
        c = _ask("Escolha: ").lower()
        if c in ("0", "q"):
            return
        if c == "n" and page < n_pages - 1:
            page += 1
        elif c == "p" and page > 0:
            page -= 1
        elif c.isdigit():
            idx = int(c) - 1
            if start <= idx < start + len(chunk):
                menu_action_detail(config, chunk[idx - start])
                actions = Action.list_recent(200)
                n_pages = max(1, (len(actions) + _ACTIONS_PAGE_SIZE - 1) // _ACTIONS_PAGE_SIZE)

def menu_action_detail(config: Config, action: Action) -> None:
    while True:
        action = Action.load(action.id)
        meta   = action.meta
        status = meta.get("status", "?")

        _cls()
        _top(action.id)
        _sep()
        _row(f"  Tipo:     {action.op_type}")
        _row(f"  Estado:   {_status_icon(status)} {status}")
        if meta.get("profile"):
            _row(f"  Perfil:   {meta['profile']}")
        if meta.get("server"):
            _row(f"  Servidor: {meta['server']}")
        if meta.get("started_at"):
            _row(f"  Iniciado: {meta['started_at'][:19]}")
        if meta.get("finished_at"):
            _row(f"  Fim:      {meta['finished_at'][:19]}")
        if meta.get("exit_code") is not None:
            _row(f"  Exit:     {meta['exit_code']}")
        if meta.get("targets_ok") is not None and meta.get("targets_total") is not None:
            _row(f"  Targets:  {meta['targets_ok']}/{meta['targets_total']} OK")
        _row(f"  Pasta:    {action.local_dir}")
        if meta.get("local_zip"):
            _row(f"  Zip:      {meta['local_zip']}")

        _sep()
        is_running = status == "running"
        is_release = "release" in action.op_type
        if is_running:
            _row("  m) Monitorizar    - ligar e ver logs em tempo real")
            _row("  x) Cancelar       - terminar o processo remoto")
        if is_release:
            label = "Extrair novamente" if meta.get("fetched") else "Extrair resultado"
            _row(f"  f) {label} - download do ZIP de release")
        _row("  s) Ver logs       - summary.log local")
        _row("  r) Log remoto     - descarregar e ver stdout.log do servidor")
        _row("  q) Voltar")
        _bot()

        c = _ask("Escolha: ").lower()
        if c == "q":
            return

        elif c == "m" and is_running:
            _cls()
            print(f"  A ligar a {meta.get('server', '?')} e a monitorizar {action.id}…\n")
            try:
                server = make_server(config)
                with server as sv:
                    op = RemoteOp.attach(sv, action.id)
                    if not op.is_running():
                        print("  Processo não encontrado no servidor (pode ter terminado).")
                    else:
                        rc = op.monitor(timeout=14400, poll=30)
                        if rc == RC_DETACHED:
                            print("\n  Monitor desligado - o processo continua a correr no servidor.")
            except Exception as exc:
                print(f"\n  Erro ao ligar: {exc}")
            _ask("\n  [Enter]")

        elif c == "x" and is_running:
            confirm = _ask(f"  Confirmar cancelar '{action.id}'? (s/N): ").lower()
            if confirm not in ("s", "sim"):
                continue
            try:
                server = make_server(config)
                with server as sv:
                    op = RemoteOp.attach(sv, action.id)
                    op.stop()
                action.save_meta(status="cancelled")
                print("  Processo terminado.")
            except Exception as exc:
                print(f"  Erro ao cancelar: {exc}")
            _ask("  [Enter]")

        elif c == "f" and is_release:
            _cls()
            print(f"  A ligar a {meta.get('server', '?')} …\n")
            try:
                server = make_server(config)
                with server as sv:
                    op      = RemoteOp.attach(sv, action.id)
                    builder = pdata.release_builder(sv.profile.os)
                    home    = builder.home_dir(sv)
                    paths   = builder.paths_for(op, home)
                    local_zip = action.local_dir / Path(paths.stamped_zip).name
                    print(f"  A descarregar: {paths.stamped_zip}")
                    sv.download(paths.stamped_zip, local_zip)
                    sz = local_zip.stat().st_size / (1024 * 1024)
                    print(f"  Guardado: {local_zip} ({sz:.1f} MB)")
                    action.save_meta(fetched=True, local_zip=str(local_zip))
            except Exception as exc:
                print(f"\n  Erro no fetch: {exc}")
            _ask("\n  [Enter]")

        elif c == "s":
            _cls()
            _top(f"Logs - {action.id}")
            _sep()
            try:
                content = action.local_summary.read_text("utf-8", errors="replace")
            except OSError:
                content = "(sem summary.log local)"
            print(content)
            _ask("\n  [Enter]")

        elif c == "r":
            _cls()
            print(f"  A descarregar stdout.log de {meta.get('server', '?')}…\n")
            try:
                server = make_server(config)
                with server as sv:
                    op = RemoteOp.attach(sv, action.id)
                    content = sv.capture(
                        f'[ -f {op.remote_dir}/stdout.log ] && cat {op.remote_dir}/stdout.log || echo ""',
                        timeout=30,
                    ) if sv.profile.os != "windows" else sv.capture(
                        f'if (Test-Path "{op.remote_dir}/stdout.log") '
                        f'{{ Get-Content "{op.remote_dir}/stdout.log" -Raw }}',
                        timeout=30,
                    )
                    if not content:
                        content = f"(stdout.log não encontrado em {op.remote_dir})"
                print(content)
                p = action.local_dir / "stdout.log"
                p.write_text(content, "utf-8", errors="replace")
                print(f"\n  Guardado em: {p}")
            except Exception as exc:
                print(f"\n  Erro: {exc}")
            _ask("\n  [Enter]")

def _choose(label: str, options: list[str]) -> str | None:
    _row(f"  {label}:")
    for i, opt in enumerate(options, 1):
        _row(f"    {i}) {opt}")
    _bot()
    c = _ask("  Escolha: ")
    if not c.isdigit() or not (1 <= int(c) <= len(options)):
        return None
    return options[int(c) - 1]

def menu_new_action(config: Config) -> None:
    _cls()
    _top("Nova Acção")
    _sep()

    profile = config.server()
    _row(f"  Servidor activo: {profile.label}")
    _sep()

    op = _choose("Operação", ["release", "check", "tests", "setup", "uninstall"])
    if op is None:
        return

    registry = TargetRegistry()
    server = make_server(config)

    try:
        if op == "setup":
            builder = pdata.setup_builder(profile.os, sudo_pass=profile.password)
            rc = SetupJob(server, builder).run(f"setup-{profile.os}")
            _ask(f"\n  Terminado (exit {rc}). [Enter]")

        elif op == "check":
            from Build.cli.run_direct import _CHECK_FEATURES
            feature = _choose("Feature (subconjunto a verificar - 'none' é o mais rápido)", list(_CHECK_FEATURES))
            if feature is None:
                return
            env = pdata.check_tests_env(profile.os)
            rc = CheckJob(
                server, env, registry, config.build_jobs(), config.build_release(),
                variant_filter=_CHECK_FEATURES[feature],
            ).run(f"check-{profile.os}")
            _ask(f"\n  Terminado (exit {rc}). [Enter]")

        elif op == "tests":
            env = pdata.check_tests_env(profile.os)
            store = ProfileStore(registry, PROFILES_JSON)
            profile_name = config.profile_name()
            triples = store.triples_for(profile_name)
            rc = TestsJob(server, env, registry).run(f"tests-{profile.os}", triples, profile_name)
            _ask(f"\n  Terminado (exit {rc}). [Enter]")

        elif op == "release":
            store = ProfileStore(registry, PROFILES_JSON)
            profile_name = config.profile_name()
            triples = store.triples_for(profile_name)
            renv = pdata.release_env(profile.os)
            cfg = build_config_for(
                registry, triples, profile_name, renv, config,
                native_windows=pdata.for_os(profile.os).native_windows,
            )
            builder = pdata.release_builder(profile.os)
            zip_path = ReleaseJob(server, builder).run(f"release-{profile.os}", cfg)
            _ask(f"\n  Terminado. Zip: {zip_path or '(nenhum - ver mensagens acima)'} [Enter]")

        elif op == "uninstall":
            bat_paths = None
            if profile.os == "windows":
                with server as sv:
                    _ts(f"Conectado a {sv.label}")
                    bat_paths = pdata.upload_windows_bats(sv)
            components = pdata.uninstall_components(profile.os, bat_paths)
            job = UninstallJob(server)
            env_block = _UNINSTALL_ENV_BLOCK.get(profile.os, "")

            if profile.os == "nixos":
                nixos_module = next((c for c in components if c.id == "nixos_module"), None)
                rest = [c for c in components if c.id != "nixos_module"]
                selected_module = job.ask_components([nixos_module]) if nixos_module else []
                selected_rest = job.ask_components(rest)
                if selected_module:
                    with server as sv:
                        _ts(f"Conectado a {sv.label}")
                        job.revert_nixos_module(sv)
                wipe_local = job.confirm_local_results()
                rc = job.execute(
                    f"uninstall-{profile.os}", env_block, selected_rest,
                    nixos=True, wipe_local=wipe_local,
                )
            elif profile.os == "linux":
                pass_b64 = base64.b64encode(profile.password.encode()).decode()
                sudo_preamble = (
                    f'PASS=$(echo {pass_b64} | base64 -d)\n'
                    '_sudo() { echo "$PASS" | sudo -S -E bash -c "$*"; }\n\n'
                )
                rc = job.run(f"uninstall-{profile.os}", env_block, components, sudo_preamble=sudo_preamble)
            else:
                rc = job.run(f"uninstall-{profile.os}", env_block, components)

            _ask(f"\n  Terminado (exit {rc}). [Enter]")

    except Exception as exc:
        _ask(f"\n  Erro: {exc} [Enter]")

def menu_utils() -> None:
    _cls()
    _top("Utilitários")
    _sep()
    _row("  1) Ícones Android - regenerar ícones a partir dos PNGs de origem")
    _row("  2) Mudar versão   - actualizar a versão do VaultSeed em todos os locais")
    _row("  q) Voltar")
    _bot()
    c = _ask("Escolha: ")
    if c == "1":
        rc = _run_script(UTILS_DIR / "regenerate_android_icons.py")
        _ask(f"\n  Terminado (exit {rc}). [Enter]")
    elif c == "2":
        rc = _run_script(UTILS_DIR / "version_bump.py")
        _ask(f"\n  Terminado (exit {rc}). [Enter]")

def menu_main() -> None:
    config = Config(ENV_FILE)
    while True:
        _cls()
        profile = config.server()
        _top("VAULTSEED - BUILD")
        _sep()
        _row(f"  Servidor activo: {profile.label}")
        _row(f"  Perfil: {config.profile_name()}")
        _sep()
        _row("  1) Acções        - ver histórico local")
        _row("  2) Nova Acção    - setup / check / tests / release / uninstall")
        _row("  3) Configuração  - servidores, perfil de targets")
        _row("  4) Utilitários   - ícones Android, mudar versão")
        _sep()
        _row("  q) Sair")
        _bot()
        c = _ask("Escolha: ").lower()
        if c == "q":
            break
        elif c == "1":
            menu_actions(config)
        elif c == "2":
            menu_new_action(config)
        elif c == "3":
            menu_config(config)
        elif c == "4":
            menu_utils()

if __name__ == "__main__":
    menu_main()