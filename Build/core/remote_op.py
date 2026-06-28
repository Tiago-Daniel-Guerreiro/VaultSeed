from __future__ import annotations

import base64
import os
import re
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path

from . import action as _action
from .server import Server

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")

def _b64_bom(text: str) -> str:
    return base64.b64encode(b"\xef\xbb\xbf" + text.encode("utf-8")).decode("ascii")

def _ts(msg: str) -> None:
    print(f"[{datetime.utcnow():%H:%M:%S}] {msg}", flush=True)

def _sq(text: str) -> str:
    return "'" + text.replace("'", "'\\''") + "'"

RC_DETACHED = 99

_RE_FASE        = re.compile(r'\bFASE:\s*(.*)')
_RE_PROGRESS    = re.compile(r'\bPROGRESS:\s*(\d+)/(\d+)')
_RE_TS          = re.compile(r'^\[(\d{2}):(\d{2}):(\d{2})\]')

def _seconds_since(ts_match: "re.Match") -> int:
    h, m, sec = (int(x) for x in ts_match.groups())
    then_s = h * 3600 + m * 60 + sec
    now    = datetime.utcnow()
    now_s  = now.hour * 3600 + now.minute * 60 + now.second
    diff   = now_s - then_s
    return diff + 86400 if diff < 0 else diff

def _cpu_str(pct: float, ncpu: int) -> str:
    ncpu = ncpu or 1
    return f"{pct / ncpu:.0f}% ({pct:.0f}%/{ncpu})"

_last_cpu_snapshot: dict[str, tuple[float, float]] = {}

class ShellOps(ABC):
    @abstractmethod
    def remote_home(self, server: Server) -> str:
        """Pasta "home" a usar para este servidor."""

    @abstractmethod
    def preamble(self, op: "RemoteOp") -> str:
        """Variáveis e helpers de log (_fase/_ok/_fail/_info/_prog) para o início dos scripts gerados."""

    @abstractmethod
    def remote_test(self, server: Server, path: str, timeout: int) -> bool: ...

    @abstractmethod
    def remote_cat(self, server: Server, path: str, timeout: int) -> str: ...

    @abstractmethod
    def remote_tail(self, server: Server, path: str, skip: int, timeout: int) -> str: ...

    @abstractmethod
    def remote_rm(self, server: Server, paths: tuple[str, ...], timeout: int) -> None: ...

    @abstractmethod
    def cache_cleanup(self, nixos: bool = False) -> str:
        """Script que limpa cache/acções anteriores, antes da desinstalação de componentes"""

    @abstractmethod
    def launch(self, server: Server, op: "RemoteOp", script_text: str) -> None:
        """Envia o script e lança-o em background (sobrevive à ligação cair)."""

    @abstractmethod
    def is_alive(self, server: Server, pid: str, timeout: int) -> bool: ...

    @abstractmethod
    def kill(self, server: Server, pid: str) -> None: ...

    @abstractmethod
    def mark_running(self, server: Server, op: "RemoteOp") -> None: ...

    @abstractmethod
    def mark_finished(self, server: Server, op: "RemoteOp", rc: int) -> None: ...

    @abstractmethod
    def fetch_resources(self, server: Server, pid: str) -> str: ...

    @abstractmethod
    def list_remote(self, server: Server, temp_dir: str) -> list[dict]: ...

class BashShell(ShellOps):
    def remote_home(self, server: Server) -> str:
        if server.is_local:
            return str(Path.home()).replace("\\", "/")
        return f"/home/{server.profile.user or 'user'}"

    def preamble(self, op: "RemoteOp") -> str:
        return (
            f'OP_ID="{op.id}"\n'
            f'OP_DIR="{op.remote_dir}"\n'
            f'SUMMARY="{op.r_summary}"\n'
            f'PHASE="{op.r_phase}"\n'
            f'OP_STATUS="{op.r_status}"\n'
            f'CARGO_LOGS="{op.r_cargo}"\n'
            'mkdir -p "$OP_DIR" "$CARGO_LOGS"\n'
            '\n'
            '# Helpers de log\n'
            '_s()    { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$SUMMARY"; }\n'
            '_fase() { _s "FASE: $*"; printf "%s" "$*" > "$PHASE"; }\n'
            '_ok()   { _s "OK: $*"; }\n'
            '_fail() { _s "FAIL: $*"; }\n'
            '_info() { _s "INFO: $*"; }\n'
            '_prog() { _s "PROGRESS: $1/$2"; }\n'
            '\n'
        )

    def remote_test(self, server, path, timeout=10):
        out = server.capture(f'[ -e {path} ] && echo 1 || echo 0', timeout=timeout).strip()
        return out == "1"

    def remote_cat(self, server, path, timeout=20):
        return server.capture(f'[ -f {path} ] && cat {path} || echo ""', timeout=timeout)

    def remote_tail(self, server, path, skip, timeout=30):
        return server.capture(f'[ -f {path} ] && tail -n +{skip + 1} {path} || true', timeout=timeout)

    def remote_rm(self, server, paths, timeout=10):
        server.run(f"rm -f {' '.join(paths)}", timeout=timeout)

    def cache_cleanup(self, nixos: bool = False) -> str:
        lines = [
            '_fase "Limpeza: acções anteriores e cache"',
            'rm -rf "$HOME/.vaultseed/temp" && _info "Removido: ~/.vaultseed/temp"',
            'rm -rf "$HOME/.vaultseed_cache" && _info "Removido: ~/.vaultseed_cache"',
            'shopt -s nullglob',
            'for f in "$HOME"/.vaultseed/*.sh "$HOME"/.vaultseed/*.log '
            '"$HOME"/.vaultseed/*.status "$HOME"/.vaultseed/*.pid "$HOME"/.vaultseed/*.lock; do',
            '  rm -f "$f" && _info "Removido (legado): $f"',
            'done',
            'if [ -d "$HOME/VaultSeed_Release" ]; then',
            '  rm -rf "$HOME/VaultSeed_Release" && _info "Removido (legado): ~/VaultSeed_Release"',
            'fi',
            'if [ -d "$HOME/VaultSeed" ]; then',
            '  rm -rf "$HOME/VaultSeed/target" "$HOME/VaultSeed/.targets" '
            '&& _info "Removido: ~/VaultSeed/target, ~/VaultSeed/.targets"',
            'fi',
        ]
        if nixos:
            lines += [
                'for f in "$HOME"/VaultSeed/.envrc "$HOME"/VaultSeed/flake.nix "$HOME"/VaultSeed/flake.lock; do',
                '  [ -f "$f" ] && rm -f "$f" && _info "Removido (flake legado): $f"',
                'done',
                'if [ -d "$HOME/VaultSeed/.direnv" ]; then',
                '  rm -rf "$HOME/VaultSeed/.direnv" && _info "Removido: ~/VaultSeed/.direnv"',
                'fi',
            ]
        lines.append('_ok "Limpeza de cache OK"')
        return "\n".join(lines) + "\n\n"

    def launch(self, server, op, script_text):
        script_b64 = _b64(script_text)
        server.run_checked(
            f"mkdir -p {op.remote_dir} {op.r_cargo} && "
            f"echo {script_b64} | base64 -d > {op.r_script} && "
            f"chmod +x {op.r_script} && "
            f"rm -f {op.r_status} {op.r_summary} {op.r_phase}"
        )
        server.run_checked(
            f"setsid bash {op.r_script} "
            f">{op.remote_dir}/stdout.log 2>&1 </dev/null & "
            f"_PID=$!; echo $_PID > {op.r_pid}; echo $_PID > {op.r_lock}"
        )

    def is_alive(self, server, pid, timeout=10):
        out = server.capture(f'kill -0 {pid} 2>/dev/null && echo 1 || echo 0', timeout=timeout).strip()
        return out == "1"

    def kill(self, server, pid):
        server.run(
            f'kill -TERM -{pid} 2>/dev/null || true; '
            f'kill -TERM  {pid} 2>/dev/null || true; '
            f'kill -KILL -{pid} 2>/dev/null || true; '
            f'kill -KILL  {pid} 2>/dev/null || true',
            timeout=5,
        )

    def mark_running(self, server, op):
        server.run_checked(
            f"mkdir -p {op.remote_dir} {op.r_cargo} && "
            f"echo {os.getpid()} > {op.r_pid} && "
            f"echo {os.getpid()} > {op.r_lock}"
        )

    def mark_finished(self, server, op, rc):
        server.run(f"echo {rc} > {op.r_status} && rm -f {op.r_lock}", timeout=10)

    _RESOURCE_SCRIPT = (
        'pid="{pid}"\n'
        'pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d \' \')\n'
        'if [ -n "$pgid" ]; then\n'
        "    ps -o pcpu=,rss= -g \"$pgid\" 2>/dev/null | awk '{{c+=$1; r+=$2; n++}} END "
        '{{printf "PROC %.1f %d %d\\n", c+0, r+0, n+0}}\'\n'
        'else\n'
        '    echo "PROC 0.0 0 0"\n'
        'fi\n'
        'echo "NCPU $(nproc)"\n'
    )

    def fetch_resources(self, server, pid):
        if not pid:
            return "PID não encontrado - operação pode já ter terminado"
        try:
            script = self._RESOURCE_SCRIPT.format(pid=pid)
            raw = server.capture(f"bash -c {_sq(script)}", timeout=15)
        except Exception as exc:
            return f"falha ao obter recursos - {exc}"

        proc_cpu, proc_rss_kb, proc_n, ncpu = 0.0, 0.0, 0, 1
        for line in raw.splitlines():
            parts = line.split()
            if not parts:
                continue
            tag, rest = parts[0], parts[1:]
            try:
                if tag == "PROC" and len(rest) >= 3:
                    proc_cpu, proc_rss_kb, proc_n = float(rest[0]), float(rest[1]), int(float(rest[2]))
                elif tag == "NCPU" and rest:
                    ncpu = int(rest[0])
            except ValueError:
                continue

        return (
            f"CPU {_cpu_str(proc_cpu, ncpu)} | RAM {proc_rss_kb / 1024 / 1024:.2f} GB "
            f"({proc_n} proc)"
        )

    def list_remote(self, server, temp_dir):
        script = (
            f'for d in {temp_dir}/*/; do\n'
            '  [ -d "$d" ] || continue\n'
            '  id=$(basename "$d")\n'
            '  lock=""   ; [ -f "$d/lock"   ] && lock=$(cat "$d/lock")\n'
            '  status="" ; [ -f "$d/status" ] && status=$(cat "$d/status")\n'
            '  phase=""  ; [ -f "$d/phase"  ] && phase=$(cat "$d/phase")\n'
            '  pid=""    ; [ -f "$d/pid"    ] && pid=$(cat "$d/pid")\n'
            '  alive="0" ; [ -n "$lock" ] && kill -0 "$lock" 2>/dev/null && alive="1"\n'
            '  echo "ID=$id|LOCK=$lock|STATUS=$status|PHASE=$phase|PID=$pid|ALIVE=$alive"\n'
            'done\n'
        )
        raw = server.capture(f'bash -c {_sq(script)}', timeout=30)
        return _parse_list_remote(raw)

class PowerShellShell(ShellOps):
    def remote_home(self, server: Server) -> str:
        if server.is_local:
            appdata = os.environ.get("APPDATA")
            if appdata:
                return f"{appdata.replace(chr(92), '/')}/VaultSeed"
            return f"{str(Path.home()).replace(chr(92), '/')}/AppData/Roaming/VaultSeed"
        return f"C:/Users/{server.profile.user or 'user'}/AppData/Roaming/VaultSeed"

    def preamble(self, op: "RemoteOp") -> str:
        return (
            f'$OP_ID = "{op.id}"\n'
            f'$OP_DIR = "{op.remote_dir}"\n'
            f'$SUMMARY = "{op.r_summary}"\n'
            f'$PHASE = "{op.r_phase}"\n'
            f'$OP_STATUS = "{op.r_status}"\n'
            f'$CARGO_LOGS = "{op.r_cargo}"\n'
            'New-Item -ItemType Directory -Force -Path $OP_DIR, $CARGO_LOGS | Out-Null\n'
            '\n'
            '# Helpers de log\n'
            'function _s($m) {\n'
            '    $line = "[$((Get-Date).ToUniversalTime().ToString(\'HH:mm:ss\'))] $m"\n'
            '    Add-Content -Path $SUMMARY -Value $line -Encoding UTF8\n'
            '    Write-Output $line\n'
            '}\n'
            'function _fase($m) { _s "FASE: $m"; Set-Content -Path $PHASE -Value $m -NoNewline }\n'
            'function _ok($m)   { _s "OK: $m" }\n'
            'function _fail($m) { _s "FAIL: $m" }\n'
            'function _warn($m) { _s "WARN: $m" }\n'
            'function _info($m) { _s "INFO: $m" }\n'
            'function _prog($a, $b) { _s "PROGRESS: $a/$b" }\n'
            '\n'
            '$ErrorActionPreference = "Continue"\n'
            '\n'
            '# Invoke-WebRequest com a barra de progresso por defeito é extremamente\n'
            '# lento quando o stdout está redireccionado para ficheiro, como aqui.\n'
            '$ProgressPreference = "SilentlyContinue"\n'
            '\n'
        )

    def remote_test(self, server, path, timeout=10):
        out = server.capture(
            f"if (Test-Path -LiteralPath '{path}') {{ '1' }} else {{ '0' }}", timeout=timeout,
        ).strip()
        return out == "1"

    def remote_cat(self, server, path, timeout=20):
        return server.capture(
            f"if (Test-Path -LiteralPath '{path}') {{ Get-Content -LiteralPath '{path}' -Raw }}",
            timeout=timeout,
        )

    def remote_tail(self, server, path, skip, timeout=30):
        return server.capture(
            f"if (Test-Path -LiteralPath '{path}') "
            f"{{ Get-Content -LiteralPath '{path}' | Select-Object -Skip {skip} }}",
            timeout=timeout,
        )

    def remote_rm(self, server, paths, timeout=10):
        quoted = ",".join(f"'{p}'" for p in paths)
        server.run(f"Remove-Item -Path {quoted} -Force -ErrorAction SilentlyContinue", timeout=timeout)

    def cache_cleanup(self, nixos: bool = False) -> str:
        return (
            '_fase "Limpeza: acções anteriores e cache"\n'
            'Remove-Item -Recurse -Force -Path "$env:APPDATA/VaultSeed/.vaultseed/temp" -ErrorAction SilentlyContinue\n'
            '_info "Removido: $env:APPDATA/VaultSeed/.vaultseed/temp"\n'
            'Remove-Item -Recurse -Force -Path "$env:APPDATA/VaultSeed/.vaultseed_cache" -ErrorAction SilentlyContinue\n'
            '_info "Removido: $env:APPDATA/VaultSeed/.vaultseed_cache"\n'
            'if (Test-Path "$env:APPDATA/VaultSeed/source") {\n'
            '    Remove-Item -Recurse -Force -Path "$env:APPDATA/VaultSeed/source/target", "$env:APPDATA/VaultSeed/source/.targets" -ErrorAction SilentlyContinue\n'
            '    _info "Removido: $env:APPDATA/VaultSeed/source/target, .targets"\n'
            '}\n'
            '_ok "Limpeza de cache OK"\n\n'
        )

    def launch(self, server, op, script_text):
        script_b64 = _b64_bom(script_text)
        server.run_checked(
            f"New-Item -ItemType Directory -Force -Path "
            f"'{op.remote_dir}', '{op.r_cargo}' | Out-Null; "
            f"[IO.File]::WriteAllBytes('{op.r_script}', "
            f"[Convert]::FromBase64String('{script_b64}')); "
            f"Remove-Item -Path '{op.r_status}', '{op.r_summary}', "
            f"'{op.r_phase}' -Force -ErrorAction SilentlyContinue"
        )
        server.run_fire_and_forget(
            f"$p = Start-Process powershell.exe -ArgumentList "
            f"'-NoProfile','-ExecutionPolicy','Bypass','-File','\"{op.r_script}\"' "
            f"-RedirectStandardOutput '{op.remote_dir}/stdout.log' "
            f"-RedirectStandardError '{op.remote_dir}/stderr.log' "
            f"-WindowStyle Hidden -PassThru; "
            f"Set-Content -Path '{op.r_pid}' -Value $p.Id -NoNewline; "
            f"Set-Content -Path '{op.r_lock}' -Value $p.Id -NoNewline"
        )

    def is_alive(self, server, pid, timeout=10):
        out = server.capture(
            f"if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ '1' }} else {{ '0' }}",
            timeout=timeout,
        ).strip()
        return out == "1"

    def kill(self, server, pid):
        server.run(
            f"Get-CimInstance Win32_Process -Filter "
            f"\"ParentProcessId = {pid}\" | "
            f"ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force "
            f"-ErrorAction SilentlyContinue }}; "
            f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue",
            timeout=5,
        )

    def mark_running(self, server, op):
        server.run_checked(
            f"New-Item -ItemType Directory -Force -Path "
            f"'{op.remote_dir}', '{op.r_cargo}' | Out-Null; "
            f"Set-Content -Path '{op.r_pid}' -Value {os.getpid()} -NoNewline; "
            f"Set-Content -Path '{op.r_lock}' -Value {os.getpid()} -NoNewline"
        )

    def mark_finished(self, server, op, rc):
        server.run(
            f"Set-Content -Path '{op.r_status}' -Value {rc} -NoNewline; "
            f"Remove-Item -Path '{op.r_lock}' -Force -ErrorAction SilentlyContinue",
            timeout=10,
        )

    _WIN_RESOURCE_SCRIPT = (
        "$root = Get-Process -Id {pid} -ErrorAction SilentlyContinue; "
        "if ($root) {{ "
        "$allProcs = Get-CimInstance Win32_Process; "
        "$ids = [System.Collections.Generic.HashSet[int]]::new(); "
        "[void]$ids.Add({pid}); "
        "$queue = [System.Collections.Generic.Queue[int]]::new(); "
        "$queue.Enqueue({pid}); "
        "while ($queue.Count -gt 0) {{ "
        "$cur = $queue.Dequeue(); "
        "foreach ($c in ($allProcs | Where-Object {{ $_.ParentProcessId -eq $cur }})) {{ "
        "if ($ids.Add($c.ProcessId)) {{ $queue.Enqueue($c.ProcessId) }} "
        "}} "
        "}}; "
        "$all = $ids | ForEach-Object {{ Get-Process -Id $_ -ErrorAction SilentlyContinue }} | Where-Object {{ $_ }}; "
        "$rss = ($all | Measure-Object -Property WorkingSet64 -Sum).Sum; "
        "$cpuSec = ($all | Measure-Object -Property CPU -Sum).Sum; "
        "$elapsed = ((Get-Date) - $root.StartTime).TotalSeconds; "
        "\"PROC $rss $($all.Count) $cpuSec $elapsed $env:NUMBER_OF_PROCESSORS\" "
        "}} else {{ 'PROC 0 0 0 0 1' }}"
    )

    def fetch_resources(self, server, pid):
        if not pid:
            return "PID não encontrado - operação pode já ter terminado"
        try:
            script = self._WIN_RESOURCE_SCRIPT.format(pid=pid)
            raw = server.capture(script, timeout=15)
        except Exception as exc:
            return f"falha ao obter recursos - {exc}"

        rss_kb, proc_n, cpu_sec, elapsed_sec, ncpu = 0.0, 0, 0.0, 0.0, 1
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 6 and parts[0] == "PROC":
                try:
                    rss_kb      = float(parts[1]) / 1024
                    proc_n      = int(float(parts[2]))
                    cpu_sec     = float(parts[3])
                    elapsed_sec = float(parts[4])
                    ncpu        = int(float(parts[5])) or 1
                except ValueError:
                    continue
        pct = (cpu_sec / elapsed_sec * 100) if elapsed_sec > 0 else 0.0

        now = time.time()
        cpu_label = _cpu_str(pct, ncpu)
        prev = _last_cpu_snapshot.get(pid)
        if prev is not None:
            prev_time, prev_cpu_sec = prev
            dt = now - prev_time
            if dt > 0:
                inst_pct = max(0.0, (cpu_sec - prev_cpu_sec) / dt * 100)
                cpu_label = _cpu_str(inst_pct, ncpu)
        _last_cpu_snapshot[pid] = (now, cpu_sec)

        return f"CPU {cpu_label} | RAM {rss_kb / 1024 / 1024:.2f} GB ({proc_n} proc)"

    def list_remote(self, server, temp_dir):
        script = (
            f"if (Test-Path '{temp_dir}') {{\n"
            f"  Get-ChildItem -LiteralPath '{temp_dir}' -Directory | ForEach-Object {{\n"
            "    $d = $_.FullName\n"
            "    $id = $_.Name\n"
            "    $lock   = if (Test-Path \"$d/lock\")   { (Get-Content -Raw \"$d/lock\").Trim() }   else { '' }\n"
            "    $status = if (Test-Path \"$d/status\") { Get-Content -Raw \"$d/status\" } else { '' }\n"
            "    $phase  = if (Test-Path \"$d/phase\")  { Get-Content -Raw \"$d/phase\" }  else { '' }\n"
            "    $pid_   = if (Test-Path \"$d/pid\")    { Get-Content -Raw \"$d/pid\" }    else { '' }\n"
            "    $alive  = '0'\n"
            "    if ($lock -and (Get-Process -Id $lock -ErrorAction SilentlyContinue)) { $alive = '1' }\n"
            "    \"ID=$id|LOCK=$lock|STATUS=$status|PHASE=$phase|PID=$pid_|ALIVE=$alive\"\n"
            "  }\n"
            "}\n"
        )
        raw = server.capture(script, timeout=30)
        return _parse_list_remote(raw)

def _parse_list_remote(raw: str) -> list[dict]:
    ops = []
    for line in raw.splitlines():
        kv = {}
        for part in line.split("|"):
            if "=" in part:
                k, _, v = part.partition("=")
                kv[k] = v
        if not kv.get("ID"):
            continue
        is_running = bool(kv.get("LOCK")) and kv.get("ALIVE") == "1"
        is_done    = kv.get("STATUS") != ""
        ops.append({
            "id":        kv["ID"],
            "running":   is_running,
            "done":      is_done,
            "exit_code": kv.get("STATUS", ""),
            "phase":     kv.get("PHASE", ""),
            "pid":       kv.get("PID", ""),
        })
    ops.sort(key=lambda o: (not o["running"], o["id"]))
    return ops

def shell_for(server: Server) -> ShellOps:
    return PowerShellShell() if server.profile.os == "windows" else BashShell()

def sync_source(server: Server, source_zip: Path, remote_zip: str, project_dir: str, remote_home: str, preserve=(".targets", "target")) -> None:
    new_dir = f"{project_dir}.new"
    _ts("A enviar código …")
    server.run_checked(f'mkdir -p "{remote_home}"')
    server.upload(source_zip, remote_zip)

    excludes = " ".join(f"--exclude='/{p}'" for p in preserve)
    _ts("A sincronizar código (rsync --checksum, preservando cache de build) …")
    server.run_checked(
        f'rm -rf "{new_dir}" && mkdir -p "{new_dir}" "{project_dir}" && '
        f'unzip -q -o "{remote_zip}" -d "{new_dir}" && '
        f'rm -f "{remote_zip}" && '
        f'rsync -a --checksum --delete {excludes} "{new_dir}/" "{project_dir}/" && '
        f'rm -rf "{new_dir}"'
    )

def sync_source_windows(server: Server, source_zip: Path, remote_zip: str, project_dir: str, remote_home: str, preserve=(".targets", "target")) -> None:
    cache_dir = f"{remote_home}/.vaultseed_cache"

    pre = [f"New-Item -ItemType Directory -Force -Path '{remote_home}', '{cache_dir}' | Out-Null"]
    for p in preserve:
        pre.append(
            f"Remove-Item -Recurse -Force -Path '{cache_dir}/{p}' -ErrorAction SilentlyContinue; "
            f"if (Test-Path -LiteralPath '{project_dir}/{p}') "
            f"{{ Move-Item -Force -Path '{project_dir}/{p}' -Destination '{cache_dir}/{p}' }}"
        )
    pre.append(
        f"Remove-Item -Recurse -Force -Path '{project_dir}' -ErrorAction SilentlyContinue; "
        f"Remove-Item -Force -Path '{remote_zip}' -ErrorAction SilentlyContinue"
    )

    _ts("A preparar directório remoto (preservando cache de build) …")
    server.run_checked("; ".join(pre))

    _ts("A enviar código …")
    server.upload(source_zip, remote_zip)

    restore = "; ".join(
        f"if (Test-Path -LiteralPath '{cache_dir}/{p}') "
        f"{{ Move-Item -Force -Path '{cache_dir}/{p}' -Destination '{project_dir}/{p}' }}"
        for p in preserve
    )
    server.run_checked(
        f"New-Item -ItemType Directory -Force -Path '{project_dir}' | Out-Null; "
        f"Expand-Archive -LiteralPath '{remote_zip}' -DestinationPath '{project_dir}' -Force; "
        f"Remove-Item -Force -Path '{remote_zip}'; "
        f"{restore}"
    )

class RemoteOp:
    REMOTE_TEMP = ".vaultseed/temp"

    def __init__(self, server: Server, op_type: str, action_id: str | None = None):
        self.server   = server
        self.op_type  = op_type
        self.shell: ShellOps = shell_for(server)
        self.action  = _action.Action.load(action_id) if action_id else _action.Action.create(op_type)
        self.id      = self.action.id

        rh = self.shell.remote_home(server)
        self.remote_home = rh
        self.remote_dir  = f"{rh}/{self.REMOTE_TEMP}/{self.id}"
        self.r_script    = f"{self.remote_dir}/" + ("run.ps1" if server.profile.os == "windows" else "run.sh")
        self.r_summary   = f"{self.remote_dir}/summary.log"
        self.r_cargo     = f"{self.remote_dir}/cargo"
        self.r_status    = f"{self.remote_dir}/status"
        self.r_phase     = f"{self.remote_dir}/phase"
        self.r_pid       = f"{self.remote_dir}/pid"
        self.r_lock      = f"{self.remote_dir}/lock"

        self.local_dir     = self.action.local_dir
        self.local_summary = self.action.local_summary
        self.local_cargo   = self.action.local_dir / "cargo"

    def preamble(self) -> str:
        return self.shell.preamble(self)

    def launch(self, script_text: str) -> None:
        s = self.server
        self.action.save_meta(
            type=self.op_type, server=s.label,
            started_at=datetime.utcnow().isoformat(), status="launching",
        )
        try:
            existing = self.shell.remote_cat(s, self.r_lock, 10).strip()
            if existing:
                raise RuntimeError(
                    f"Operação '{self.id}' já está a correr (PID {existing}).\n"
                    f"Para forçar: remove o lock manualmente em {self.r_lock}"
                )
            self.shell.launch(s, self, script_text)
        except Exception as exc:
            import traceback as _tb
            err_text = (
                f"=== Erro ao lançar operação {self.id} ===\n"
                f"Timestamp: {datetime.utcnow().isoformat()}\n"
                f"Servidor:  {s.label}\n\n"
                f"{_tb.format_exc()}\nMensagem: {exc}\n"
            )
            try:
                (self.local_dir / "error.log").write_text(err_text, "utf-8")
            except Exception:
                pass
            self.action.save_meta(status="launch-failed", error=str(exc))
            raise

        self.action.save_meta(status="running")
        _ts(f"[{self.id}] lançado. Log remoto: {self.r_summary}")

    def monitor(self, timeout: int = 7200, poll: int = 10) -> int:
        s              = self.server
        lines_seen     = 0
        start          = time.time()
        current_fase   = "(a iniciar…)"
        fase_start     = start
        progress       = ""

        try:
            existing = self.local_summary.read_text("utf-8", errors="replace").splitlines()
        except OSError:
            existing = []
        if existing:
            lines_seen = len(existing)
            first_ts = last_fase_ts = None
            for line in existing:
                ts_m = _RE_TS.match(line)
                if ts_m and first_ts is None:
                    first_ts = ts_m
                m = _RE_FASE.search(line)
                if m:
                    current_fase = m.group(1).strip()
                    progress     = ""
                    if ts_m:
                        last_fase_ts = ts_m
                m = _RE_PROGRESS.search(line)
                if m:
                    progress = f" ({m.group(1)}/{m.group(2)})"
            if first_ts:
                start = time.time() - _seconds_since(first_ts)
            fase_start = time.time() - _seconds_since(last_fase_ts) if last_fase_ts else start

        pid = self.shell.remote_cat(s, self.r_pid, 10).strip()
        _ts(f"[{self.id}] a monitorizar… (Ctrl+C desliga sem parar o processo remoto)")
        try:
            proc_info = self.shell.fetch_resources(s, pid)
            if proc_info:
                print(f"  Recursos - {proc_info}", flush=True)
        except Exception:
            pass

        try:
            while True:
                elapsed = time.time() - start
                if elapsed > timeout:
                    _ts(f"TIMEOUT ({timeout}s) - operação ainda corre no servidor.")
                    self.action.save_meta(status="timeout")
                    return 2

                try:
                    out = self.shell.remote_tail(s, self.r_summary, lines_seen, 30)
                    if out:
                        new_lines = out.splitlines()
                        for line in new_lines:
                            print(line, flush=True)
                            m = _RE_FASE.search(line)
                            if m:
                                current_fase = m.group(1).strip()
                                fase_start   = time.time()
                                progress     = ""
                            m = _RE_PROGRESS.search(line)
                            if m:
                                progress = f" ({m.group(1)}/{m.group(2)})"
                        lines_seen += len(new_lines)
                        with open(self.local_summary, "a", encoding="utf-8") as f:
                            f.write(out if out.endswith("\n") else out + "\n")

                    raw = self.shell.remote_cat(s, self.r_status, 20).strip()
                    if raw != "":
                        return self._finish(raw)

                    if not self.is_running():
                        time.sleep(1)
                        raw = self.shell.remote_cat(s, self.r_status, 20).strip()
                        if raw != "":
                            return self._finish(raw)
                        _ts(f"[{self.id}] processo remoto terminou sem registar "
                            f"estado final - a confiar no lock remoto.")
                        self.action.save_meta(status="unknown", finished_at=datetime.utcnow().isoformat())
                        self.shell.remote_rm(s, (self.r_lock,), 10)
                        return 1
                except subprocess.TimeoutExpired:
                    _ts(f"[{self.id}] poll lento (host ocupado) - a tentar novamente…")
                    time.sleep(poll)
                    continue

                total_s = int(time.time() - start)
                fase_s  = int(time.time() - fase_start)
                t_mm    = f"{total_s // 60}m{total_s % 60:02d}s"
                f_mm    = f"{fase_s  // 60}m{fase_s  % 60:02d}s"

                proc_info = ""
                try:
                    proc_info = self.shell.fetch_resources(s, pid)
                except Exception:
                    pass

                status_line = f"  - {current_fase}{progress}  [fase: {f_mm} | total: {t_mm}]"
                if proc_info:
                    status_line += f"  |  {proc_info}"
                print(status_line, flush=True)
                time.sleep(poll)

        except KeyboardInterrupt:
            print("", flush=True)
            _ts(f"[{self.id}] Ctrl+C - monitor desligado (processo remoto continua a correr).")
            return RC_DETACHED

    def _finish(self, raw_status: str) -> int:
        try:
            rc = int(raw_status)
        except ValueError:
            rc = 1
        label = "OK" if rc == 0 else f"FALHOU (exit {rc})"
        _ts(f"[{self.id}] concluído: {label}")
        self.action.save_meta(
            status="ok" if rc == 0 else "failed",
            finished_at=datetime.utcnow().isoformat(), exit_code=rc,
        )
        self.shell.remote_rm(self.server, (self.r_lock,), 10)
        return rc

    def stop(self) -> None:
        pid = ""
        try:
            pid = self.shell.remote_cat(self.server, self.r_pid, 5).strip()
        except Exception:
            pass
        if pid:
            try:
                self.shell.kill(self.server, pid)
                _ts(f"Processo remoto {pid} terminado.")
            except Exception as exc:
                _ts(f"[aviso] kill {pid}: {exc}")
        else:
            _ts("Processo remoto não encontrado (pode já ter terminado).")
        try:
            self.shell.remote_rm(self.server, (self.r_lock,), 3)
        except Exception:
            pass

    def is_running(self) -> bool:
        pid = self.shell.remote_cat(self.server, self.r_lock, 10).strip()
        if not pid:
            return False
        return self.shell.is_alive(self.server, pid, 10)

    def mark_running(self) -> None:
        self.shell.mark_running(self.server, self)

    def mark_finished(self, rc: int) -> None:
        self.shell.mark_finished(self.server, self, rc)

    def read_result_meta(self) -> dict:
        raw = self.shell.remote_cat(self.server, f"{self.remote_dir}/result_meta.txt", 10)
        meta = {}
        for line in raw.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                meta[k.strip()] = v.strip()
        return meta

    def fetch_cargo_log(self, target: str) -> str:
        remote  = f"{self.r_cargo}/{target}.log"
        content = self.shell.remote_cat(self.server, remote, 120)
        if not content:
            content = f"(log não encontrado: {remote})"
        self.local_cargo.mkdir(parents=True, exist_ok=True)
        local = self.local_cargo / f"{target}.log"
        local.write_text(content, "utf-8", errors="replace")
        return content

    @classmethod
    def list_remote(cls, server: Server, include_done: bool = True) -> list[dict]:
        shell = shell_for(server)
        rh    = shell.remote_home(server)
        temp  = f"{rh}/{cls.REMOTE_TEMP}"
        ops   = shell.list_remote(server, temp)
        if not include_done:
            ops = [o for o in ops if o["running"]]
        for o in ops:
            o["remote_dir"] = f"{temp}/{o['id']}"
        return ops

    @classmethod
    def attach(cls, server: Server, action_id: str) -> "RemoteOp":
        return cls(server, _action.parse_type(action_id), action_id=action_id)

    def __repr__(self) -> str:
        return f"RemoteOp(id={self.id!r}, type={self.op_type!r})"
