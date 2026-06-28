from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT_BOOTSTRAP = str(Path(__file__).resolve().parent.parent.parent)
if _REPO_ROOT_BOOTSTRAP not in sys.path:
    sys.path.insert(0, _REPO_ROOT_BOOTSTRAP)

from Build.core.job import CheckJob, ReleaseJob, TestsJob, build_config_for
from Build.core.server import make_server
from Build.core.target import ProfileStore, TargetRegistry
from Build.cli import platform_data as pdata
from Build.cli.menu import Config, ENV_FILE, PROFILES_JSON

_OPS = ("check", "tests", "release")

_CHECK_FEATURES = {
    "none":    ["core"],
    "console": ["console"],
    "gui":     ["gui"],
    "wasm":    ["extension"],
    "all":     None,
}

def main(argv: list[str]) -> int:
    if not argv or argv[0] not in _OPS:
        print(f"Uso: python Build/cli/run_direct.py {{{'|'.join(_OPS)}}} [feature]", file=sys.stderr)
        print(f"  feature (só para 'check'): {', '.join(_CHECK_FEATURES)}  (default: all)", file=sys.stderr)
        return 2

    op = argv[0]

    variant_filter: list[str] | None = None
    if op == "check":
        feature = argv[1] if len(argv) > 1 else "all"
        if feature not in _CHECK_FEATURES:
            print(f"Feature desconhecida: {feature!r}  (válidas: {', '.join(_CHECK_FEATURES)})", file=sys.stderr)
            return 2
        variant_filter = _CHECK_FEATURES[feature]
    elif len(argv) > 1:
        print(f"'{op}' não aceita argumentos extra.", file=sys.stderr)
        return 2

    config = Config(ENV_FILE)
    profile = config.server()
    registry = TargetRegistry()
    server = make_server(config)

    print(f"Servidor activo: {profile.label}  |  Perfil: {config.profile_name()}  |  Operação: {op}")

    if op == "check":
        env = pdata.check_tests_env(profile.os)
        return CheckJob(
            server, env, registry, config.build_jobs(), config.build_release(),
            variant_filter=variant_filter,
        ).run(f"check-{profile.os}")

    if op == "tests":
        env = pdata.check_tests_env(profile.os)
        store = ProfileStore(registry, PROFILES_JSON)
        profile_name = config.profile_name()
        triples = store.triples_for(profile_name)
        return TestsJob(server, env, registry).run(f"tests-{profile.os}", triples, profile_name)

    # op == "release"
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
    print(f"Zip: {zip_path or '(nenhum - ver mensagens acima)'}")
    return 0 if zip_path else 1

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
