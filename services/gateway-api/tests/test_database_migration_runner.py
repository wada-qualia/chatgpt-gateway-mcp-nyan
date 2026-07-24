from __future__ import annotations

import importlib.util
import sys
from argparse import Namespace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
RUNNER_PATH = ROOT / "deploy" / "apply-database-migrations.py"
DEPLOY_PATH = ROOT / "deploy" / "deploy-blue-green.sh"


def load_runner():
    spec = importlib.util.spec_from_file_location(
        "gateway_database_migrations", RUNNER_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_migration_manifest_is_contiguous_and_checksum_bound() -> None:
    runner = load_runner()
    migrations = runner.discover_migrations(ROOT)

    assert [migration.version for migration in migrations] == list(
        range(1, len(migrations) + 1)
    )
    assert migrations[-1].filename == "006_mcp_chatgpt_projections.sql"
    assert all(len(migration.checksum_sha256) == 64 for migration in migrations)

    script = runner.build_psql_script(
        migrations, revision="a" * 40, baseline_version=None
    )
    assert f"pg_advisory_lock({runner.LOCK_KEY})" in script
    assert "CREATE TABLE IF NOT EXISTS gateway_schema_migrations" in script
    assert "migration checksum mismatch" in script
    for migration in migrations:
        assert migration.filename in script
        assert migration.checksum_sha256 in script
        assert migration.sql.rstrip() in script


def test_existing_schema_without_ledger_requires_explicit_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = load_runner()
    args = Namespace(
        release_root=ROOT,
        revision="b" * 40,
        postgres_container="postgres",
        db_user="gateway",
        db_name="gateway",
        baseline_existing=None,
    )
    monkeypatch.setattr(runner, "parse_args", lambda: args)
    monkeypatch.setattr(runner, "ledger_exists", lambda _args: False)
    monkeypatch.setattr(runner, "schema_is_empty", lambda _args: False)

    with pytest.raises(RuntimeError, match="Existing schema has no migration ledger"):
        runner.main()


def test_explicit_baseline_records_existing_versions_without_reexecution() -> None:
    runner = load_runner()
    migrations = runner.discover_migrations(ROOT)

    script = runner.build_psql_script(migrations, revision="c" * 40, baseline_version=6)

    assert script.count("baselining migration") == 6
    assert "execution_mode) VALUES (1" in script
    assert "'baseline'" in script
    assert "CREATE TABLE mcp_credential_bindings" not in script


def test_deploy_applies_migrations_after_backup_before_candidate_start() -> None:
    deploy = DEPLOY_PATH.read_text(encoding="utf-8")
    prepare = deploy[
        deploy.index("prepare_operation()") : deploy.index(
            "restart_candidate_operation()"
        )
    ]

    assert RUNNER_PATH.is_file()
    assert RUNNER_PATH.stat().st_mode & 0o111
    assert "GATEWAY_DB_MIGRATION_BASELINE_VERSION" in deploy
    assert prepare.index("create_backup") < prepare.index("apply_database_migrations")
    assert prepare.index("apply_database_migrations") < prepare.index(
        "starting inactive slot"
    )
