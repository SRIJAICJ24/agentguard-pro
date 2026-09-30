"""Stage 5 - onboarding, doctor, configure, daemon registration.

The required behaviours: `doctor` reports failure on a malformed config and on a
tampered audit chain, and `onboard` produces a config that `status` can then read.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from agentguard import config as cfg
from agentguard import doctor
from agentguard.config import MODE_ENFORCE, MODE_OBSERVE, Config, ConfigError


@pytest.fixture
def home(monkeypatch):
    """An isolated AGENTGUARD_HOME per test."""
    directory = tempfile.mkdtemp(prefix="agentguard-home-")
    monkeypatch.setenv("AGENTGUARD_HOME", directory)
    try:
        yield Path(directory)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture
def workdir():
    """A scratch directory to write a starter policy into."""
    directory = tempfile.mkdtemp(prefix="agentguard-work-")
    try:
        yield Path(directory)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def answers(*values: str):
    """An input_fn that replays scripted answers, then falls back to defaults."""
    queue = list(values)

    def _input(_prompt: str) -> str:
        return queue.pop(0) if queue else ""

    return _input


# =====================================================================
# config
# =====================================================================
def test_config_round_trips(home):
    original = Config(mode=MODE_ENFORCE, port=9500, dashboard=False)
    cfg.save(original)
    loaded = cfg.load()
    assert loaded.mode == MODE_ENFORCE
    assert loaded.port == 9500
    assert loaded.dashboard is False
    assert loaded.enforcement is True


def test_missing_config_returns_defaults_not_an_error(home):
    assert not cfg.exists()
    config = cfg.load()
    assert config.mode == MODE_OBSERVE
    assert config.enforcement is False


@pytest.mark.parametrize("body", [
    "{ not json",
    "",
    "[1, 2, 3]",
])
def test_malformed_config_raises(home, body):
    cfg.config_path().parent.mkdir(parents=True, exist_ok=True)
    cfg.config_path().write_text(body, encoding="utf-8")
    with pytest.raises(ConfigError):
        cfg.load()


def test_invalid_values_are_rejected(home):
    cfg.config_path().parent.mkdir(parents=True, exist_ok=True)
    cfg.config_path().write_text(json.dumps({"mode": "yolo", "port": 99999}),
                                 encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        cfg.load()
    assert "mode" in str(exc.value)


def test_colliding_ports_are_rejected(home):
    bad = Config(port=9000, dashboard=True, dashboard_port=9000)
    assert bad.validate()
    with pytest.raises(ConfigError):
        cfg.save(bad)


def test_unknown_keys_are_ignored_for_forward_compatibility(home):
    cfg.config_path().parent.mkdir(parents=True, exist_ok=True)
    cfg.config_path().write_text(
        json.dumps({"mode": "observe", "port": 9000, "future_setting": "whatever"}),
        encoding="utf-8",
    )
    assert cfg.load().port == 9000       # loads rather than bricking the install


# =====================================================================
# doctor - the two required failure cases
# =====================================================================
def test_doctor_reports_failure_on_malformed_config(home):
    cfg.config_path().parent.mkdir(parents=True, exist_ok=True)
    cfg.config_path().write_text("{ this is not valid json", encoding="utf-8")

    report = doctor.run()
    assert not report.ok
    config_check = next(r for r in report.results if r.name == "config file")
    assert config_check.status == doctor.STATUS_FAIL
    assert "JSON" in config_check.detail or "json" in config_check.detail
    assert config_check.hint, "a failure must say what to do next"


def test_doctor_reports_failure_on_tampered_audit_chain(home):
    from agentguard import audit
    from agentguard.db import connect
    from agentguard.decision import Decision, Verdict

    cfg.save(Config())
    for i in range(3):
        audit.record(stage="TOOL_PREPARE", tool=f"t{i}", arguments={"i": i},
                     decision=Decision(Verdict.ALLOW, 0.0), session_id="s")
    assert doctor.run().ok, "control: a clean install must pass"

    conn = connect()
    conn.execute("UPDATE audit SET reason='edited' WHERE id=2")
    conn.commit()

    report = doctor.run()
    assert not report.ok
    chain = next(r for r in report.results if r.name == "audit chain")
    assert chain.status == doctor.STATUS_FAIL
    assert "row 2" in chain.detail


def test_doctor_passes_on_a_healthy_install(home):
    cfg.save(Config())
    report = doctor.run()
    assert report.ok
    assert not report.failures


def test_doctor_warns_rather_than_fails_when_not_yet_onboarded(home):
    report = doctor.run()
    config_check = next(r for r in report.results if r.name == "config file")
    assert config_check.status == doctor.STATUS_WARN
    assert report.ok, "a fresh install is usable, not broken"


def test_doctor_detects_an_unparseable_policy(home, workdir):
    bad = workdir / "broken.policy.yaml"
    bad.write_text("roles:\n  coder:\n   allow: [unclosed\n", encoding="utf-8")
    result = doctor.check_policy(bad)
    assert result.status == doctor.STATUS_FAIL
    assert "parse" in result.detail


def test_doctor_detects_a_busy_port(home):
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        busy_port = sock.getsockname()[1]
        result = doctor.check_port(busy_port)
    # The socket above answers nothing on /mcp, so this is a genuine conflict.
    assert result.status == doctor.STATUS_FAIL
    assert str(busy_port) in result.detail


def test_doctor_report_serialises(home):
    cfg.save(Config())
    data = doctor.run().to_dict()
    assert set(data) == {"ok", "checks"}
    assert all({"name", "status", "detail", "hint"} <= set(c) for c in data["checks"])


def test_doctor_render_is_readable(home):
    cfg.save(Config())
    text = doctor.render(doctor.run())
    assert "PASS" in text
    assert "audit chain" in text


# =====================================================================
# onboarding - the required round trip
# =====================================================================
def test_onboard_produces_a_config_that_status_can_read(home, workdir, capsys):
    from agentguard.cli import main
    from agentguard.onboarding import onboard

    onboard(input_fn=answers("enforce", "9500", "y", "9501"), policy_dir=workdir)

    # The required assertion: `status` reads it back without error.
    assert main(["status"]) == 0
    out = capsys.readouterr().out
    assert "9500" in out
    assert str(cfg.config_path()) in out

    saved = cfg.load()
    assert saved.mode == MODE_ENFORCE
    assert saved.port == 9500
    assert saved.dashboard_port == 9501


def test_onboard_defaults_are_safe_when_everything_is_skipped(home, workdir):
    from agentguard.onboarding import onboard

    config = onboard(input_fn=answers(), policy_dir=workdir)
    assert config.mode == MODE_OBSERVE, "holding Enter must not enable blocking"
    assert config.enforcement is False


def test_onboard_writes_a_starter_policy(home, workdir):
    from agentguard.onboarding import onboard
    from agentguard.policy import load as load_policy

    onboard(input_fn=answers(), policy_dir=workdir)
    policy_file = workdir / "agentguard.policy.yaml"
    assert policy_file.is_file()

    policy = load_policy(policy_file)
    assert policy.enforcement is False
    assert "coder" in policy.roles


def test_onboard_never_overwrites_an_existing_policy(home, workdir):
    from agentguard.onboarding import onboard

    existing = workdir / "agentguard.policy.yaml"
    existing.write_text("enforcement: true  # hand written\n", encoding="utf-8")
    onboard(input_fn=answers(), policy_dir=workdir)
    assert "hand written" in existing.read_text(encoding="utf-8")


def test_onboard_repairs_a_port_collision(home, workdir):
    from agentguard.onboarding import onboard

    # Same port for gateway and dashboard.
    config = onboard(input_fn=answers("observe", "9000", "y", "9000"), policy_dir=workdir)
    assert config.port != config.dashboard_port
    assert not config.validate()


def test_onboard_over_a_malformed_config_still_works(home, workdir):
    from agentguard.onboarding import onboard

    cfg.config_path().parent.mkdir(parents=True, exist_ok=True)
    cfg.config_path().write_text("{ broken", encoding="utf-8")
    onboard(input_fn=answers(), policy_dir=workdir)
    assert cfg.load().port == cfg.DEFAULT_PORT


def test_onboard_rejects_a_nonsense_port_then_accepts_a_good_one(home, workdir):
    from agentguard.onboarding import onboard

    config = onboard(input_fn=answers("observe", "not-a-port", "70000", "9300", "n"),
                     policy_dir=workdir)
    assert config.port == 9300


# =====================================================================
# configure
# =====================================================================
def test_configure_changes_one_setting(home):
    from agentguard.onboarding import configure

    cfg.save(Config(port=9000))
    configure("port", "9700")
    assert cfg.load().port == 9700
    assert cfg.load().mode == MODE_OBSERVE, "other settings must be untouched"


def test_configure_mode(home):
    from agentguard.onboarding import configure

    cfg.save(Config())
    configure("mode", "enforce")
    assert cfg.load().enforcement is True


def test_configure_rejects_an_unknown_setting(home):
    from agentguard.onboarding import configure

    cfg.save(Config())
    with pytest.raises(ConfigError):
        configure("colour", "blue")


def test_configure_rejects_a_value_that_would_break_the_config(home):
    from agentguard.onboarding import configure

    cfg.save(Config(port=9000, dashboard=True, dashboard_port=9001))
    with pytest.raises(ConfigError):
        configure("dashboard_port", "9000")     # would collide with the gateway
    assert cfg.load().dashboard_port == 9001, "a rejected change must not be saved"


def test_configure_on_a_malformed_config_explains_the_fix(home):
    from agentguard.onboarding import configure

    cfg.config_path().parent.mkdir(parents=True, exist_ok=True)
    cfg.config_path().write_text("{ broken", encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        configure("port", "9000")
    assert "onboard" in str(exc.value)


# =====================================================================
# daemon registration
# =====================================================================
@pytest.mark.parametrize("system,expected", [
    ("linux", "agentguard.service"),
    ("darwin", "com.agentguard.gateway.plist"),
    ("windows", "agentguard-daemon.cmd"),
])
def test_daemon_plan_per_platform(home, workdir, system, expected):
    from agentguard.onboarding import build_daemon_plan

    plan = build_daemon_plan(Config(port=9000), system=system, home=workdir)
    assert plan.path.name == expected
    assert plan.content.strip()
    assert plan.activate_cmd


def test_daemon_plan_includes_enforcement_flag_only_when_enforcing(home, workdir):
    from agentguard.onboarding import build_daemon_plan

    observing = build_daemon_plan(Config(mode=MODE_OBSERVE), system="linux", home=workdir)
    enforcing = build_daemon_plan(Config(mode=MODE_ENFORCE), system="linux", home=workdir)
    assert "--enforce" not in observing.content
    assert "--enforce" in enforcing.content


def test_daemon_handles_an_interpreter_path_containing_spaces(home, workdir, monkeypatch):
    """Regression guard: splitting a joined command string corrupted such paths."""
    from agentguard import onboarding

    spaced = r"C:\Program Files\Py\python.exe"
    monkeypatch.setattr(onboarding, "_console_parts",
                        lambda: [spaced, "-m", "agentguard.cli"])

    linux = onboarding.build_daemon_plan(Config(), system="linux", home=workdir)
    assert f'"{spaced}"' in linux.content        # quoted for a shell-style line

    darwin = onboarding.build_daemon_plan(Config(), system="darwin", home=workdir)
    assert f"<string>{spaced}</string>" in darwin.content   # one argv element


def test_install_daemon_writes_but_does_not_activate(home, workdir):
    """Installing must not silently start a service that intercepts tool calls."""
    from agentguard.onboarding import install_daemon

    plan = install_daemon(Config(), system="linux", home=workdir, activate=False)
    assert plan.path.is_file()
    assert plan.path.read_text(encoding="utf-8") == plan.content
    assert "systemctl" in plan.activate_display


def test_unsupported_platform_explains_the_manual_route(home, workdir):
    from agentguard.onboarding import build_daemon_plan

    with pytest.raises(RuntimeError) as exc:
        build_daemon_plan(Config(), system="plan9", home=workdir)
    assert "manually" in str(exc.value)


# =====================================================================
# enforcement precedence
# =====================================================================
def test_enforcement_precedence(home):
    """Flags beat the config; the config beats the policy file."""
    import argparse

    from agentguard.cli import resolve_enforcement

    cfg.save(Config(mode=MODE_OBSERVE))

    flag_on = argparse.Namespace(enforce=True, observe=False)
    assert resolve_enforcement(flag_on)[0] is True

    flag_off = argparse.Namespace(enforce=False, observe=True)
    assert resolve_enforcement(flag_off)[0] is False

    from_config = argparse.Namespace(enforce=False, observe=False)
    assert resolve_enforcement(from_config)[0] is False

    cfg.save(Config(mode=MODE_ENFORCE))
    assert resolve_enforcement(from_config)[0] is True


def test_enforcement_falls_through_to_policy_without_a_config(home):
    import argparse

    from agentguard.cli import resolve_enforcement

    verdict, source = resolve_enforcement(argparse.Namespace(enforce=False, observe=False))
    assert verdict is None, "None lets the policy file decide"
    assert "policy" in source


# =====================================================================
# CLI wiring
# =====================================================================
def test_cli_doctor_exit_codes(home, capsys):
    from agentguard.cli import main

    cfg.save(Config())
    assert main(["doctor"]) == 0

    cfg.config_path().write_text("{ broken", encoding="utf-8")
    assert main(["doctor"]) == 1, "doctor must exit non-zero when a check fails"


def test_cli_doctor_json_output(home, capsys):
    from agentguard.cli import main

    cfg.save(Config())
    main(["doctor", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True


def test_cli_onboard_non_interactive(home, workdir, monkeypatch, capsys):
    from agentguard.cli import main

    monkeypatch.chdir(workdir)
    assert main(["onboard", "--non-interactive"]) == 0
    assert cfg.exists()
    assert (workdir / "agentguard.policy.yaml").is_file()


def test_cli_configure_reports_failure(home, capsys):
    from agentguard.cli import main

    cfg.save(Config())
    assert main(["configure", "colour", "blue"]) == 1
    assert "failed" in capsys.readouterr().err


def test_daemon_command_parses_without_an_upstream(home, workdir):
    """Regression: with no upstream configured (someone who uses no MCP servers),
    the generated service ran `proxy --port N`, but `proxy` required --upstream, so
    the background service would exit immediately on every start."""
    from agentguard.cli import build_parser
    from agentguard.onboarding import _gateway_args

    args = build_parser().parse_args(_gateway_args(Config(port=9000)))
    assert args.cmd == "proxy" and args.upstream is None and args.port == 9000


def test_windows_launcher_has_plain_crlf_line_endings(home, workdir):
    """Regression: the launcher was built with \r\n and then written in text mode,
    which on Windows turned every line ending into \r\r\n - a stray carriage return
    that cmd.exe can read as part of `goto loop`."""
    from agentguard.onboarding import install_daemon

    plan = install_daemon(Config(port=9000), system="windows", home=workdir)
    for path in [plan.path, *(plan.extra_files or {})]:
        raw = path.read_bytes()
        assert b"\r\r\n" not in raw, path.name
        assert raw.count(b"\r\n") == raw.count(b"\n"), f"{path.name}: every newline is CRLF"


def test_background_daemon_is_pointed_at_the_policy_file(home, workdir, monkeypatch):
    """Regression: the service starts outside the project folder (Task Scheduler,
    systemd, launchd), where the upward policy search finds nothing, so it silently
    ran on built-in defaults and ignored edits to agentguard.policy.yaml. Onboarding
    now records the policy path and the service passes it explicitly."""
    from agentguard.cli import build_parser
    from agentguard.onboarding import _gateway_args, onboard

    monkeypatch.chdir(workdir)
    config = onboard(non_interactive=True, policy_dir=workdir)
    expected = str((workdir / "agentguard.policy.yaml").resolve())
    assert config.policy_file == expected
    assert cfg.load().policy_file == expected

    args = build_parser().parse_args(_gateway_args(config))
    assert args.policy == expected and args.cmd == "proxy"
