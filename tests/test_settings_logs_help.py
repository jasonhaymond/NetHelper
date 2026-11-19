"""
Tests for settings (.env), per-run logging/retention, the help system and the
menu definitions.
"""

from __future__ import annotations

import argparse
import logging
import shlex
from pathlib import Path

import pytest

from nethelper import cli, helptext, menu
from nethelper.core import logsetup
from nethelper.core import settings as st


def test_env_parse_precedence_and_invalid_values(tmp_path, monkeypatch):
    """.env values load; environment beats .env; invalid values fall back to the default with a reported problem."""
    env = tmp_path / ".env"
    env.write_text('# comment\nNETHELPER_TIMEOUT=7\nNETHELPER_COLOR = "never"\nNETHELPER_LOG_KEEP=abc\n'
                   "NETHELPER_TYPO=1\nexport NETHELPER_PING_COUNT=4 # trailing comment\n", encoding="utf-8")
    monkeypatch.setenv("NETHELPER_PING_COUNT", "25")
    s = st.load(str(env))
    assert s.get("NETHELPER_TIMEOUT") == 7.0 and s.source["NETHELPER_TIMEOUT"] == ".env"
    assert s.get("NETHELPER_COLOR") == "never"
    assert s.get("NETHELPER_PING_COUNT") == 25 and s.source["NETHELPER_PING_COUNT"] == "environment"
    assert s.get("NETHELPER_LOG_KEEP") == 40 and any("NETHELPER_LOG_KEEP" in p for p in s.problems)
    assert any("NETHELPER_TYPO" in p for p in s.problems)


def test_env_save_validates_backs_up_and_masks_secrets(tmp_path):
    """Saving refuses invalid values, keeps a .bak of the previous file, and secrets display masked."""
    env = tmp_path / ".env"
    values = st.current_file_values(env)
    values["NETHELPER_THROUGHPUT_KEY"] = "topsecret-key"
    assert st.save(env, values) is None
    values["NETHELPER_TIMEOUT"] = "5"
    backup = st.save(env, values)
    assert backup and backup.exists()
    with pytest.raises(ValueError):
        st.validate_value("NETHELPER_TIMEOUT", "999")
    with pytest.raises(ValueError):
        st.validate_value("NETHELPER_OUTPUT_DESTINATIONS", "gopher://x/y")
    s = st.load(str(env))
    assert s.display("NETHELPER_THROUGHPUT_KEY") == st.MASK and "topsecret-key" in s.secrets()


def test_env_example_is_in_sync():
    """.env.example documents exactly the current settings (regenerate with scripts/gen_env_example.py)."""
    example = (Path(__file__).parent.parent / ".env.example").read_text(encoding="utf-8")
    assert example == st.render({}, header="NetHelper settings - EXAMPLE (copy to your .env; see 'nethelper help settings')")


def test_run_logs_rotate_after_keep_count(tmp_path):
    """Only the newest NETHELPER_LOG_KEEP run logs survive (default 40)."""
    env = tmp_path / ".env"
    env.write_text(f"NETHELPER_LOG_DIR={tmp_path / 'logs'}\nNETHELPER_LOG_KEEP=5\n", encoding="utf-8")
    s = st.load(str(env))
    folder = tmp_path / "logs"
    folder.mkdir()
    for n in range(10):
        (folder / f"run-20260101-0000{n:02d}-000-p1-old.log").write_text("x", encoding="utf-8")
    path = logsetup.start_run("quick", [], s)
    logsetup.end_run(0)
    remaining = sorted(folder.glob("run-*.log"))
    assert len(remaining) == 5 and path in remaining


def test_run_log_masks_secrets_and_records_header(tmp_path):
    """A secret setting never appears in the log; the header and footer are written."""
    env = tmp_path / ".env"
    env.write_text(f"NETHELPER_LOG_DIR={tmp_path}\nNETHELPER_THROUGHPUT_KEY=SuperSecret123\n", encoding="utf-8")
    s = st.load(str(env))
    path = logsetup.start_run("serve", ["--key", "SuperSecret123"], s)
    logging.getLogger("nethelper.test").info("connecting with key SuperSecret123")
    logsetup.end_run(0)
    text = path.read_text(encoding="utf-8")
    assert "SuperSecret123" not in text and "********" in text
    assert "run started: serve" in text and "exit code 0" in text
    runs = logsetup.list_runs(tmp_path)
    assert runs[0]["command"] == "serve" and runs[0]["exit"] == "0"


def _example_argv(cmd: str) -> list[str]:
    """Split a help example command line into argv (dropping the program name)."""
    return shlex.split(cmd.replace("\\", "/"))[1:]


def test_every_command_has_help_with_examples_that_parse():
    """Every CLI command has a help page with >= 2 examples, and every example is valid syntax."""
    parser = cli.build_parser()
    subcommands = set(parser._subparsers._group_actions[0].choices)  # noqa: SLF001
    assert subcommands == set(helptext.COMMANDS), subcommands ^ set(helptext.COMMANDS)
    for name, info in helptext.COMMANDS.items():
        assert len(info["examples"]) >= 2, name
        for example, _ in info["examples"]:
            # Drop shell output redirection ("> file") - it's not part of NetHelper's arguments.
            argv = _example_argv(example.split(" > ")[0])
            parser.parse_args(argv)  # raises SystemExit on invalid syntax


def test_help_pages_render():
    """Overview, command and topic pages all render; unknown names return None."""
    assert "throughput" in helptext.overview()
    assert "Examples:" in helptext.command_page("wifi")
    assert "Standard user" in helptext.topic_page("elevation")
    assert helptext.lookup("nonsense") is None


def test_menu_items_build_valid_command_lines():
    """Every menu item's base command (with sample answers) parses - the menu can't offer a broken action."""
    parser = cli.build_parser()
    samples = {"text": "x", "host": "10.0.0.1", "target": "10.0.0.1", "url": "https://example.com", "int": "5",
               "float": "2", "file": "out.html", "yesno": None, "choice": None, "iface": "eth0", "ifaces": "eth0"}

    def walk(m):
        for entry in m.entries:
            if isinstance(entry, menu.Menu):
                yield from walk(entry)
            elif isinstance(entry, menu.Item):
                yield entry

    count = 0
    for item in walk(menu.build_tree()):
        argv = list(item.argv)
        for p in item.prompts:
            value = p.default if p.kind == "choice" else samples[p.kind]
            if p.kind == "yesno":
                if p.flag:
                    argv.append(p.flag)
                continue
            if p.flag == "-f" and p.kind == "host":
                value = f"host:{value}"
            if item.argv[0] == "dns" and p.kind == "text":
                value = "example.com"
            if item.argv[0] == "port" and p.kind == "text":
                value = "80,443"
            if item.argv[:1] == ["lan"] and p.flag == "--net":
                value = "10.0.0.0/24"
            argv += [p.flag, value] if p.flag else [value]
        parser.parse_args(argv)
        count += 1
    assert count > 40


def test_menu_prompt_validation(monkeypatch):
    """The menu re-asks on invalid input (bad host, out-of-range number) instead of passing it on."""
    answers = iter(["-bad host", "10.0.0.5"])
    monkeypatch.setattr("builtins.input", lambda *_: next(answers))
    con = cli.Console(color=False)
    assert menu.answer_prompt(con, menu.Prompt("Host", "host", "-s", required=True)) == ["-s", "10.0.0.5"]
    answers2 = iter(["99999", "50"])
    monkeypatch.setattr("builtins.input", lambda *_: next(answers2))
    assert menu.answer_prompt(con, menu.Prompt("Count", "int", "-c", lo=1, hi=1000)) == ["-c", "50"]


def test_cli_config_set_show_and_help(tmp_path, capsys, monkeypatch):
    """`config set` validates and saves; `config show` masks secrets; `help` prints pages."""
    env = tmp_path / ".env"
    assert cli.main(["config", "set", "NETHELPER_TIMEOUT", "6", "--env", str(env), "--no-color"]) == 0
    assert cli.main(["config", "set", "NETHELPER_TIMEOUT", "500", "--env", str(env), "--no-color"]) == 3
    assert cli.main(["config", "set", "NETHELPER_THROUGHPUT_KEY", "hunter22", "--env", str(env), "--no-color"]) == 0
    capsys.readouterr()
    assert cli.main(["config", "show", "--env", str(env), "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "NETHELPER_TIMEOUT" in out and "6" in out and "hunter22" not in out
    assert cli.main(["help", "throughput", "--no-color"]) == 0
    assert "nethelper throughput gateway" in capsys.readouterr().out
    assert cli.main(["help", "nope", "--no-color"]) == 3


def test_unexpected_errors_are_contained(monkeypatch, capsys):
    """An unexpected exception in a command gives exit code 4 and a friendly message, not a traceback."""
    def boom(args, con):
        raise RuntimeError("kaboom")
    monkeypatch.setitem(cli.HANDLERS, "caps", boom)
    code = cli.execute(argparse.Namespace(command="caps", no_color=True, json=False))
    assert code == 4 and "kaboom" in capsys.readouterr().err
