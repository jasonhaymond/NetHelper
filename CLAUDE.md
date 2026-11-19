# NetHelper - project notes for Claude

Cross-platform network troubleshooting CLI and menu in pure-stdlib Python
(3.11+). The global standards in ~/.claude/CLAUDE.md apply; this file adds
only project specifics.

## Start here
- Read docs/development.md first. It covers the layout, how to add a check, setting, command or menu item, the test commands, the `# nosec` table, and the list of paths NOT yet tested live.

## Code rules
- The runtime must stay standard-library only.
- Never import subprocess outside nethelper/core/cmd.py.
- Validate user input with core/validate.py, and destinations with core/destinations.parse.
- Check ids are permanent: baselines and verdict rules reference them.
- Mark bandwidth-heavy checks `exclusive=True`.

## Keeping things in sync
- The version lives in nethelper/__init__.py AND pyproject.toml. Bump both.
- **New setting:** add it to core/settings.py SPECS, then run `python scripts/gen_env_example.py` (a test enforces this).
- **New command:** add a helptext.COMMANDS entry with at least 2 examples (a test enforces this).
- **New menu item:** it must parse (a test enforces this).

## Running things
- **Tests:** `.venv\Scripts\python -m pytest`. Linux pass via WSL: `PYTHONPATH=.venv/Lib/site-packages python3 -m pytest` (dev guide §6).
- **Security suite:** `pwsh scripts/security-check.ps1` (reports go to security-reports/, which is gitignored).
- **Distribution:** no server or deployment. Distribute dist/nethelper.pyz from scripts/build.py.
