# Contributing

Thanks for considering a contribution to ASIF (Agent Security Intelligence Framework).

## Reporting bugs / suggesting features

Use [GitHub Issues](https://github.com/Mavchris/Agent_Security_Framework/issues). Include the command you ran and, for bugs, the actual vs. expected output.

## Submitting a pull request

```bash
git clone https://github.com/YOUR_FORK/Agent_Security_Framework.git
cd Agent_Security_Framework
python -m venv .venv && source .venv/Scripts/activate  # or .venv\Scripts\Activate.ps1 on Windows
pip install -r requirements.txt
git checkout -b feature/my-feature
# make your changes
pip install pytest  # not currently pinned in requirements.txt
python -m pytest tests/
git push origin feature/my-feature
```

Open a pull request against `main` with a short description of what changed and why.

## Code style

- Match the existing style of the module you're editing rather than introducing a new one (the codebase currently mixes `print()`-based and `logging`-based modules — prefer `logging` in new code).
- Keep functions focused; several existing functions (e.g. `pipeline/process.py`'s `run_pipeline()`) are known to do too much at once and are on the cleanup list rather than a pattern to copy.
- SQL queries must use parameterized placeholders (`?`), never string interpolation — this is consistently followed today and should stay that way.

## Known limitations worth knowing before you dig in

See the [Known Limitations](README.md#known-limitations) section of the README — it's an honest, current list (test coverage, automation track record, unwired scrapers) rather than something scattered across issues.
