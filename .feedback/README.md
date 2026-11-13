# Feedback task starting environment

Upstream: https://github.com/fox-it/dissect.fat
Upstream commit: `640424d5d0837280e7f1553b7247f99321fbc5c9`
Prepared on macOS with the Python version recorded in the environment plan. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests
```

Scope note: Complete offline upstream test scope specified by argv.

Observed baseline (2026-11-13): `8 passed in 0.50s`
Whole-command wall time: 0.849 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
