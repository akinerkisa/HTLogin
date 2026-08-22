# Changelog

## Unreleased

- Added passive `--safe-mode` for form inspection without active probes.
- Added a per-target request budget with `--max-requests`.
- Added `pyproject.toml`, development dependencies, CI, packaging checks, and
  security/contribution guidance.
- Fixed the default pytest configuration so coverage is opt-in in local runs.
- Added Windows console encoding fallback and fixed `--rate-limit 0` so the
  rate-limit audit can be disabled as documented.
