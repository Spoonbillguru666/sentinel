# Contributing to sentinel

Thank you for your interest in contributing to sentinel!

## Development Setup

```bash
git clone https://github.com/Helixar-AI/sentinel
cd sentinel
pip install -e ".[dev]"
```

## Branching Strategy

```
main          ← production-ready releases only. Protected.
  └── develop ← integration branch. All features merge here first.
        ├── feature/add-kubernetes-checks
        └── fix/false-positive-cfg-007
```

- All changes go through PRs to `develop`
- `main` only receives PRs from `develop`
- CI must pass before merging

## Adding a New Rule

Rules are defined in `sentinel/rules/rules.yaml` as data — no Python required for the rule definition itself.

**Step 1 — Add to `sentinel/rules/rules.yaml`:**

```yaml
- id: CFG-011
  module: config
  severity: HIGH
  check_key: no_egress_filter
  title: No egress filtering configuration found
  rationale: Without egress filtering, MCP tools can make arbitrary outbound connections.
  remediation: Add an egress_filter block specifying allowed outbound destinations.
  reference: net-003
```

Fields:
- `id` — unique rule ID (format: `MOD-NNN`)
- `module` — one of `config`, `probe`, `container`
- `severity` — `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`
- `check_key` — unique snake_case key used in scanner code
- `title` — short, action-oriented description
- `rationale` — why this matters
- `remediation` — how to fix it
- `reference` — checklist.helixar.ai control ID (optional)

**Step 2 — Add detection logic:**

In the relevant `sentinel/modules/*.py` file, add a `_check_<key>` method and call it from `scan()`:

```python
def _check_egress_filter(self, config: dict, result: ScanResult, path: Path) -> None:
    has_egress = any(
        _get_nested(config, k) is not None
        for k in ("egress_filter", "egress", "outbound_filter")
    )
    if not has_egress:
        f = self._make_finding("no_egress_filter", str(path), "No egress filter found.")
        if f:
            result.add_finding(f)
```

**Step 3 — Add tests:**

```python
def test_no_egress_filter_detected(self):
    path = write_json({})
    result = self.scanner.scan(path)
    assert "CFG-011" in self.ids(result)

def test_egress_filter_present_no_cfg011(self):
    path = write_json({"egress_filter": {"allow": ["api.example.com"]}})
    result = self.scanner.scan(path)
    assert "CFG-011" not in self.ids(result)
```

## Running Tests

```bash
python -m pytest tests/unit/ -v
python -m pytest tests/unit/ --cov=sentinel --cov-report=term-missing
```

## Code Style

```bash
ruff check sentinel/ tests/
ruff format sentinel/ tests/
```

## Submitting a PR

1. Fork the repo
2. Create a branch: `feature/my-new-rule` or `fix/cfg-007-false-positive`
3. Make your changes with tests
4. Ensure `pytest` passes and `ruff check` is clean
5. Open a PR against `develop`

## Reporting Security Issues

Please do not open public issues for security vulnerabilities. Email security@helixar.ai instead.
