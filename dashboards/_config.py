"""
Shared config loader pentru toate dashboards/*/build.py.

Citește din `.env` (la repo root) → fallback la os.environ → eroare clară dacă
variabile required lipsesc. Niciun secret/IP nu e hardcoded — toate trec prin
acest loader.

Folosire în build.py:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from _config import KIBANA_URL, DATA_VIEW_ID, DATA_VIEW_ECS_ID
"""

import os
import sys
from pathlib import Path


def _find_repo_root(start: Path) -> Path:
    """Urcă în arbore până găsește .env / .env.example / .git."""
    for parent in [start] + list(start.parents):
        if any((parent / marker).exists() for marker in (".env", ".env.example", ".git")):
            return parent
    return start


def _load_env_file(path: Path) -> None:
    """Parsează un .env shell-style și pune valorile în os.environ (fără să suprascrie)."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)


_REPO_ROOT = _find_repo_root(Path(__file__).resolve())
_load_env_file(_REPO_ROOT / ".env")


def _required(name: str) -> str:
    v = os.environ.get(name)
    if not v or v.startswith("00000000-"):
        sys.stderr.write(
            f"\nERROR: env var '{name}' is not set (or has placeholder value).\n"
            f"Setup: cp {_REPO_ROOT}/.env.example {_REPO_ROOT}/.env  "
            f"(then edit values).\n\n"
        )
        sys.exit(1)
    return v


KIBANA_URL       = _required("KIBANA_URL")
DATA_VIEW_ID     = _required("KIBANA_DATA_VIEW_ID")
DATA_VIEW_ECS_ID = _required("KIBANA_DATA_VIEW_ECS_ID")
