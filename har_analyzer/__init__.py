from __future__ import annotations

from pathlib import Path


_SRC_PACKAGE = Path(__file__).resolve().parent.parent / "src" / "har_analyzer"
__path__ = [str(_SRC_PACKAGE)]

from .graph import run_scan
from .models import RunConfig

__all__ = ["RunConfig", "run_scan"]
