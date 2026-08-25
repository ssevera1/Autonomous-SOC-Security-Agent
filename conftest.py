"""Make the repository root importable so tests can `import threat_hunter`.

CI runs bare `pytest -q` (.github/workflows/ci.yml), which - unlike
`python -m pytest` - does not put the invocation directory on sys.path, and the
package is not pip-installed. Prepending explicitly here keeps the tests working
regardless of pytest's import mode.
"""

import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
