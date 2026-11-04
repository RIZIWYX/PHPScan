import re
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def rules():
    from phpscan.rules import load_rules

    return load_rules()




EXPECT = re.compile(r"EXPECT:\s*([A-Z0-9\-]+)")


def expected(path: Path) -> set[tuple[int, str]]:
    """(ligne, règle) attendues dans un fichier de test, marquées par `EXPECT: <règle>`."""
    out: set[tuple[int, str]] = set()
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        out.update((i, rid) for rid in EXPECT.findall(line))
    return out
