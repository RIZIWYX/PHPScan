import re
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
EXPECT = re.compile(r"EXPECT:\s*([A-Z0-9\-]+)")


@pytest.fixture(scope="session")
def rules():
    from phpscan.rules import load_rules

    return load_rules()


def expected(path: Path) -> set[tuple[int, str]]:
    out = set()
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        for rid in EXPECT.findall(line):
            out.add((i, rid))
    return out
