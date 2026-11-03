from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def rules():
    from phpscan.rules import load_rules

    return load_rules()


