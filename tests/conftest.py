from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def raw_sample_path() -> Path:
    """Día sintético con la cabecera real (generado por fixtures/make_raw_sample.py)."""
    return FIXTURES / "raw_day_sample.csv"
