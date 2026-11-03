from __future__ import annotations

import pytest

from securelib.log import get_logger


def test_component_prefix(capsys: pytest.CaptureFixture[str]) -> None:
    get_logger("test-component").info("epoch=1 seq=2 hello")
    assert capsys.readouterr().out == "[test-component] epoch=1 seq=2 hello\n"
