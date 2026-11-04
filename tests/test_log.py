from __future__ import annotations

import pytest

from securelib.log import TAIL, LogTail, get_logger


def test_component_prefix(capsys: pytest.CaptureFixture[str]) -> None:
    get_logger("test-component").info("epoch=1 seq=2 hello")
    assert capsys.readouterr().out == "[test-component] epoch=1 seq=2 hello\n"


def test_lines_are_kept_for_the_terminal_page() -> None:
    get_logger("tail-test").info("seq=7 accepted")
    assert TAIL.after(0)[-1]["line"] == "[tail-test] seq=7 accepted"


def test_tail_after_and_restart() -> None:
    tail = LogTail(maxlen=3)
    for i in range(5):
        tail.add(f"line {i}")
    assert [x["line"] for x in tail.after(0)] == ["line 2", "line 3", "line 4"]
    assert [x["line"] for x in tail.after(4)] == ["line 4"]
    assert tail.after(5) == []
    # a reader ahead of us saw an earlier run of the process: give it everything
    assert len(tail.after(99)) == 3
