"""Log readers: one-shot replay and an EOF-following tail with rotation handling."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator


class ReplayReader:
    """Reads a saved audit log start to finish (tests, offline replay, Windows dev)."""

    def __init__(self, path):
        self.path = Path(path)

    def lines(self) -> Iterator[str]:
        with self.path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                yield line


class TailReader:
    """Follows a growing audit log; detects auditd rotation via inode change."""

    def __init__(self, path, *, from_start: bool = False):
        self.path = Path(path)
        self._handle = None
        self._inode: int | None = None
        self._open_at_end = not from_start

    def _open(self, *, at_end: bool) -> None:
        handle = self.path.open("r", encoding="utf-8", errors="replace")
        if at_end:
            handle.seek(0, os.SEEK_END)
        self._handle = handle
        self._inode = os.fstat(handle.fileno()).st_ino

    def poll(self) -> list[str]:
        if self._handle is None:
            self._open(at_end=self._open_at_end)
            self._open_at_end = False  # only the very first open honours from_start
        else:
            self._check_rotation()
        lines: list[str] = []
        while True:
            position = self._handle.tell()
            line = self._handle.readline()
            if not line:
                break
            if not line.endswith("\n"):
                self._handle.seek(position)  # half-written line: wait for the rest
                break
            lines.append(line)
        return lines

    def _check_rotation(self) -> None:
        try:
            stat = os.stat(self.path)
        except OSError:
            return
        if stat.st_ino != self._inode:
            self.close()
            self._open(at_end=False)  # read the fresh log from its beginning
        elif stat.st_size < self._handle.tell():
            self._handle.seek(0)  # truncate-in-place (rare)

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None