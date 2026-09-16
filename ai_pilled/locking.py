"""Bounded cooperative locks; contention never removes another owner's lock."""
import fcntl
import time

from .runtime import CommandUnavailable

LOCK_TIMEOUT = 2.0


def acquire_lock(stream, mode):
    deadline = time.monotonic() + LOCK_TIMEOUT
    while True:
        try:
            fcntl.flock(stream, mode | fcntl.LOCK_NB)
            return
        except BlockingIOError as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CommandUnavailable('Local state lock is busy; retry after the other operation finishes') from exc
            time.sleep(min(0.05, remaining))
