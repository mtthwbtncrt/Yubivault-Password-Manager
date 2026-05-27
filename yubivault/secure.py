"""Best-effort secure memory for secrets in a Python process.

Honest caveat: Python's `bytes` is immutable and any operation can produce
copies the runtime owns; this module CANNOT guarantee a secret is purged
from the heap. What it gives us:

- A mutable backing bytearray we can overwrite with zeros on exit.
- `VirtualLock` (Windows) / `mlock` (POSIX) to prevent the page from being
  swapped to disk.
- A context manager that ensures wipe() runs even on exception.

Treat this as defence-in-depth, not as a guarantee.
"""

from __future__ import annotations

import ctypes
import sys
from typing import Any

_IS_WIN = sys.platform == "win32"


def _try_lock(buf: bytearray) -> bool:
    if _IS_WIN:
        try:
            kernel32 = ctypes.windll.kernel32
            ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
            return bool(kernel32.VirtualLock(ctypes.byref(ptr), len(buf)))
        except (OSError, AttributeError):
            return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
        return libc.mlock(ctypes.byref(ptr), len(buf)) == 0
    except (OSError, AttributeError):
        return False


def _try_unlock(buf: bytearray) -> None:
    try:
        if _IS_WIN:
            kernel32 = ctypes.windll.kernel32
            ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
            kernel32.VirtualUnlock(ctypes.byref(ptr), len(buf))
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
            libc.munlock(ctypes.byref(ptr), len(buf))
    except (OSError, AttributeError):
        pass


def wipe(buf: bytearray) -> None:
    """Overwrite a bytearray with zeros in place."""
    for i in range(len(buf)):
        buf[i] = 0


class Secret:
    """Wraps secret bytes in a bytearray that can be wiped and is page-locked.

    Implements the buffer protocol so it can be passed where bytes-like
    is expected (cffi-backed crypto calls in pynacl and cryptography accept
    this without making an immutable copy).

    Usage:
        with Secret(b"...") as s:
            do_crypto(s)   # passes the bytearray directly
        # s is now zeroed
    """

    __slots__ = ("_buf", "_locked", "_wiped")

    def __init__(self, data: bytes | bytearray):
        self._buf = bytearray(data)
        self._locked = _try_lock(self._buf)
        self._wiped = False

    # Bytes-like protocol --------------------------------------------------

    def __len__(self) -> int:
        return len(self._buf)

    def __bytes__(self) -> bytes:
        # Last resort: caller wants an immutable copy. Doc'd as such.
        return bytes(self._buf)

    def __buffer__(self, flags) -> memoryview:
        return memoryview(self._buf)

    def __release_buffer__(self, view: memoryview) -> None:
        view.release()

    # The crypto libs we use call cffi which accepts bytearray directly via
    # the buffer protocol, so we expose the bytearray for that path.
    @property
    def view(self) -> bytearray:
        return self._buf

    # Lifecycle ------------------------------------------------------------

    def wipe(self) -> None:
        if self._wiped:
            return
        wipe(self._buf)
        if self._locked:
            _try_unlock(self._buf)
            self._locked = False
        self._wiped = True

    def __enter__(self) -> "Secret":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.wipe()

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception:
            pass

    def __repr__(self) -> str:
        # Never include the secret in repr.
        return f"<Secret len={len(self._buf)} wiped={self._wiped}>"
