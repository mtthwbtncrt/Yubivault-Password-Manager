from __future__ import annotations

import os
import subprocess
import sys
import time

# Windows process creation flags
DETACHED_PROCESS = 0x00000008
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200


def copy(text: str) -> None:
    """Copy text to the system clipboard (Windows)."""
    if sys.platform == "win32":
        # clip.exe reads stdin and replaces the clipboard. It expects UTF-16LE.
        p = subprocess.Popen(
            ["clip.exe"],
            stdin=subprocess.PIPE,
            close_fds=True,
        )
        p.communicate(text.encode("utf-16-le"))
    else:
        raise NotImplementedError(f"Clipboard not implemented for {sys.platform}")


def clear() -> None:
    """Clear the system clipboard."""
    copy("")


_BACKGROUND_CLEAR_SCRIPT = """
import sys, time, subprocess, hashlib

seconds = int(sys.argv[1])
expected_sha = sys.argv[2] if len(sys.argv) > 2 else ""

time.sleep(seconds)

# Best-effort: only clear if the current clipboard still matches what we set.
# (Avoids stomping on content the user pasted in the meantime.)
try:
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    CF_UNICODETEXT = 13
    if user32.OpenClipboard(0):
        try:
            h = user32.GetClipboardData(CF_UNICODETEXT)
            current = ""
            if h:
                p = kernel32.GlobalLock(h)
                if p:
                    try:
                        current = ctypes.wstring_at(p)
                    finally:
                        kernel32.GlobalUnlock(h)
        finally:
            user32.CloseClipboard()
        if expected_sha and hashlib.sha256(current.encode("utf-16-le")).hexdigest() != expected_sha:
            sys.exit(0)
except Exception:
    pass

# Replace clipboard with empty content
p = subprocess.Popen(["clip.exe"], stdin=subprocess.PIPE, close_fds=True)
p.communicate(b"")
"""


def copy_with_auto_clear(text: str, seconds: int) -> None:
    """Copy text to clipboard. Spawn a DETACHED subprocess that clears it
    after `seconds`, only if the clipboard content is unchanged.

    The clear survives the parent process exiting (Ctrl+C, normal exit, crash).
    """
    copy(text)

    if sys.platform != "win32":
        return

    import hashlib
    expected_sha = hashlib.sha256(text.encode("utf-16-le")).hexdigest()

    # Run the same Python interpreter, but detached. pythonw.exe is the
    # window-less variant — fall back to python.exe with CREATE_NO_WINDOW.
    py = sys.executable
    if py.lower().endswith("python.exe"):
        candidate = py[:-len("python.exe")] + "pythonw.exe"
        if os.path.exists(candidate):
            py = candidate

    subprocess.Popen(
        [py, "-c", _BACKGROUND_CLEAR_SCRIPT, str(seconds), expected_sha],
        creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
