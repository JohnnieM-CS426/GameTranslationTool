import os
import sys
import time
import subprocess
import ctypes

from PySide6 import QtCore

APP_DIR = os.path.dirname(__file__)
TEXTRACTOR_CLI_PATH = os.path.join(APP_DIR, "TextractorCLI.exe")


def get_pid_from_hwnd(hwnd: int) -> int:
    """Return process ID for a given window handle (HWND)."""
    if sys.platform == "win32":
        import ctypes
        pid = ctypes.c_ulong()
        ctypes.windll.user32.GetWindowThreadProcessId(
            ctypes.c_void_p(hwnd),
            ctypes.byref(pid)
    )
        return pid.value
    elif sys.platform == "darwin":
            # macOS implementation (not implemented here)
            print("[TEXTRACTOR] get_pid_from_hwnd not implemented on macOS")
            return None
    else:
            return None

class TextractorWorker(QtCore.QThread):
    """Runs TextractorCLI.exe, attaches to a process, emits hooked text lines."""

    text_ready = QtCore.Signal(str)

    def __init__(self, pid: int, cli_path: str = TEXTRACTOR_CLI_PATH, parent=None):
        super().__init__(parent)
        self.pid = pid
        self.cli_path = cli_path
        self._proc = None
        self._running = False

    def run(self):
        if not os.path.isfile(self.cli_path):
            print("[TEXTRACTOR] CLI not found at", self.cli_path)
            return

        try:
            self._proc = subprocess.Popen(
                [self.cli_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding="utf-16-le",
                errors="ignore",
                bufsize=1,
            )
        except Exception as e:
            print("[TEXTRACTOR] Failed to start CLI:", e)
            return

        self._running = True

        try:
            cmd = f"attach -P{self.pid}\n"
            self._proc.stdin.write(cmd)
            self._proc.stdin.flush()
        except Exception as e:
            print("[TEXTRACTOR] Failed to send attach command:", e)
            self._running = False

        for line in self._proc.stdout:
            if not self._running:
                break
            line = line.strip()
            if not line:
                continue

            if "] " in line:
                try:
                    _, text = line.split("] ", 1)
                except ValueError:
                    text = line
            else:
                text = line

            text = text.strip()
            if len(text) < 2:
                continue

            self.text_ready.emit(text)

        try:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
        except Exception:
            pass

    def stop(self):
        self._running = False
        if self._proc and self._proc.poll() is None:
            try:
                cmd = f"detach -P{self.pid}\n"
                self._proc.stdin.write(cmd)
                self._proc.stdin.flush()
                time.sleep(0.2)
                self._proc.terminate()
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
