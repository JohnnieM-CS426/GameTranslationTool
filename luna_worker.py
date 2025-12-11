import time
import traceback
from PySide6 import QtCore

from lunatranslate import LunaHook
from textractor_worker import get_pid_from_hwnd

class LunaWorker(QtCore.QThread):
    """
    A worker thread designed to manage the LunaHook injection process.
    It runs in the background to prevent the GUI from freezing while waiting for hooked text.
    """
    text_ready = QtCore.Signal(str) # Signal to send captured text back to the main UI thread.
    status = QtCore.Signal(str)     # Signal to send status updates (errors, success messages).

    def __init__(self, hwnd, parent=None):
        """
        Initializes the worker with the target window handle (HWND).
        Sets up the running flag and the hook instance placeholder.
        """
        super().__init__(parent)
        self.hwnd = hwnd
        self._running = True
        self._hook = None

    def run(self):
        """
        The main execution loop of the thread.
        It resolves the Process ID (PID) from the window handle and attaches the LunaHook.
        """
        print("=== LunaWorker START ===")
        print(f"HWND = {self.hwnd}")

        # Principle: We cannot hook a window handle directly; we need the underlying Process ID.
        pid = get_pid_from_hwnd(self.hwnd)
        print(f"Resolved PID = {pid}")

        if not pid:
            self.status.emit("Failed: Could not resolve PID from HWND")
            print("PID resolving FAILED")
            return

        try:
            # Instantiate the hook interface. This usually loads the underlying C++/DLL logic.
            self._hook = LunaHook()
            print("LunaHook() loaded successfully.")
        except Exception as e:
            print("!!! FAILED to load LunaHook()")
            traceback.print_exc()
            self.status.emit("Failed to load LunaHook")
            return

        # Define a callback function that the Hook will call whenever it finds new text in game memory.
        def on_text(text):
            print("[HOOK TEXT]", repr(text))
            self.text_ready.emit(text)

        print("Calling hook.start(pid)...")
        ok = False

        try:
            # Attempt to inject code into the target process (PID) and register the callback.
            ok = self._hook.start(pid, on_text)
        except Exception as e:
            print("!!! Exception during hook.start()")
            traceback.print_exc()

        print(f"hook.start() returned: {ok}")

        if not ok:
            self.status.emit("Failed to start LunaHook")
            return

        self.status.emit(f"LunaHook attached (PID {pid})")
        print("=== LunaHook ATTACHED OK ===")

        # Keep the thread alive so the hook callback remains active.
        while self._running:
            time.sleep(0.1)

        print("=== LunaWorker STOP ===")
        try:
            # Detach cleanly when the loop breaks.
            self._hook.stop()
        except:
            traceback.print_exc()

    def stop(self):
        """
        Signals the thread to stop running.
        It sets the flag to False, allowing the 'while' loop in run() to exit.
        """
        print("LunaWorker.stop() called")
        self._running = False