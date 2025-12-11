import frida
from PySide6 import QtCore


class TextractorWorker(QtCore.QThread):
    """
    A worker thread that uses Frida for dynamic instrumentation.
    Frida allows injecting JavaScript into a running process to hook function calls (like text rendering).
    """
    # Runs Frida to hook text rendering functions, emits hooked text lines.
    text_ready = QtCore.Signal(str)
    
    def __init__(self, pid: int, parent=None):
        """
        Initializes the Frida session with the target Process ID (PID).
        """
        super().__init__(parent)
        self.pid = pid
        self.session = None
        self.script = None
        self._running = False
    
    def run(self):
        """
        Main execution: attaches to the process, injects the JS script, and listens for messages.
        """
        self._running = True
# start frida session and script
        try:
            # Principle: Frida attaches to the target process memory space.
            self._session = frida.attach(self.pid)
            
            # The JavaScript code defines what functions to hook inside the target process.
            # (The code below is a placeholder template).
            js = """
            // Frida JavaScript code to hook text rendering functions
            // This is a placeholder; actual implementation depends on the target application
            rpc.exports = {
                // Exported functions can be defined here
            };
            """
            
            # Create and load the script into the target process.
            self._script = self._session.create_script(js)
            self._script.on("message", self.on_message)
            self._script.load()
            
        except Exception as e:
            print("[FRIDA] Failed to start CLI:", e)
            return

        while self._running:
            QtCore.QThread.msleep(100)
            
# handle messages from frida script
    def on_message(self, message, data):
        """
        Callback triggered when the injected JS script calls send().
        It parses the payload and emits the text to the UI.
        """
        if message['type'] == 'send':
            text = message['payload']
            self.text_ready.emit(text)
            
# stop the frida session and script
    def stop(self):
        """
        Cleanly detaches the Frida session and unloads scripts to prevent game crashes.
        """
        self._running = False
        
        try:
            if self._script:
                    self._script.unload()
            if self._session:
                    self._session.detach()
        except Exception:
                pass
        try:
            self.wait()
        except Exception:
                pass