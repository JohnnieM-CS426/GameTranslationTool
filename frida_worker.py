import frida
from PySide6 import QtCore


<<<<<<< Updated upstream
class TextractorWorker(QtCore.QThread):
    #Runs Frida to hook text rendering functions, emits hooked text lines.
=======
class FridaWorker(QtCore.QThread):
    """
    A worker thread that uses Frida for dynamic instrumentation.
    Frida allows injecting JavaScript into a running process to hook function calls (like text rendering).
    """
    # Runs Frida to hook text rendering functions, emits hooked text lines.
>>>>>>> Stashed changes
    text_ready = QtCore.Signal(str)
    
    def __init__(self, pid: int, parent=None):
        """
        Initializes the Frida based text hook worker for a given process id.
        It stores the pid, sets up internal session and script references, and prepares the QThread for later execution.
        """
        super().__init__(parent)
        self.pid = pid
        self.session = None
        self.script = None
        self._running = False
    
    def run(self):
        """
        Attaches Frida to the target process and starts the instrumentation script.
        It loads the JavaScript code, hooks text related functions, enters a message loop, and keeps running while the worker is marked as active.
        """
        self._running = True
#start frida session and script
        try:
            self._session = frida.attach(self.pid)
            js = """
            // Frida JavaScript code to hook text rendering functions
            // This is a placeholder; actual implementation depends on the target application
            rpc.exports = {
                // Exported functions can be defined here
            };
            """
            
            self._script = self._session.create_script(js)
            self._script.on("message", self.on_message)
            self._script.load()
            
        except Exception as e:
            print("[FRIDA] Failed to start CLI:", e)
            return

        while self._running:
            QtCore.QThread.msleep(100)
            
#handle messages from frida script
    def on_message(self, message, data):
        """
        Handles messages sent from the injected Frida script.
        It filters for messages that contain captured text payloads and emits them through the text_ready Qt signal so the UI can display them.
        """
        if message['type'] == 'send':
            text = message['payload']
            self.text_ready.emit(text)
            
#stop the frida session and script
    def stop(self):
        """
        Stops the Frida worker and cleans up the injected script and session.
        It marks the worker as not running, tries to unload the script and detach the session, and waits for the QThread to finish.
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