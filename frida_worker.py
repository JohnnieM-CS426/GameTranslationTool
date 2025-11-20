import frida
from PySide6 import QtCore


class TextractorWorker(QtCore.QThread):
    #Runs Frida to hook text rendering functions, emits hooked text lines.
    text_ready = QtCore.Signal(str)
    
    def __init__(self, pid: int, parent=None):
        super().__init__(parent)
        self.pid = pid
        self.session = None
        self.script = None
        self._running = False
    
    def run(self):
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
        if message['type'] == 'send':
            text = message['payload']
            self.text_ready.emit(text)
            
#stop the frida session and script
    def stop(self):
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