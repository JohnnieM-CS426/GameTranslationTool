from PIL import ImageGrab, Image
import cv2
import numpy as np
import win32gui, win32ui, win32con
import ctypes
from PySide6 import QtWidgets, QtCore, QtGui


class WindowLister:
    """
    Helper class to list windows (Duplicated logic from capture.py).
    Useful for standalone usage of this file.
    """
    @staticmethod
    def list_windows():
        wins = []
        def enum(hwnd, ctx):
            if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
                wins.append((hwnd, win32gui.GetWindowText(hwnd)))
        win32gui.EnumWindows(enum, None)
        return wins

def get_window_rect(hwnd):
    """
    Calculates the screen coordinates of a window.
    """
    try:
        rect = win32gui.GetClientRect(hwnd)
        left_top = win32gui.ClientToScreen(hwnd, (rect[0], rect[1]))
        right_bottom = win32gui.ClientToScreen(hwnd, (rect[2], rect[3]))
        left, top = left_top
        right, bottom = right_bottom
        return int(left), int(top), int(right), int(bottom)
    except Exception:
        try:
            rect = win32gui.GetWindowRect(hwnd)
            left, top, right, bottom = rect
            return int(left), int(top), int(right), int(bottom)
        except Exception:
            return None

def capture_window_image(hwnd):
    """
    Captures the specified window area using ImageGrab.
    """
    coords = get_window_rect(hwnd)
    if not coords:
        return None
    left, top, right, bottom = coords
    try:
        img = ImageGrab.grab(bbox=(left, top, right, bottom))
    except Exception:
        img = ImageGrab.grab()
    return img.convert("RGB")

def ocr_image_data(pil_image):
    """
    Prepares image for OCR using Tesseract (implied by the code, though RapidOCR is used elsewhere).
    """
    img = np.array(pil_image)
    gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
    
    # Principle: Apply adaptive thresholding to binarize the image (black and white).
    # This helps separate text from complex game backgrounds.
    try:
        th = cv2.adaptiveThreshold(gray,255,cv2.ADAPTIVE_THRESH_GAUSSIAN_C,cv2.THRESH_BINARY,11,2)
    except Exception:
        th = gray
    
    # Note: 'pytesseract' is referenced here but not imported at the top. This function assumes it exists.
    # It extracts dictionary data containing text and coordinate info.
    data = pytesseract.image_to_data(Image.fromarray(img), output_type=pytesseract.Output.DICT, lang='eng+jpn+chi_sim')
    results = []
    n = len(data['text'])
    for i in range(n):
        text = data['text'][i].strip()
        if not text:
            continue
        x, y, w, h = int(data['left'][i]), int(data['top'][i]), int(data['width'][i]), int(data['height'][i])
        results.append({'text': text, 'bbox': (x,y,w,h), 'lang': 'unknown'})
    return results

class OverlayWindow(QtWidgets.QWidget):
    """
    A standalone transparent window class that creates floating subtitles.
    It can be positioned over the game window to show translations in real-time.
    """
    def __init__(self, ocr_results, parent=None, offset=(0,0)):
        """
        Initializes the overlay window with specific flags.
        FramelessWindowHint removes the title bar; WindowStaysOnTopHint keeps it above the game.
        """
        super().__init__(parent, QtCore.Qt.Window)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowStaysOnTopHint | QtCore.Qt.Tool)
        # WA_TranslucentBackground makes the window background transparent, so only text is visible.
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.labels = []
        self.ocr_results = ocr_results
        self.offset = offset
        self.build_ui()

    def build_ui(self):
        """
        Constructs the UI elements (QLabels) for each translated text block.
        It positions them based on the original OCR bounding box coordinates + offset.
        """
        desktop = QtWidgets.QApplication.primaryScreen().geometry()
        self.setGeometry(desktop)
        for r in self.ocr_results:
            txt = r.get('translation') or r.get('text')
            x,y,w,h = r['bbox']
            x += self.offset[0]; y += self.offset[1]
            lbl = QtWidgets.QLabel(self)
            lbl.setText(txt)
            lbl.setWordWrap(True)
            # Make the label ignore mouse events so clicks pass through to the game.
            lbl.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
            font = QtGui.QFont("Segoe UI", max(10, int(h*0.6)))
            lbl.setFont(font)
            lbl.move(x, y)
            lbl.resize(max(50,w), max(20,h))
            # Semi-transparent black background for readability.
            lbl.setStyleSheet("color: yellow; background-color: rgba(0,0,0,120);")
            self.labels.append(lbl)

    def update_results(self, ocr_results, offset=(0,0)):
        """
        Refreshes the overlay with new OCR results.
        It clears existing labels and rebuilds the UI.
        """
        # clear old labels
        for lbl in self.labels:
            lbl.deleteLater()
        self.labels = []
        self.ocr_results = ocr_results
        self.offset = offset
        self.build_ui()