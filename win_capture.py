
from PIL import ImageGrab
import win32gui

class WindowLister:
    @staticmethod
    def list_windows():
        wins = []
        def enum(hwnd, ctx):
            if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
                wins.append((hwnd, win32gui.GetWindowText(hwnd)))
        win32gui.EnumWindows(enum, None)
        return wins

def get_window_rect(hwnd):
    try:
        rect = win32gui.GetClientRect(hwnd)
        lt = win32gui.ClientToScreen(hwnd, (rect[0], rect[1]))
        rb = win32gui.ClientToScreen(hwnd, (rect[2], rect[3]))
        left, top = lt
        right, bottom = rb
        return int(left), int(top), int(right), int(bottom)
    except Exception:
        try:
            left, top, right, bottom = win32gui.GetWindowRect(hwnd)
            return int(left), int(top), int(right), int(bottom)
        except Exception:
            return None

def capture_window_image(hwnd):
    coords = get_window_rect(hwnd)
    if not coords:
        return None
    left, top, right, bottom = coords
    img = ImageGrab.grab(bbox=(left, top, right, bottom))
    return img.convert("RGB")
