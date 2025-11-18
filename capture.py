
import time
import numpy as np
from PIL import Image
import win32gui, win32ui, win32con

_dxcam = None

class WindowLister:
    @staticmethod
    def list_windows():
        wins = []
        def enum(hwnd, ctx):
            if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
                wins.append((hwnd, win32gui.GetWindowText(hwnd)))
        win32gui.EnumWindows(enum, None)
        wins.sort(key=lambda x: x[1].lower())
        return wins

def get_window_rect(hwnd):
    try:
        left, top, right, bottom = win32gui.GetClientRect(hwnd)
        lt = win32gui.ClientToScreen(hwnd, (left, top))
        rb = win32gui.ClientToScreen(hwnd, (right, bottom))
        return (lt[0], lt[1], rb[0], rb[1])
    except Exception:
        try:
            return win32gui.GetWindowRect(hwnd)
        except:
            return None

def _bitblt_capture(hwnd):
    rect = get_window_rect(hwnd)
    if not rect:
        return None
    left, top, right, bottom = rect
    w, h = right - left, bottom - top
    if w <= 0 or h <= 0:
        return None
    hwndDC = win32gui.GetWindowDC(hwnd)
    mfcDC  = win32ui.CreateDCFromHandle(hwndDC)
    saveDC = mfcDC.CreateCompatibleDC()
    saveBitMap = win32ui.CreateBitmap()
    saveBitMap.CreateCompatibleBitmap(mfcDC, w, h)
    saveDC.SelectObject(saveBitMap)
    saveDC.BitBlt((0, 0), (w, h), mfcDC, (0, 0), win32con.SRCCOPY)

    bmpinfo = saveBitMap.GetInfo()
    bmpstr = saveBitMap.GetBitmapBits(True)

    win32gui.DeleteObject(saveBitMap.GetHandle())
    saveDC.DeleteDC()
    mfcDC.DeleteDC()
    win32gui.ReleaseDC(hwnd, hwndDC)

    img = np.frombuffer(bmpstr, dtype=np.uint8)
    img.shape = (bmpinfo['bmHeight'], bmpinfo['bmWidth'], 4)
    rgb = img[..., [2,1,0]]
    return Image.fromarray(rgb)

def _dxgi_capture(hwnd):
    global _dxcam
    try:
        if _dxcam is None:
            import dxcam
            _dxcam = dxcam.create()
        rect = get_window_rect(hwnd)
        if not rect:
            return None
        left, top, right, bottom = rect
        frame = _dxcam.grab(region=(left, top, right, bottom))
        if frame is None:
            return None
        return Image.fromarray(frame[..., :3])
    except Exception:
        return None

def _looks_invalid(pil_img):
    try:
        arr = np.asarray(pil_img)
        if arr.size == 0:
            return True
        v = float(arr.var())
        if v < 50:
            return True
        return False
    except Exception:
        return True

def capture_window_image(hwnd):
    img = _bitblt_capture(hwnd)
    if img is not None and not _looks_invalid(img):
        return img
    img2 = _dxgi_capture(hwnd)
    if img2 is not None and not _looks_invalid(img2):
        return img2
    return img or img2
