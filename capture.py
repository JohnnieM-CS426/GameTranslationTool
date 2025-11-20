
import time
import sys
import numpy as np
from PIL import Image, ImageGrab

#For Windows and Mac software
WINDOWS = sys.platform.startswith("win32")
MAC = sys.platform.startswith("darwin")

#Check if its Windows, then import windows specific libraries
if WINDOWS:
    import win32gui, win32ui, win32con

_dxcam = None

class WindowLister:
    @staticmethod
    def list_windows():
        if WINDOWS:  
         wins = []
         def enum(hwnd, ctx):
            if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
                wins.append((hwnd, win32gui.GetWindowText(hwnd)))
         win32gui.EnumWindows(enum, None)
         wins.sort(key=lambda x: x[1].lower())
         return wins
#Check if its Mac, then import Mac specific libraries
        if MAC:
            try:
                import Quartz.CoreGraphics as CG
                #get all window info
                options = CG.kCGWindowListOptionOnScreenOnly | CG.kCGWindowListExcludeDesktopElements
                window_list = CG.CGWindowListCopyWindowInfo(options, CG.kCGNullWindowID)
                result = []
                #loop through the windows and get the id,name and title of the window
                for window in window_list:
                    windowid = window['kCGWindowNumber']
                    title = window.get('kCGWindowName', '')
                    #filter to keep visible windows only
                    if title and windowid:
                        result.append((windowid, title))
                return result
            except Exception:
                print("Not installed")#used for debugging
                return[]
    
        return[]
                

def get_window_rect(hwnd):
    if not WINDOWS:
        return None
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
    
#capture helper for Mac
def _mac_capture_window(window_id = None):
    try:
        import Quartz.CoreGraphics as CG
        #after importing the right libraries, capture an image of the window of your choice
        imageCap = CG.CGWindowListCreateImage(
            CG.CGRectNull,
            CG.CGRectInfinite,
            CG.kCGWindowListOptionIncludingWindow,
            window_id,
            CG.kCGWindowImageDefault
        )
        #return none if it fails
        if not imageCap:
            return None
        #get width, height, and data(pixel info) from the captured image
        width = CG.CGImageGetWidth(imageCap)
        height = CG.CGImageGetHeight(imageCap)
        data = CG.CGDataProviderCopyData(CG.CGImageGetDataProvider((imageCap)))
        
        #create a pil image from the raw data
        img = Image.frombuffer(
            "RGBA", 
            (width, height), 
            data, 
            "raw", 
            "BGRA",
            0, 1
        )
        # Convert to RGB
        img = img.convert("RGB")
        return img
    except Exception:
        #if any error occurs during the whole process, return none
        return None
    
    
def capture_window_image(hwnd):
    if WINDOWS:
        img = _bitblt_capture(hwnd)
        if img is not None and not _looks_invalid(img):
            return img
        img2 = _dxgi_capture(hwnd)
        if img2 is not None and not _looks_invalid(img2):
            return img2
        return img or img2

    if MAC:
        #capture window using the mac capture function
        img = _mac_capture_window(window_id=hwnd)
        #return the image if the capture is successful
        if img is not None and not _looks_invalid(img):
            return img
        
        #capture the whole screen if window capture fails
        try:
            img2 = ImageGrab.grab()
            return img2
        except Exception: 
            return None
        
    return None
