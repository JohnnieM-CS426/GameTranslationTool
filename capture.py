import time
import sys
import numpy as np
from PIL import Image, ImageGrab

# For Windows and Mac software
# Detect the current operating system to load specific libraries.
WINDOWS = sys.platform.startswith("win32")
MAC = sys.platform.startswith("darwin")

# Check if it's Windows, then import windows specific libraries
# Win32gui and win32ui allow direct interaction with the Windows GDI (Graphics Device Interface).
if WINDOWS:
    import win32gui, win32ui, win32con

_dxcam = None

class WindowLister:
    """
    A utility class to list active windows on the operating system.
    It supports both Windows (via Win32 API) and macOS (via Quartz).
    """
    @staticmethod
    def list_windows():
        """
        Enumerates all visible windows on the desktop and returns their handles and titles.
        It uses OS-specific APIs to filter out background processes and invalid windows.
        """
        if WINDOWS:  
            # Principle: Use EnumWindows to iterate over all top-level windows.
            # We filter for windows that are visible and have a title bar text.
             wins = []
             def enum(hwnd, ctx):
                if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
                    wins.append((hwnd, win32gui.GetWindowText(hwnd)))
             win32gui.EnumWindows(enum, None)
             # Sort windows alphabetically for easier user selection.
             wins.sort(key=lambda x: x[1].lower())
             return wins

        # Check if its Mac, then import Mac specific libraries
        if MAC:
            try:
                import Quartz.CoreGraphics as CG
                # Principle: Use CoreGraphics (Quartz) to request a list of on-screen windows.
                # kCGWindowListOptionOnScreenOnly ensures we don't get hidden windows.
                options = CG.kCGWindowListOptionOnScreenOnly | CG.kCGWindowListExcludeDesktopElements
                window_list = CG.CGWindowListCopyWindowInfo(options, CG.kCGNullWindowID)
                result = []
                # Loop through the windows and get the id, name and title of the window
                for window in window_list:
                    windowid = window['kCGWindowNumber']
                    title = window.get('kCGWindowName', '')
                    pid = window.get('kCGWindowOwnerPID', None)
                    # Filter to keep visible windows only: must have a title and a process ID.
                    if title and pid:
                        result.append((pid, title))
                return result
            except Exception:
                print("Not installed") # Used for debugging if Quartz is missing
                return[]
    
        return[]
                

def get_window_rect(hwnd):
    """
    Retrieves the screen coordinates (left, top, right, bottom) of the specified window's client area.
    It attempts to exclude window borders and title bars to capture only the game content.
    """
    if not WINDOWS:
        return None
    try:
        # Principle: GetClientRect returns coordinates relative to the window itself (0,0 is top-left).
        # We then use ClientToScreen to map these relative points to absolute screen coordinates.
        left, top, right, bottom = win32gui.GetClientRect(hwnd)
        lt = win32gui.ClientToScreen(hwnd, (left, top))
        rb = win32gui.ClientToScreen(hwnd, (right, bottom))
        return (lt[0], lt[1], rb[0], rb[1])
    except Exception:
        # Fallback: If ClientRect fails, get the full window rectangle (includes borders).
        try:
            return win32gui.GetWindowRect(hwnd)
        except:
            return None

def _bitblt_capture(hwnd):
    """
    Captures a screenshot of a specific window using the legacy Windows GDI API (BitBlt).
    It creates a memory Device Context compatible with the window and copies the pixel bits.
    """
    rect = get_window_rect(hwnd)
    if not rect:
        return None
    left, top, right, bottom = rect
    w, h = right - left, bottom - top
    if w <= 0 or h <= 0:
        return None
    
    # Principle:
    # 1. Get the Device Context (DC) of the specific window handle.
    # 2. Create a memory DC (mfcDC) to hold the image data in RAM.
    # 3. Create a Bitmap object and select it into the memory DC.
    # 4. Perform BitBlt (Bit Block Transfer) to copy pixels from Window DC to Memory DC.
    hwndDC = win32gui.GetWindowDC(hwnd)
    mfcDC  = win32ui.CreateDCFromHandle(hwndDC)
    saveDC = mfcDC.CreateCompatibleDC()
    saveBitMap = win32ui.CreateBitmap()
    saveBitMap.CreateCompatibleBitmap(mfcDC, w, h)
    saveDC.SelectObject(saveBitMap)
    saveDC.BitBlt((0, 0), (w, h), mfcDC, (0, 0), win32con.SRCCOPY)

    # Extract raw binary data from the bitmap object.
    bmpinfo = saveBitMap.GetInfo()
    bmpstr = saveBitMap.GetBitmapBits(True)

    # Cleanup GDI objects to prevent memory leaks (very important in GDI).
    win32gui.DeleteObject(saveBitMap.GetHandle())
    saveDC.DeleteDC()
    mfcDC.DeleteDC()
    win32gui.ReleaseDC(hwnd, hwndDC)

    # Convert raw bytes into a NumPy array and then into a PIL Image.
    # We must swap channels because GDI returns BGRA/BGR, but PIL expects RGB.
    img = np.frombuffer(bmpstr, dtype=np.uint8)
    img.shape = (bmpinfo['bmHeight'], bmpinfo['bmWidth'], 4)
    rgb = img[..., [2,1,0]] # Drop Alpha and swap B and R channels
    return Image.fromarray(rgb)

def _dxgi_capture(hwnd):
    """
    Captures the screen using the DirectX Graphics Infrastructure (DXGI) via the dxcam library.
    This method is significantly faster than GDI (BitBlt) as it grabs frames directly from the GPU buffer.
    """
    global _dxcam
    try:
        # Lazy initialization of the DXCam instance to avoid overhead on startup.
        if _dxcam is None:
            import dxcam
            _dxcam = dxcam.create()
        
        rect = get_window_rect(hwnd)
        if not rect:
            return None
        left, top, right, bottom = rect
        
        # Grab the specific region of the screen corresponding to the window.
        frame = _dxcam.grab(region=(left, top, right, bottom))
        if frame is None:
            return None
        # DXCam returns numpy arrays directly. We convert it to a PIL image.
        return Image.fromarray(frame[..., :3])
    except Exception:
        return None

def _looks_invalid(pil_img):
    """
    Validates the captured image to ensure it is not a black screen or empty data.
    It calculates the variance of the pixel data to detect flat (single color) images.
    """
    try:
        arr = np.asarray(pil_img)
        if arr.size == 0:
            return True
        # Principle: Calculate variance. A variance of < 50 usually implies a solid black 
        # or solid white screen, indicating a capture failure (e.g., DRM or minimized window).
        v = float(arr.var())
        if v < 50:
            return True
        return False
    except Exception:
        return True
    
# capture helper for Mac
def _mac_capture_window(window_id = None):
    """
    Captures a specific window on macOS using Quartz CoreGraphics.
    It requests the window image directly from the window server/compositor.
    """
    try:
        import Quartz.CoreGraphics as CG
        # after importing the right libraries, capture an image of the window of your choice
        # Principle: Create an image reference from the specific window ID.
        imageCap = CG.CGWindowListCreateImage(
            CG.CGRectNull,
            CG.CGRectInfinite,
            CG.kCGWindowListOptionIncludingWindow,
            window_id,
            CG.kCGWindowImageDefault
        )
        # return none if it fails
        if not imageCap:
            return None
        
        # get width, height, and data(pixel info) from the captured image
        width = CG.CGImageGetWidth(imageCap)
        height = CG.CGImageGetHeight(imageCap)
        data = CG.CGDataProviderCopyData(CG.CGImageGetDataProvider((imageCap)))
        
        # create a pil image from the raw data
        # MacOS Quartz usually returns BGRA data.
        img = Image.frombuffer(
            "RGBA", 
            (width, height), 
            data, 
            "raw", 
            "BGRA",
            0, 1
        )
        # Convert to RGB to be compatible with the rest of the app (OCR engines).
        img = img.convert("RGB")
        return img
    except Exception:
        # if any error occurs during the whole process, return none
        return None
    
    
def capture_window_image(hwnd):
    """
    The main facade function that selects the best capture method based on the OS and success rate.
    On Windows, it tries BitBlt first, then falls back to DXGI; on Mac, it uses Quartz.
    """
    if WINDOWS:
        # Try GDI (BitBlt) capture first as it's standard.
        img = _bitblt_capture(hwnd)
        if img is not None and not _looks_invalid(img):
            return img
        # Fallback to DXGI (DirectX) if GDI fails (e.g., hardware accelerated windows).
        img2 = _dxgi_capture(hwnd)
        if img2 is not None and not _looks_invalid(img2):
            return img2
        return img or img2

    if MAC:
        # capture window using the mac capture function
        img = _mac_capture_window(window_id=hwnd)
        # return the image if the capture is successful
        if img is not None and not _looks_invalid(img):
            return img
        
        # capture the whole screen if window capture fails
        # Fallback: standard PIL ImageGrab (less precise but reliable).
        try:
            img2 = ImageGrab.grab()
            return img2
        except Exception: 
            return None
        
    return None