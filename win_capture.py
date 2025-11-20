
from PIL import ImageGrab, Image
import sys
import numpy as np

#For Windows and Mac software
WINDOWS = sys.platform.startswith("win32")
MAC = sys.platform.startswith("darwin")

#windows imports
if WINDOWS:
    import win32gui
    
#mac imports
if MAC:
    from Quartz import (
        CGWindowListCopyWindowInfo,
        CGWindowListCreateImage,
        kCGWindowListOptionOnScreenOnly,
        kCGNullWindowID,
        kCGWindowListOptionIncludingWindow,
        kCGWindowImageDefault,
    )
    import Quartz
    
class WindowLister:
    @staticmethod
    def list_windows():
        if WINDOWS:   
            wins = []
            def enum(hwnd, ctx):
                if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
                    wins.append((hwnd, win32gui.GetWindowText(hwnd)))
            win32gui.EnumWindows(enum, None)
            return wins
        if MAC:
        #get all window info
            windowInfo = CGWindowListCopyWindowInfo(
            kCGWindowListOptionOnScreenOnly,
            kCGNullWindowID
        )
            out = []
        
        #loop through the windows and get the id,name and title of the window
            for w in windowInfo:
                windowID = w.get("kCGWindowNumber")
                owner = w.get("kCGWindowOwnerName", " ")
                name = w.get("kCGWindowName", " ")
        
        #filter to keep visible windows only
                if windowID and (owner or name):
                    out.append((windowID, f"{owner} - {name}"))
        
        return out    
    
            

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
    if WINDOWS:
        coords = get_window_rect(hwnd)
        if not coords:
            return None
        
        left, top, right, bottom = coords
        img = ImageGrab.grab(bbox=(left, top, right, bottom))
        return img.convert("RGB")

    if MAC:
        #capture window image and return nothing if failure occurs
        imageRef = CGWindowListCreateImage(
            Quartz.CGRectNull,
            kCGWindowListOptionIncludingWindow,
            hwnd,
            kCGWindowImageDefault
        )
        
        if imageRef is None:
            return None
        
        #get the width and height and pixel data of the image
        width = Quartz.CGImageGetWidth(imageRef)
        height = Quartz.CGImageGetHeight(imageRef)
        
        pixData = Quartz.CGDataProviderCopyData(
            Quartz.CGImageGetDataProvider(imageRef)
        )
        
        #convert from raw data to pil image
        npArray = np.frombuffer(pixData, dtype = np.uint8).reshape((height,width,5))
        
        return Image.fromarray(npArray, "RGBA")
    
    return None