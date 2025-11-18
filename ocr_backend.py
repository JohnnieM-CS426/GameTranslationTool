
import os, sys, time
import numpy as np
from PIL import Image

APP_DIR = os.path.dirname(os.path.abspath(__file__))
VENDOR_EASYOCR = os.path.join(APP_DIR, "vendor", "EasyOCR-1.7.2")
if os.path.exists(VENDOR_EASYOCR):
    sys.path.insert(0, VENDOR_EASYOCR)

try:
    import easyocr
except Exception as e:
    raise RuntimeError("EasyOCR import failed. Ensure vendor/EasyOCR-1.7.2 exists or install easyocr.") from e

LOG_DIR = os.path.join(APP_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
_last_debug_save = 0.0

_readers = {}

def _lang_key(code: str):
    code = (code or "auto").lower()
    if code == "zh": return "zh"
    if code == "ja": return "ja"
    return "en"

def _get_reader(code: str):
    key = _lang_key(code)
    if key in _readers:
        return _readers[key]
    if key == "zh":
        langs = ['ch_sim','en']
    elif key == "ja":
        langs = ['ja','en']
    else:
        langs = ['en']
    reader = easyocr.Reader(langs, gpu=False, verbose=False)
    _readers[key] = reader
    print(f"[EasyOCR] Initialized reader with languages: {langs}")
    return reader

def ocr_image_data(pil_image, prefer_lang_code="auto"):
    global _last_debug_save
    now = time.time()
    if now - _last_debug_save > 1.0:
        try:
            pil_image.save(os.path.join(LOG_DIR, "debug_frame.png"))
        except Exception:
            pass
        _last_debug_save = now

    reader = _get_reader(prefer_lang_code)
    img = np.array(pil_image)
    if img.shape[1] > 1600:
        scale = 1600.0 / img.shape[1]
        new_h = int(img.shape[0] * scale)
        import cv2
        img = cv2.resize(img, (1600, new_h))

    results_raw = reader.readtext(img, detail=1)
    print(f"[EasyOCR] detected: {len(results_raw)} items")
    results = []
    for item in results_raw:
        try:
            bbox, text, conf = item
        except Exception:
            continue
        if not text or not str(text).strip():
            continue
        xs = [pt[0] for pt in bbox]; ys = [pt[1] for pt in bbox]
        x, y = int(min(xs)), int(min(ys))
        w, h = int(max(xs) - x), int(max(ys) - y)
        if w < 5 or h < 5:
            continue
        results.append({'text': str(text).strip(), 'bbox': (x, y, w, h), 'lang': 'unknown'})
    return results
