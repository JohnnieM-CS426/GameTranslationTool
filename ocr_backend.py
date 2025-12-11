import os
import time
import numpy as np
from PIL import Image
from rapidocr_onnxruntime import RapidOCR

APP_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(APP_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Initialize the RapidOCR engine. 
# It uses ONNX Runtime for efficient deep learning inference.
_ocr_engine = RapidOCR()
_last_debug_save = 0.0


def ocr_image_data(pil_image, prefer_lang_code="auto"):
    """
    Processes an image using RapidOCR to extract text and bounding boxes.
    It includes preprocessing steps like resizing to improve OCR accuracy on small text.
    """
    global _last_debug_save

    # Debugging mechanism: Saves one frame every second to disk to verify what the OCR sees.
    now = time.time()
    if now - _last_debug_save > 1.0:
        try:
            pil_image.save(os.path.join(LOG_DIR, "debug_frame.png"))
        except Exception:
            pass
        _last_debug_save = now

    img = np.array(pil_image)

    # Principle: Upscale the image if it is too narrow.
    # OCR models often struggle with small low-res text; resizing to ~1600px width helps recognition.
    if img.ndim == 3 and img.shape[1] > 1600:
        scale = 1600.0 / img.shape[1]
        new_h = int(img.shape[0] * scale)
        import cv2
        img = cv2.resize(img, (1600, new_h), interpolation=cv2.INTER_LINEAR)

    # Principle: Convert RGB to BGR.
    # PIL uses RGB, but OpenCV/RapidOCR usually expects BGR format for processing.
    if img.ndim == 3 and img.shape[2] == 3:
        import cv2
        img_bgr = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)
    else:
        img_bgr = img

    # Perform inference.
    result, _ = _ocr_engine(img_bgr)
    entries = []

    if not result:
        return entries

    # Parse the results. RapidOCR returns a list of [bbox, text, confidence].
    for item in result:
        try:
            bbox, text, score = item
        except Exception:
            continue

        if not text or not str(text).strip():
            continue

        # Calculate the bounding box (x, y, width, height) from the polygon points.
        try:
            xs = [pt[0] for pt in bbox]
            ys = [pt[1] for pt in bbox]
            x, y = int(min(xs)), int(min(ys))
            w, h = int(max(xs) - x), int(max(ys) - y)
        except Exception:
            continue

        # Filter out noise (extremely small detected regions).
        if w < 5 or h < 5:
            continue

        entries.append({
            "text": str(text).strip(),
            "bbox": (x, y, w, h),
            "lang": "unknown",
        })

    return entries