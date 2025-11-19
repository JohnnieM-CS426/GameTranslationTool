import requests
import html
import urllib.parse

GOOGLE_TRANSLATE_URL = "https://translate.google.com/m"
_translation_cache = {}

LANG_MAP = {
    "auto": "auto",
    "zh": "zh-CN",
    "en": "en",
    "ja": "ja",
}

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

def google_translate(text, src="auto", dst="en"):
    if not text.strip():
        return ""

    src = LANG_MAP.get(src.lower(), src)
    dst = LANG_MAP.get(dst.lower(), dst)

    params = {"sl": src, "tl": dst, "q": text}
    url = GOOGLE_TRANSLATE_URL + "?" + urllib.parse.urlencode(params)

    r = requests.get(url, headers=headers, timeout=5)
    if r.status_code != 200:
        return text

    content = r.text
    try:
        start = content.index('result-container">') + 18
        end = content.index("<", start)
        return html.unescape(content[start:end])
    except:
        return text


def translate_text(src_lang, dst_lang, text):
    key = f"{src_lang}|{dst_lang}|{text}"
    if key in _translation_cache:
        return _translation_cache[key]

    result = google_translate(text, src_lang, dst_lang)
    _translation_cache[key] = result
    return result
