import requests
import html
import urllib.parse

# We use the mobile version of Google Translate as the API endpoint because it's simpler to scrape.
GOOGLE_TRANSLATE_URL = "https://translate.google.com/m"
_translation_cache = {}

LANG_MAP = {
    "auto": "Auto",
    #"zh": "zh-CN",
    #"en": "en",
    #"ja": "ja","""
    "af": "Afrikaans",
    "ar": "Arabic",
    "bg": "Bulgarian",
    "bn": "Bengali",
    "cs": "Czech",
    "da": "Danish",
    "de": "German",
    "el": "Greek",
    "en": "English",
    "es": "Spanish",
    "et": "Estonian",
    "fa": "Persian",
    "fi": "Finnish",
    "fr": "French",
    "gu": "Gujarati",
    "he": "Hebrew",
    "hi": "Hindi",
    "hr": "Croatian",
    "hu": "Hungarian",
    "id": "Indonesian",
    "it": "Italian",
    "ja": "Japanese",
    "jw": "Javanese",
    "km": "Khmer",
    "kn": "Kannada",
    "ko": "Korean",
    "la": "Latin",
    "lo": "Lao",
    "lt": "Lithuanian",
    "lv": "Latvian",
    "ml": "Malayalam",
    "mr": "Marathi",
    "ms": "Malay",
    "mt": "Maltese",
    "ne": "Nepali",
    "nl": "Dutch",
    "no": "Norwegian",
    "pl": "Polish",
    "pt": "Portuguese",
    "ro": "Romanian",
    "ru": "Russian",
    "si": "Sinhala",
    "sk": "Slovak",
    "sl": "Slovenian",
    "so": "Somali",
    "sq": "Albanian",
    "sv": "Swedish",
    "sw": "Swahili",
    "ta": "Tamil",
    "te": "Telugu",
    "th": "Thai",
    "tl": "Tagalog",
    "tr": "Turkish",
    "uk": "Ukrainian",
    "ur": "Urdu",
    "vi": "Vietnamese",
    "zh-CN": "Chinese (Simplified)",
    "zh-TW": "Chinese (Traditional)",
    "zu": "Zulu",
}

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

def google_translate(text, src="auto", dst="en"):
    """
    Sends a request to Google Translate to translate text.
    It scrapes the result from the HTML response of the mobile translation page.
    """
    if not text.strip():
        return ""

    src = src.lower()
    dst = dst.lower()
    
    # Principle: Construct a GET request with source language (sl), target language (tl), and query (q).
    params = {"sl": src, "tl": dst, "q": text}
    url = GOOGLE_TRANSLATE_URL + "?" + urllib.parse.urlencode(params)

    r = requests.get(url, headers=headers, timeout=5)
    if r.status_code != 200:
        return text

    content = r.text
    # Principle: Parse the HTML. The result is typically inside a div with class 'result-container'.
    # We find the start and end of this tag to extract the translation.
    try:
        start = content.index('result-container">') + 18
        end = content.index("<", start)
        return html.unescape(content[start:end])
    except:
        return text


def translate_text(src_lang, dst_lang, text):
    """
    A wrapper around the translation function that adds caching.
    This prevents repeated network requests for the same text (common in games).
    """
    key = f"{src_lang}|{dst_lang}|{text}"
    if key in _translation_cache:
        return _translation_cache[key]

    result = google_translate(text, src_lang, dst_lang)
    _translation_cache[key] = result
    return result