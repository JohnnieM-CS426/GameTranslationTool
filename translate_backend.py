
import os
from typing import Optional, List
from argostranslate import package, translate

APP_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(APP_DIR, "translatePacks", "argos_models")

def _ensure_models_installed():
    if os.path.isdir(MODEL_DIR):
        for fn in os.listdir(MODEL_DIR):
            if fn.lower().endswith(".argosmodel"):
                try:
                    package.install_from_path(os.path.join(MODEL_DIR, fn))
                except Exception:
                    pass

def _get_lang(lang_code: str):
    langs = translate.get_installed_languages()
    for l in langs:
        if l.code.lower().startswith(lang_code.lower()):
            return l
    return None

def available_pair(src_code: str, dst_code: str):
    src = _get_lang(src_code); dst = _get_lang(dst_code)
    if not src or not dst: return None
    for t in src.translations:
        if t.from_lang.code == src.code and t.to_lang.code == dst.code:
            return t
    return None

def translate_text(src_code: str, dst_code: str, text: str) -> str:
    if not text: return ""
    _ensure_models_installed()
    if src_code == "auto":
        for ch in text:
            if '぀' <= ch <= 'ヿ':
                src_code = "ja"; break
            if '一' <= ch <= '鿿':
                src_code = "zh"; break
        else:
            src_code = "en"
    direct = available_pair(src_code, dst_code)
    if direct:
        return direct.translate(text)
    if src_code != "en" and dst_code != "en":
        to_en = available_pair(src_code, "en")
        en_to_dst = available_pair("en", dst_code)
        if to_en and en_to_dst:
            mid = to_en.translate(text)
            return en_to_dst.translate(mid)
    return text
