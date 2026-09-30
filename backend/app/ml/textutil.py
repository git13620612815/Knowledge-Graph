import re

from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

CN_STOP = {
    "的", "了", "是", "在", "我", "有", "和", "就", "不", "人", "都", "一", "一个",
    "上", "也", "很", "到", "说", "要", "去", "你", "会", "着", "没有", "看", "好",
    "自己", "这", "那", "与", "及", "或", "被", "把", "从", "对", "而", "并", "其",
    "请", "我们", "你们", "他们", "以及", "如果", "因为", "所以", "这个", "那个",
}


def fullwidth_to_half(text: str) -> str:
    out = []
    for ch in text:
        code = ord(ch)
        if code == 0x3000:
            out.append(" ")
        elif 0xFF01 <= code <= 0xFF5E:
            out.append(chr(code - 0xFEE0))
        else:
            out.append(ch)
    return "".join(out)


def preprocess(text: str) -> str:
    raw = text or ""
    if "<" in raw and ">" in raw:
        raw = BeautifulSoup(raw, "html.parser").get_text(" ")
    raw = fullwidth_to_half(raw).lower()
    raw = re.sub(r"https?://\S+", " URL ", raw)
    raw = re.sub(r"\S+@\S+", " EMAIL ", raw)
    return raw


def tokenize(text: str) -> list[str]:
    chinese = re.search(r"[\u4e00-\u9fff]", text) is not None
    if chinese:
        import jieba

        words = [w.strip() for w in jieba.lcut(text) if w.strip()]
        stops = set(ENGLISH_STOP_WORDS) | CN_STOP
    else:
        words = re.findall(r"[a-z0-9]+", text)
        stops = set(ENGLISH_STOP_WORDS)
    kept = []
    for word in words:
        if word in stops:
            continue
        if word.isascii() and len(word) < 2:
            continue
        if not word.isascii() and len(word) < 2:
            continue
        kept.append(word)
    return kept
