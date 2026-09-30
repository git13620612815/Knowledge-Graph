import ipaddress
import re
import urllib.parse
from io import BytesIO

import tldextract

from app.ml.textutil import preprocess, tokenize

_tld = tldextract.TLDExtract(suffix_list_urls=())
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
REDIRECT_RE = re.compile(
    r"(https?://[^\s<>\"']+)\s*(?:->|跳转至|redirects?\s+to)\s*(https?://[^\s<>\"']+)",
    re.I,
)
META_RE = re.compile(r"url\s*=\s*(https?://[^\"'\s>]+)", re.I)

BRANDS = (
    "google", "microsoft", "apple", "paypal", "amazon", "facebook", "instagram",
    "netflix", "linkedin", "twitter", "yahoo", "outlook", "icloud", "adobe",
    "dropbox", "github", "alibaba", "taobao", "alipay", "tencent", "wechat",
    "baidu", "jd", "chase", "wellsfargo", "citibank", "hsbc", "dhl", "fedex",
    "ups", "office", "gmail", "steam", "ebay", "walmart", "spotify", "zoom",
    "slack", "openai", "icbc", "ccb", "abchina", "cmbchina", "qq", "163",
    "sina", "sohu", "douyin", "bilibili", "meituan",
)
SAFE_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "paypal.com", "amazon.com",
    "facebook.com", "instagram.com", "netflix.com", "linkedin.com", "github.com",
    "adobe.com", "dropbox.com", "alipay.com", "taobao.com", "qq.com", "baidu.com",
    "jd.com", "icloud.com", "office.com", "live.com", "outlook.com",
}
COUNT_TYPES = {"Url", "Domain", "Sender", "Logo", "CertIssuer", "Ip"}


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 1:
        return 2
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins = cur[j - 1] + 1
            delete = prev[j] + 1
            sub = prev[j - 1] + (ca != cb)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalize_url(url: str) -> str:
    url = url.strip().rstrip(".,);]>'\"")
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host:
        return url
    port = parts.port
    scheme = (parts.scheme or "http").lower()
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    path = parts.path or ""
    query = f"?{parts.query}" if parts.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def registered_domain(host: str) -> str:
    if is_ip(host):
        return host
    ext = _tld(host)
    return (ext.registered_domain or host).lower()


def subdomain_count(host: str) -> int:
    if is_ip(host):
        return 0
    ext = _tld(host)
    if not ext.subdomain:
        return 0
    return len([p for p in ext.subdomain.split(".") if p])


def brand_lookalike(domain: str) -> bool:
    if domain in SAFE_DOMAINS or is_ip(domain):
        return False
    sld = domain.split(".")[0]
    if len(sld) < 4 or sld in BRANDS:
        return False
    return any(levenshtein(sld, brand) == 1 for brand in BRANDS)


def _ratio(text: str, pred) -> float:
    if not text:
        return 0.0
    return round(sum(1 for ch in text if pred(ch)) / len(text), 4)


def phash_of(image_bytes: bytes) -> str | None:
    try:
        import imagehash
        from PIL import Image
    except Exception:
        return None
    try:
        img = Image.open(BytesIO(image_bytes)).convert("RGB")
        return str(imagehash.phash(img))
    except Exception:
        return None


def hamming_hex(a: str, b: str) -> int:
    try:
        return (int(a, 16) ^ int(b, 16)).bit_count()
    except ValueError:
        return 99


def top_keywords(text: str, vectorizer, limit: int = 8) -> list[str]:
    if vectorizer is None:
        tokens = tokenize(preprocess(text))
        seen = []
        for token in tokens:
            if token not in seen:
                seen.append(token)
            if len(seen) >= limit:
                break
        return seen
    vec = vectorizer.transform([text])
    if vec.nnz == 0:
        return []
    names = vectorizer.get_feature_names_out()
    row = vec.tocoo()
    pairs = sorted(zip(row.data, row.col), reverse=True)
    words = []
    for _, col in pairs:
        word = str(names[col])
        if word in {"url", "email"}:
            continue
        words.append(word)
        if len(words) >= limit:
            break
    return words


def extract_mail(
    *,
    sample_key: str,
    subject: str,
    body: str,
    from_addr: str | None = None,
    html: str | None = None,
    images: list[bytes] | None = None,
    cert_map: dict[str, str] | None = None,
    vectorizer=None,
    known_logos: list[str] | None = None,
) -> dict:
    cert_map = cert_map or {}
    images = images or []
    known_logos = list(known_logos or [])
    nodes: dict[str, dict] = {}
    edges: list[tuple[str, str, str]] = []

    def add_node(biz_id: str, ntype: str, name: str, props: dict | None = None):
        if biz_id not in nodes:
            nodes[biz_id] = {"type": ntype, "name": name[:500], "props": props or {}}
        return biz_id

    def add_edge(rel: str, src: str, dst: str):
        if src and dst and src != dst:
            edges.append((rel, src, dst))

    email_id = f"email:{sample_key}"
    add_node(email_id, "Email", (subject or "未命名邮件")[:80], {"subject": subject or ""})

    sender_match = EMAIL_RE.search(from_addr or "")
    if sender_match:
        sender = sender_match.group(0).lower()
        sender_id = f"sender:{sender}"
        add_node(sender_id, "Sender", sender, {"display_name": (from_addr or "")[:120], "domain": sender.split("@")[-1]})
        add_edge("SENT_BY", email_id, sender_id)

    raw_for_url = f"{subject or ''}\n{body or ''}\n{html or ''}"
    urls = []
    seen_url = set()
    for match in URL_RE.findall(raw_for_url):
        norm = normalize_url(match)
        if not norm or norm in seen_url:
            continue
        seen_url.add(norm)
        urls.append(norm)

    for url in urls:
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
        url_id = f"url:{url}"
        add_node(
            url_id,
            "Url",
            url,
            {
                "raw": url,
                "has_ip_host": is_ip(host),
                "length": len(url),
                "digit_ratio": _ratio(url, str.isdigit),
                "special_ratio": _ratio(url, lambda c: not c.isalnum()),
            },
        )
        add_edge("CONTAINS_URL", email_id, url_id)
        if not host:
            continue
        if is_ip(host):
            ip_id = f"ip:{host}"
            add_node(ip_id, "Ip", host, {"version": 6 if ":" in host else 4})
            domain_id = f"domain:{host}"
            add_node(domain_id, "Domain", host, {"subdomain_count": 0, "brand_lookalike": False, "has_ip_host": True})
            add_edge("HOSTED_ON", url_id, domain_id)
            add_edge("RESOLVES_TO", domain_id, ip_id)
            continue
        domain = registered_domain(host)
        domain_id = f"domain:{domain}"
        add_node(
            domain_id,
            "Domain",
            domain,
            {
                "subdomain_count": subdomain_count(host),
                "brand_lookalike": brand_lookalike(domain),
                "has_ip_host": False,
            },
        )
        add_edge("HOSTED_ON", url_id, domain_id)
        issuer = cert_map.get(domain)
        if issuer:
            issuer_key = re.sub(r"\s+", "", issuer.lower())
            issuer_id = f"issuer:{issuer_key}"
            add_node(issuer_id, "CertIssuer", issuer, {"name": issuer})
            add_edge("ISSUED_BY", domain_id, issuer_id)

    redirect_sources = f"{body or ''}\n{html or ''}"
    for src, dst in REDIRECT_RE.findall(redirect_sources):
        add_edge("REDIRECTS_TO", f"url:{normalize_url(src)}", f"url:{normalize_url(dst)}")
    for target in META_RE.findall(html or ""):
        if urls:
            add_edge("REDIRECTS_TO", f"url:{urls[0]}", f"url:{normalize_url(target)}")

    logos = []
    for blob in images[:3]:
        digest = phash_of(blob)
        if not digest:
            continue
        logo_id = f"logo:{digest}"
        add_node(logo_id, "Logo", digest, {"phash": digest})
        add_edge("HAS_LOGO", email_id, logo_id)
        logos.append(digest)
    pool = known_logos + logos
    for digest in logos:
        for other in pool:
            if other == digest:
                continue
            if hamming_hex(digest, other) <= 8:
                add_edge("SIMILAR_LOGO", f"logo:{digest}", f"logo:{other}")

    for word in top_keywords(f"{subject or ''} {body or ''}", vectorizer):
        word_id = f"keyword:{word.lower()}"
        add_node(word_id, "Keyword", word.lower(), {"tfidf": 1})
        add_edge("MENTIONS", email_id, word_id)

    return {"nodes": nodes, "edges": edges, "email_id": email_id}
