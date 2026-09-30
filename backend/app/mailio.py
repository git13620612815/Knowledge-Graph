import io
import csv
import zipfile
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from pathlib import Path

MAX_SINGLE = 20 * 1024 * 1024
MAX_ZIP = 50 * 1024 * 1024
MAX_DETECT = 200
MAX_DATASET = 5000


class MailParseError(ValueError):
    pass


def decode_header_value(value: str | None) -> str:
    if not value:
        return ""
    chunks = []
    for text, enc in decode_header(value):
        if isinstance(text, bytes):
            chunks.append(text.decode(enc or "utf-8", errors="replace"))
        else:
            chunks.append(text)
    return "".join(chunks)


def decode_bytes(payload: bytes) -> str:
    for enc in ("utf-8", "gb18030"):
        try:
            return payload.decode(enc)
        except UnicodeDecodeError:
            continue
    return payload.decode("utf-8", errors="replace")


def parse_eml(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    subject = decode_header_value(msg.get("subject"))
    from_addr = decode_header_value(msg.get("from"))
    texts: list[str] = []
    htmls: list[str] = []
    images: list[bytes] = []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        payload = part.get_payload(decode=True) or b""
        if ctype == "text/plain":
            texts.append(decode_bytes(payload))
        elif ctype == "text/html":
            htmls.append(decode_bytes(payload))
        elif ctype in {"image/png", "image/jpeg", "image/webp"} and payload:
            images.append(payload)
    body = "\n".join(t for t in texts if t.strip()) or "\n".join(htmls)
    return {"subject": subject[:500], "body": body, "from_addr": from_addr or None, "html": "\n".join(htmls), "images": images[:3]}


def parse_txt(raw: bytes) -> dict:
    text = decode_bytes(raw).strip()
    subject = ""
    body = text
    if text.lower().startswith("subject:"):
        first, _, rest = text.partition("\n")
        subject = first.split(":", 1)[1].strip()[:500]
        body = rest.strip()
    return {"subject": subject, "body": body, "from_addr": None, "html": "", "images": []}


def parse_csv(raw: bytes, require_label: bool) -> list[dict]:
    text = decode_bytes(raw)
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise MailParseError("CSV 缺少表头")
    fields = {name.strip().lower(): name for name in reader.fieldnames if name}
    if "subject" not in fields or "body" not in fields:
        raise MailParseError("CSV 必须包含 subject 和 body 列")
    if require_label and "label" not in fields:
        raise MailParseError("数据集 CSV 必须包含 label 列，取值为 phish 或 ham")
    rows = []
    errors = []
    for index, row in enumerate(reader, start=2):
        subject = (row.get(fields["subject"]) or "").strip()
        body = (row.get(fields["body"]) or "").strip()
        from_addr = (row.get(fields["from_addr"]) or "").strip() if "from_addr" in fields else ""
        label = (row.get(fields["label"]) or "").strip().lower() if "label" in fields else ""
        if require_label and label not in {"phish", "ham"}:
            errors.append(f"第 {index} 行 label 必须是 phish 或 ham")
            continue
        if not require_label:
            label = ""
        if not body:
            errors.append(f"第 {index} 行正文为空")
            continue
        rows.append({
            "subject": subject[:500],
            "body": body[:500000],
            "from_addr": from_addr or None,
            "label": label or None,
            "html": "",
            "images": [],
        })
    if errors:
        raise MailParseError("；".join(errors[:8]))
    if not rows:
        raise MailParseError("CSV 中没有可用邮件")
    return rows


def parse_upload(filename: str, raw: bytes, *, require_label: bool, batch_limit: int, default_label: str | None = None) -> tuple[list[dict], list[str]]:
    name = (filename or "").lower()
    if name.endswith(".zip"):
        if len(raw) > MAX_ZIP:
            raise MailParseError("批量压缩包不能超过 50 MB")
        return _parse_zip(raw, require_label=require_label, batch_limit=batch_limit, default_label=default_label)
    if len(raw) > MAX_SINGLE:
        raise MailParseError("单个文件不能超过 20 MB")
    if name.endswith(".csv"):
        rows = parse_csv(raw, require_label=require_label)
    elif name.endswith(".eml"):
        item = parse_eml(raw)
        item["label"] = default_label if require_label else None
        rows = [item]
    elif name.endswith(".txt"):
        item = parse_txt(raw)
        item["label"] = default_label if require_label else None
        rows = [item]
    else:
        raise MailParseError("仅支持 eml、txt、csv 或 zip")
    if require_label:
        for row in rows:
            if row.get("label") not in {"phish", "ham"}:
                raise MailParseError("数据集中的 eml/txt/zip 需要同时选择统一标签 phish 或 ham；混合数据请使用 CSV")
    if len(rows) > batch_limit:
        raise MailParseError(f"单次最多 {batch_limit} 封，请拆分后再上传")
    return rows, []


def _parse_zip(raw: bytes, *, require_label: bool, batch_limit: int, default_label: str | None) -> tuple[list[dict], list[str]]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise MailParseError("压缩包无法打开") from exc
    rows: list[dict] = []
    errors: list[str] = []
    total = 0
    for info in zf.infolist():
        if info.is_dir():
            continue
        filename = info.filename.replace("\\", "/")
        if filename.startswith("/") or ".." in Path(filename).parts:
            raise MailParseError("压缩包路径不合法")
        total += info.file_size
        if total > MAX_ZIP:
            raise MailParseError("解压后体积超过 50 MB，请拆分后再上传")
        suffix = Path(filename).suffix.lower()
        if suffix not in {".eml", ".txt", ".csv"}:
            continue
        data = zf.read(info)
        try:
            part, _ = parse_upload(
                Path(filename).name,
                data,
                require_label=require_label,
                batch_limit=batch_limit,
                default_label=default_label,
            )
        except MailParseError as exc:
            errors.append(f"{filename}: {exc}")
            continue
        rows.extend(part)
        if len(rows) > batch_limit:
            raise MailParseError(f"单次最多 {batch_limit} 封，请拆分后再上传")
    if not rows and errors:
        raise MailParseError("；".join(errors[:8]))
    if not rows:
        raise MailParseError("压缩包中没有 eml、txt 或 csv")
    return rows, errors
