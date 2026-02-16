import base64
import csv
import io
import logging
import os
import re
import zipfile
from datetime import datetime, timedelta
from xml.etree import ElementTree

import requests

OPENLINES_WEBHOOK_URL = os.environ.get("BITRIX_OPENLINES_WEBHOOK_URL") or os.environ.get("BITRIX_OLBOT_WEBHOOK_URL") or os.environ.get("BITRIX_WEBHOOK_URL")
logger = logging.getLogger(__name__)


def _send(send_message, dialog_id, text, **kwargs):
    if kwargs:
        send_message(dialog_id, text, **kwargs)
    else:
        send_message(dialog_id, text)


def _chunk_text(text, size=3000):
    return [text[i:i + size] for i in range(0, len(text), size)] if text else []


def _get_base_url(**kwargs):
    return kwargs.get("base_url") or OPENLINES_WEBHOOK_URL


def _iter_base_urls(primary_url):
    seen = set()
    candidates = [
        os.environ.get("BITRIX_OPENLINES_WEBHOOK_URL"),
        os.environ.get("BITRIX_WEBHOOK_URL"),
        primary_url,
        OPENLINES_WEBHOOK_URL,
        os.environ.get("BITRIX_OLBOT_WEBHOOK_URL"),
    ]
    for url in candidates:
        if url and url not in seen:
            seen.add(url)
            yield url


def _get_disk_base_url(fallback_url):
    return os.environ.get("BITRIX_WEBHOOK_URL") or fallback_url


def _extract_session_id(item):
    for key in ("ID", "id", "SESSION_ID", "session_id"):
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    for key in ("DIALOG_ID", "dialog_id"):
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _normalize_dialog_id(value):
    if value is None:
        return None
    dialog_id = str(value).strip()
    if dialog_id.isdigit():
        return f"chat{dialog_id}"
    return dialog_id


def _get_dialog_id_for_session(base_url, session_id):
    try:
        res = requests.post(
            f"{base_url.rstrip('/')}/imopenlines.dialog.get.json",
            json={"SESSION_ID": session_id},
            timeout=30,
        )
        if res.status_code == 404:
            return None
        res.raise_for_status()
        data = res.json()
        if "result" not in data:
            return None
        result = data.get("result") or {}
        return (
            result.get("DIALOG_ID")
            or result.get("dialog_id")
            or result.get("CHAT_ID")
            or result.get("chat_id")
        )
    except Exception:
        return None


def _get_dialog_info_for_session(base_url, session_id):
    try:
        res = requests.post(
            f"{base_url.rstrip('/')}/imopenlines.dialog.get.json",
            json={"SESSION_ID": session_id},
            timeout=30,
        )
        if res.status_code == 404:
            return None
        res.raise_for_status()
        data = res.json()
        if "result" not in data:
            return None
        return data.get("result") or {}
    except Exception:
        return None


def _extract_chat_id(value):
    if value is None:
        return None
    dialog_id = str(value).strip()
    if dialog_id.startswith("chat") and dialog_id[4:].isdigit():
        return int(dialog_id[4:])
    if dialog_id.isdigit():
        return int(dialog_id)
    return None


def _upload_file_to_bitrix_disk(base_url, folder_id, file_name, content_bytes):
    if not base_url or not folder_id:
        return None
    try:
        url = f"{base_url.rstrip('/')}/disk.folder.uploadfile.json"
        payload = {
            "id": folder_id,
            "data": {"NAME": file_name},
            "fileContent": [file_name, base64.b64encode(content_bytes).decode("ascii")],
        }
        res = requests.post(url, json=payload, timeout=60)
        if res.status_code == 404:
            return None
        res.raise_for_status()
        data = res.json()
        result = data.get("result") or {}
        disk_id = result.get("ID") or result.get("id") or result.get("DISK_ID")
        return str(disk_id) if disk_id else None
    except Exception as exc:
        logger.warning("Disk upload failed: %s", exc)
        return None


def _commit_file_to_chat(base_url, chat_id, disk_id, message=None):
    if not base_url or not chat_id or not disk_id:
        return False
    try:
        url = f"{base_url.rstrip('/')}/im.disk.file.commit.json"
        payload = {"CHAT_ID": chat_id, "DISK_ID": disk_id}
        if message:
            payload["MESSAGE"] = message
        res = requests.post(url, json=payload, timeout=30)
        if res.status_code == 404:
            return False
        res.raise_for_status()
        data = res.json()
        return data.get("result") is True
    except Exception as exc:
        logger.warning("Disk commit failed: %s", exc)
        return False


def _get_disk_download_url(base_url, disk_id):
    if not base_url or not disk_id:
        return None
    try:
        url = f"{base_url.rstrip('/')}/disk.file.get.json"
        res = requests.post(url, json={"id": disk_id}, timeout=30)
        if not res.ok:
            return None
        data = res.json()
        result = data.get("result") or {}
        return result.get("DOWNLOAD_URL")
    except Exception:
        return None


def _send_openlines_session_message(base_url, session_id, text, bot_id=None, client_id=None):
    if not base_url or not session_id or not bot_id:
        return False
    try:
        url = f"{base_url.rstrip('/')}/imopenlines.bot.session.message.send.json"
        payload = {
            "BOT_ID": bot_id,
            "SESSION_ID": session_id,
            "MESSAGE": text,
        }
        if client_id:
            payload["CLIENT_ID"] = client_id
        res = requests.post(url, json=payload, timeout=30)
        if res.status_code == 404:
            return False
        res.raise_for_status()
        data = res.json()
        if "result" in data:
            return True
        return False
    except Exception as exc:
        logger.warning("Openlines send failed: %s", exc)
        return False


def _column_letter(index):
    result = ""
    while index > 0:
        index, remainder = divmod(index - 1, 26)
        result = chr(65 + remainder) + result
    return result


def _xlsx_escape(value):
    text = str(value) if value is not None else ""
    text = (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return text


def _build_xlsx_bytes(headers, rows):
    def cell_xml(col_idx, row_idx, value):
        ref = f"{_column_letter(col_idx)}{row_idx}"
        text = _xlsx_escape(value)
        space_attr = ' xml:space="preserve"' if text.startswith(" ") or text.endswith(" ") else ""
        return f'<c r="{ref}" t="inlineStr"><is><t{space_attr}>{text}</t></is></c>'

    sheet_rows = []
    header_cells = "".join(
        cell_xml(col_idx + 1, 1, header)
        for col_idx, header in enumerate(headers)
    )
    sheet_rows.append(f'<row r="1">{header_cells}</row>')
    for row_idx, row in enumerate(rows, start=2):
        row_cells = "".join(
            cell_xml(col_idx + 1, row_idx, value)
            for col_idx, value in enumerate(row)
        )
        sheet_rows.append(f'<row r="{row_idx}">{row_cells}</row>')

    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<sheetData>"
        + "".join(sheet_rows)
        + "</sheetData></worksheet>"
    )
    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Dialog" sheetId="1" r:id="rId1"/></sheets>'
        "</workbook>"
    )
    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        "</Relationships>"
    )
    workbook_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/>'
        "</Relationships>"
    )
    content_types_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        "</Types>"
    )

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", rels_xml)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return output.getvalue()


def _col_to_index(col_letters):
    col_letters = col_letters.upper()
    index = 0
    for char in col_letters:
        if not char.isalpha():
            break
        index = index * 26 + (ord(char) - ord("A") + 1)
    return index


def _extract_cell_value(cell, shared_strings, ns):
    cell_type = cell.get("t")
    if cell_type == "inlineStr":
        t = cell.find("main:is/main:t", ns)
        return t.text if t is not None else ""
    v = cell.find("main:v", ns)
    if v is None:
        return ""
    value = v.text or ""
    if cell_type == "s":
        try:
            return shared_strings[int(value)]
        except Exception:
            return ""
    return value


def _read_xlsx_rows(content_bytes):
    rows = []
    with zipfile.ZipFile(io.BytesIO(content_bytes)) as zf:
        sheet_path = None
        for name in zf.namelist():
            if name.startswith("xl/worksheets/") and name.endswith(".xml"):
                sheet_path = name
                break
        if not sheet_path:
            return rows

        shared_strings = []
        if "xl/sharedStrings.xml" in zf.namelist():
            shared_xml = zf.read("xl/sharedStrings.xml")
            shared_root = ElementTree.fromstring(shared_xml)
            ns = {"main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
            for si in shared_root.findall("main:si", ns):
                texts = [t.text or "" for t in si.findall(".//main:t", ns)]
                shared_strings.append("".join(texts))

        sheet_xml = zf.read(sheet_path)
        sheet_root = ElementTree.fromstring(sheet_xml)
        ns = {"main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        for row in sheet_root.findall(".//main:row", ns):
            cells = {}
            for cell in row.findall("main:c", ns):
                ref = cell.get("r") or ""
                col_letters = re.sub(r"\d+", "", ref)
                col_idx = _col_to_index(col_letters)
                if col_idx <= 0:
                    continue
                cells[col_idx] = _extract_cell_value(cell, shared_strings, ns)
            if cells:
                max_col = max(cells.keys())
                row_values = [cells.get(i, "") for i in range(1, max_col + 1)]
                rows.append(row_values)
    return rows


def _find_id_column(rows):
    if not rows:
        return 0
    header = rows[0]
    header_norm = [_normalize_name(h) for h in header]
    for idx, name in enumerate(header_norm):
        if name in {"№", "no", "number", "номер"}:
            return idx
    for idx, name in enumerate(header_norm):
        if any(tag in name for tag in ["id", "диалог", "dialog", "session", "сесс", "№", "номер", "no", "number"]):
            return idx
    # Fallback: column with most numeric values
    counts = {}
    for row in rows[1:]:
        for idx, value in enumerate(row):
            if re.search(r"\d+", str(value)):
                counts[idx] = counts.get(idx, 0) + 1
    if counts:
        return max(counts, key=counts.get)
    return 0


def _extract_ids_from_rows(rows):
    ids = []
    seen = set()
    col_idx = _find_id_column(rows)
    for row in rows[1:]:
        if col_idx >= len(row):
            continue
        value = str(row[col_idx]).strip()
        if not value:
            continue
        match = re.search(r"\d+", value)
        if not match:
            continue
        session_id = match.group(0)
        if session_id not in seen:
            seen.add(session_id)
            ids.append(session_id)
    return ids


def _extract_ids_from_text(text):
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    if not lines:
        return []
    if _normalize_name(lines[0]) in {"№", "no", "number", "номер"}:
        lines = lines[1:]
    ids = []
    seen = set()
    for line in lines:
        match = re.search(r"\d+", line)
        if not match:
            continue
        session_id = match.group(0)
        if session_id not in seen:
            seen.add(session_id)
            ids.append(session_id)
    return ids


def _parse_ids_from_file(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".csv":
        with open(file_path, "rb") as f:
            content = f.read()
        for encoding in ("utf-8-sig", "cp1251", "utf-8"):
            try:
                text = content.decode(encoding)
                break
            except Exception:
                text = None
        if text is None:
            return []
        reader = csv.reader(io.StringIO(text))
        rows = [row for row in reader if row]
        return _extract_ids_from_rows(rows)
    if ext == ".xlsx":
        with open(file_path, "rb") as f:
            content = f.read()
        rows = _read_xlsx_rows(content)
        return _extract_ids_from_rows(rows)
    return []


def _collect_dialog_rows_for_session(session_id, base_url, operator_names):
    data = None
    used_base_url = None
    last_error = None
    for url_base in _iter_base_urls(base_url):
        url = f"{url_base.rstrip('/')}/imopenlines.session.history.get.json"
        res = requests.post(url, json={"SESSION_ID": session_id}, timeout=30)
        if res.status_code == 404:
            last_error = f"404 Not Found for url: {url}"
            continue
        res.raise_for_status()
        data = res.json()
        if "result" not in data:
            err = data.get("error_description") or data.get("error") or "Unknown error"
            return [], None, f"Ошибка Bitrix: {err}"
        used_base_url = url_base
        break
    if data is None:
        return [], None, f"Ошибка получения истории: {last_error or 'Unknown error'}"

    result = data.get("result") or {}
    user_map = _extract_user_map(result)
    messages = result.get("MESSAGES") or result.get("messages") or []
    dialog_info = _get_dialog_info_for_session(used_base_url, session_id) if used_base_url else None
    guest_label = "Гость"
    guest_user_id = None
    if dialog_info:
        guest_user_id = (
            dialog_info.get("USER_ID")
            or dialog_info.get("user_id")
            or dialog_info.get("CLIENT_ID")
        )
        guest_name = " ".join(
            filter(
                None,
                [
                    dialog_info.get("USER_NAME"),
                    dialog_info.get("USER_LAST_NAME"),
                    dialog_info.get("USER_SECOND_NAME"),
                ],
            )
        ).strip()
        if guest_name:
            guest_label = guest_name

    if not messages:
        dialog_id_for_history = _get_dialog_id_for_session(used_base_url, session_id) if used_base_url else None
        if dialog_id_for_history:
            dialog_id_str = _normalize_dialog_id(dialog_id_for_history)
            im_res = requests.post(
                f"{used_base_url.rstrip('/')}/im.dialog.messages.get.json",
                json={"DIALOG_ID": dialog_id_str, "FIRST_ID": 0, "LIMIT": 200},
                timeout=30,
            )
            if im_res.status_code != 404:
                im_res.raise_for_status()
                im_data = im_res.json()
                if "result" in im_data:
                    im_result = im_data.get("result") or {}
                    messages = im_result.get("messages") or im_result.get("MESSAGES") or []
                    user_map = _extract_user_map(im_result) or user_map
    if not messages:
        return [], used_base_url, "История диалога пуста."

    rows = []
    user_name_cache = {}
    guest_label_norm = _normalize_name(guest_label)
    for msg in messages:
        text = (
            msg.get("MESSAGE")
            or msg.get("message")
            or msg.get("text")
            or msg.get("TEXT")
            or ""
        ).strip()
        if not text:
            continue
        author = msg.get("AUTHOR_ID") or msg.get("author_id") or "?"
        if _is_system_line(author, text):
            continue
        msg_date = (
            msg.get("DATE")
            or msg.get("date")
            or msg.get("DATE_CREATE")
            or msg.get("date_create")
            or ""
        )
        cleaned_text = _strip_bbcode(text)
        if not cleaned_text or not cleaned_text.strip():
            continue
        author_name = None
        author_key = str(author)
        if author_key in user_map:
            author_name = user_map.get(author_key)
        if author_name is None and author_key.isdigit():
            if author_key not in user_name_cache:
                user_name_cache[author_key] = _get_user_name(used_base_url, author_key)
            author_name = user_name_cache.get(author_key)
        is_guest_by_id = guest_user_id is not None and str(guest_user_id) == author_key
        if _is_operator_marker(cleaned_text):
            speaker = "Оператор"
        else:
            if is_guest_by_id:
                speaker = guest_label
            else:
                speaker = author_name or guest_label

        speaker_norm = _normalize_name(speaker)
        author_norm = _normalize_name(author_name)
        is_guest_by_name = (
            guest_label_norm
            and (speaker_norm == guest_label_norm or author_norm == guest_label_norm)
        ) or (
            guest_label_norm
            and (guest_label_norm in speaker_norm or speaker_norm in guest_label_norm)
        )
        if is_guest_by_id or is_guest_by_name:
            speaker = guest_label
            speaker_norm = guest_label_norm

        direction = "Исх" if speaker_norm in operator_names else "Вх"
        rows.append([session_id, msg_date, direction, speaker, cleaned_text])

    rows = [row for row in rows if str(row[4]).strip()]
    return rows, used_base_url, None


def _strip_bbcode(text):
    if not text:
        return ""
    # Remove common bbcode tags and separators
    text = re.sub(r"\[/?(b|i|u|s)\]", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\[URL[^\]]*\]", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\[/URL\]", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\[icon[^\]]*\]", "", text, flags=re.IGNORECASE)
    text = re.sub(r"-{3,}", "", text)
    return text.strip()


def _is_system_line(author_id, text):
    if author_id in {"?", None, ""}:
        return True
    lowered = (text or "").lower()
    system_markers = [
        "начат новый диалог",
        "сделка прикреплена",
        "заказ прикреплен",
        "контактная информация сохранена",
        "обращение направлено",
        "переадресовал диалог",
        "изменил название чата",
    ]
    if any(marker in lowered for marker in system_markers):
        return True
    if "[user=" in lowered:
        return True
    return False


def _is_operator_marker(text):
    lowered = (text or "").lower()
    return "отправлено из мессенджера" in lowered or "отправлено роботом" in lowered


def _normalize_name(value):
    if not value:
        return ""
    return " ".join(str(value).lower().split())


def _get_operator_names():
    raw = os.environ.get("BITRIX_OPERATOR_NAMES", "")
    names = {_normalize_name("Оператор")}
    for part in raw.split(","):
        normalized = _normalize_name(part)
        if normalized:
            names.add(normalized)
    return names


def _get_user_name(base_url, user_id):
    if not base_url or not user_id or not str(user_id).isdigit():
        return None


def _extract_user_map(result):
    user_map = {}
    users = result.get("USERS") or result.get("users") or []
    if isinstance(users, dict):
        users = users.values()
    if isinstance(users, list):
        for user in users:
            if not isinstance(user, dict):
                continue
            user_id = user.get("id") or user.get("ID")
            if user_id is None:
                continue
            name = user.get("name") or user.get("NAME")
            if not name:
                name = " ".join(filter(None, [user.get("NAME"), user.get("LAST_NAME")])).strip()
            if name:
                user_map[str(user_id)] = name
    return user_map
    try:
        res = requests.get(
            f"{base_url.rstrip('/')}/user.get.json",
            params={"ID": user_id},
            timeout=20,
        )
        if res.status_code == 404:
            return None
        res.raise_for_status()
        data = res.json()
        result = data.get("result") or []
        if isinstance(result, list) and result:
            user = result[0]
            name = " ".join(filter(None, [user.get("NAME"), user.get("LAST_NAME")])).strip()
            return name or None
        return None
    except Exception:
        return None


def handle_dialogs_command(dialog_id, send_message, message_text=None, **kwargs):
    text = (message_text or "").strip()
    if not text:
        _send(send_message, dialog_id, f"dialog_id: {dialog_id}", **kwargs)
        return

    parts = text.split()
    if len(parts) == 1:
        _send(send_message, dialog_id, "Вышлите файл диалогов (CSV/XLSX) с колонкой ID.", **kwargs)
        return

    if parts[1].lower() in {"id", "current"}:
        _send(send_message, dialog_id, f"dialog_id: {dialog_id}", **kwargs)
        return

    if not parts[1].isdigit():
        _send(
            send_message,
            dialog_id,
            "Использование: dialogs | dialogs <session_id>",
            **kwargs,
        )
        return

    session_id = parts[1]
    base_url = _get_base_url(**kwargs)

    try:
        operator_names = _get_operator_names()
        rows, used_base_url, error = _collect_dialog_rows_for_session(session_id, base_url, operator_names)
        if error:
            _send(send_message, dialog_id, error, **kwargs)
            return
        if not rows:
            _send(send_message, dialog_id, "В истории нет текстовых сообщений.", **kwargs)
            return
        output = "\n".join([f"{row[3]}: {row[4]}" for row in rows])
        bot_id = kwargs.get("bot_id")
        client_id = kwargs.get("client_id")
        folder_id = os.environ.get("BITRIX_DIALOGS_FOLDER_ID")
        chat_id = _extract_chat_id(dialog_id)
        upload_base_url = _get_disk_base_url(used_base_url)

        if folder_id and chat_id and upload_base_url:
            file_name = f"dialogs_{session_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
            headers = ["dialog_id", "Дата", "Направление", "Имя", "сообщение"]
            content_bytes = _build_xlsx_bytes(headers, rows)
            disk_id = _upload_file_to_bitrix_disk(
                upload_base_url,
                folder_id,
                file_name,
                content_bytes,
            )
            if disk_id and _commit_file_to_chat(upload_base_url, chat_id, disk_id, message="История диалога"):
                _send(
                    send_message,
                    response_dialog_id,
                    "Файл диалогов создан.",
                    **kwargs,
                )
                return

        for chunk in _chunk_text(output):
            sent = _send_openlines_session_message(
                used_base_url,
                session_id,
                chunk,
                bot_id=bot_id,
                client_id=client_id,
            )
            if not sent:
                _send(send_message, response_dialog_id, chunk, **kwargs)
    except Exception as e:
        _send(send_message, dialog_id, f"Ошибка получения истории: {e}", **kwargs)


def handle_dialogs_file(file_path, dialog_id, send_message, **kwargs):
    base_url = _get_base_url(**kwargs)
    session_ids = _parse_ids_from_file(file_path)
    if not session_ids:
        _send(send_message, dialog_id, "Не удалось найти ID в файле.", **kwargs)
        return

    operator_names = _get_operator_names()
    all_rows = []
    errors = []
    used_base_url = None
    for session_id in session_ids:
        rows, row_base_url, error = _collect_dialog_rows_for_session(session_id, base_url, operator_names)
        if row_base_url and not used_base_url:
            used_base_url = row_base_url
        if error:
            errors.append(f"{session_id}: {error}")
            continue
        all_rows.extend(rows)

    if not all_rows:
        _send(send_message, dialog_id, "Не удалось собрать историю по ID из файла.", **kwargs)
        return

    folder_id = os.environ.get("BITRIX_DIALOGS_FOLDER_ID")
    chat_id = _extract_chat_id(dialog_id)
    upload_base_url = _get_disk_base_url(used_base_url)
    if not folder_id or not chat_id or not upload_base_url:
        _send(send_message, dialog_id, "Не удалось отправить файл (нет Disk-параметров).", **kwargs)
        return

    file_name = f"dialogs_batch_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    headers = ["dialog_id", "Дата", "Направление", "Имя", "сообщение"]
    content_bytes = _build_xlsx_bytes(headers, all_rows)
    disk_id = _upload_file_to_bitrix_disk(upload_base_url, folder_id, file_name, content_bytes)
    if disk_id and _commit_file_to_chat(upload_base_url, chat_id, disk_id, message="История диалогов"):
        _send(send_message, dialog_id, "Файл диалогов создан.", **kwargs)
    else:
        download_url = _get_disk_download_url(upload_base_url, disk_id)
        if download_url:
            _send(send_message, dialog_id, f"Файл диалогов создан: {download_url}", **kwargs)
        else:
            _send(send_message, dialog_id, "Не удалось отправить файл диалогов.", **kwargs)
    if errors:
        _send(send_message, dialog_id, "Ошибки:\n" + "\n".join(errors[:20]), **kwargs)


def handle_dialogs_ids(message_text, dialog_id, send_message, **kwargs):
    base_url = _get_base_url(**kwargs)
    session_ids = _extract_ids_from_text(message_text)
    if not session_ids:
        _send(send_message, dialog_id, "Не удалось найти ID в тексте.", **kwargs)
        return

    operator_names = _get_operator_names()
    all_rows = []
    errors = []
    used_base_url = None
    for session_id in session_ids:
        rows, row_base_url, error = _collect_dialog_rows_for_session(session_id, base_url, operator_names)
        if row_base_url and not used_base_url:
            used_base_url = row_base_url
        if error:
            errors.append(f"{session_id}: {error}")
            continue
        all_rows.extend(rows)

    if not all_rows:
        _send(send_message, dialog_id, "Не удалось собрать историю по ID.", **kwargs)
        return

    folder_id = os.environ.get("BITRIX_DIALOGS_FOLDER_ID")
    chat_id = _extract_chat_id(dialog_id)
    upload_base_url = _get_disk_base_url(used_base_url)
    if not folder_id or not chat_id or not upload_base_url:
        _send(send_message, dialog_id, "Не удалось отправить файл (нет Disk-параметров).", **kwargs)
        return

    file_name = f"dialogs_batch_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    headers = ["dialog_id", "Дата", "Направление", "Имя", "сообщение"]
    content_bytes = _build_xlsx_bytes(headers, all_rows)
    disk_id = _upload_file_to_bitrix_disk(upload_base_url, folder_id, file_name, content_bytes)
    if disk_id and _commit_file_to_chat(upload_base_url, chat_id, disk_id, message="История диалогов"):
        _send(send_message, dialog_id, "Файл диалогов создан.", **kwargs)
    else:
        download_url = _get_disk_download_url(upload_base_url, disk_id)
        if download_url:
            _send(send_message, dialog_id, f"Файл диалогов создан: {download_url}", **kwargs)
        else:
            _send(send_message, dialog_id, "Не удалось отправить файл диалогов.", **kwargs)
    if errors:
        _send(send_message, dialog_id, "Ошибки:\n" + "\n".join(errors[:20]), **kwargs)
