import base64
import io
import logging
import os
import re
from openpyxl import Workbook
from datetime import datetime, timedelta

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


def _extract_sessions(data):
    result = data.get("result")
    next_start = data.get("next")
    items = []
    if isinstance(result, dict):
        next_start = result.get("next") or next_start
        items = (
            result.get("items")
            or result.get("sessions")
            or result.get("result")
            or result.get("list")
            or []
        )
    elif isinstance(result, list):
        items = result
    return items or [], next_start


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


def _extract_date(item):
    for key in ("DATE_CREATE", "DATE_CREATE_TS", "DATE_CREATE_FORMAT"):
        value = item.get(key)
        if value:
            return str(value)
    return "?"


def _extract_client_label(item):
    first = (item.get("USER_NAME") or "").strip()
    last = (item.get("USER_LAST_NAME") or "").strip()
    second = (item.get("USER_SECOND_NAME") or "").strip()
    full_name = " ".join(part for part in [last, first, second] if part)
    if full_name:
        return full_name
    for key in ("USER_LOGIN", "USER_EMAIL"):
        value = (item.get(key) or "").strip()
        if value:
            return value
    for key in ("USER_ID", "CLIENT_ID", "CHAT_ID", "DIALOG_ID"):
        value = item.get(key)
        if value is not None and str(value).strip():
            return f"{key}:{value}"
    return "?"


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


def _build_xlsx_bytes(headers, rows):
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Dialog"
    sheet.append(headers)
    for row in rows:
        sheet.append(row)
    output = io.BytesIO()
    workbook.save(output)
    return output.getvalue()


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


def _send_dialogs_list(dialog_id, send_message, base_url, **kwargs):
    date_from = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    start = 0
    items_by_id = {}
    last_error = None
    try:
        for url_base in _iter_base_urls(base_url):
            url = f"{url_base.rstrip('/')}/imopenlines.session.list.json"
            start = 0
            items_by_id = {}
            while True:
                payload = {
                    "FILTER": {">=DATE_CREATE": date_from},
                    "SELECT": [
                        "ID",
                        "DIALOG_ID",
                        "DATE_CREATE",
                        "USER_ID",
                        "USER_NAME",
                        "USER_LAST_NAME",
                        "USER_SECOND_NAME",
                        "USER_LOGIN",
                        "USER_EMAIL",
                        "CHAT_ID",
                    ],
                    "ORDER": {"ID": "DESC"},
                    "start": start,
                }
                res = requests.post(url, json=payload, timeout=30)
                if res.status_code == 404:
                    last_error = f"404 Not Found for url: {url}"
                    items_by_id = {}
                    break
                res.raise_for_status()
                data = res.json()
                if "result" not in data:
                    err = data.get("error_description") or data.get("error") or "Unknown error"
                    _send(send_message, dialog_id, f"Ошибка Bitrix: {err}", **kwargs)
                    return
                items, next_start = _extract_sessions(data)
                for item in items:
                    entry = item or {}
                    session_id = _extract_session_id(entry)
                    if session_id and session_id not in items_by_id:
                        items_by_id[session_id] = {
                            "date": _extract_date(entry),
                            "client": _extract_client_label(entry),
                        }
                if next_start is None:
                    break
                start = next_start
            if items_by_id:
                break
    except Exception as e:
        _send(send_message, dialog_id, f"Ошибка получения списка: {e}", **kwargs)
        return

    if not items_by_id and last_error:
        _send(send_message, dialog_id, f"Ошибка получения списка: {last_error}", **kwargs)
        return

    if not items_by_id:
        _send(send_message, dialog_id, "За последние 7 дней диалогов не найдено.", **kwargs)
        return

    header = f"Диалоги за последние 7 дней: {len(items_by_id)}"
    lines = []
    for session_id, meta in items_by_id.items():
        lines.append(f"{session_id} | {meta['date']} | {meta['client']}")
    output = "\n".join([header] + lines)
    for chunk in _chunk_text(output):
        _send(send_message, dialog_id, chunk, **kwargs)


def handle_dialogs_command(dialog_id, send_message, message_text=None, **kwargs):
    text = (message_text or "").strip()
    if not text:
        _send(send_message, dialog_id, f"dialog_id: {dialog_id}", **kwargs)
        return

    parts = text.split()
    if len(parts) == 1 or parts[1].lower() in {"list", "recent"}:
        base_url = _get_base_url(**kwargs)
        kwargs = {k: v for k, v in kwargs.items() if k != "base_url"}
        _send_dialogs_list(dialog_id, send_message, base_url, **kwargs)
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
        data = None
        last_error = None
        used_base_url = None
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
                _send(send_message, dialog_id, f"Ошибка Bitrix: {err}", **kwargs)
                return
            used_base_url = url_base
            break

        if data is None:
            _send(
                send_message,
                dialog_id,
                f"Ошибка получения истории: {last_error or 'Unknown error'}",
                **kwargs,
            )
            return

        response_dialog_id = dialog_id
        dialog_id_for_history = None
        dialog_info = None
        guest_label = "Гость"
        guest_user_id = None
        if used_base_url:
            dialog_info = _get_dialog_info_for_session(used_base_url, session_id)
            if dialog_info:
                dialog_id_for_history = (
                    dialog_info.get("DIALOG_ID")
                    or dialog_info.get("dialog_id")
                    or dialog_info.get("CHAT_ID")
                    or dialog_info.get("chat_id")
                )
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
            if not dialog_id_for_history:
                dialog_id_for_history = _get_dialog_id_for_session(used_base_url, session_id)
            normalized = _normalize_dialog_id(dialog_id_for_history)
            if normalized:
                response_dialog_id = normalized

        result = data.get("result") or {}
        user_map = _extract_user_map(result)
        messages = result.get("MESSAGES") or result.get("messages") or []
        if not messages:
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
                _send(send_message, dialog_id, "История диалога пуста.", **kwargs)
                return
        lines = []
        rows = []
        user_name_cache = {}
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
            if not cleaned_text:
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
                direction = "Исх"
            else:
                if is_guest_by_id:
                    speaker = guest_label
                else:
                    speaker = author_name or guest_label
                direction = "Вх" if speaker == guest_label else "Исх"
            lines.append(f"{speaker}: {cleaned_text}")
            rows.append([session_id, msg_date, direction, speaker, cleaned_text])
        if not lines:
            _send(send_message, dialog_id, "В истории нет текстовых сообщений.", **kwargs)
            return
        output = "\n".join(lines)
        bot_id = kwargs.get("bot_id")
        client_id = kwargs.get("client_id")
        folder_id = os.environ.get("BITRIX_DIALOGS_FOLDER_ID")
        chat_id = _extract_chat_id(response_dialog_id)

        if folder_id and chat_id and used_base_url:
            file_name = f"dialogs_{session_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
            headers = ["dialog_id", "Дата", "Направление", "Имя", "сообщение"]
            content_bytes = _build_xlsx_bytes(headers, rows)
            disk_id = _upload_file_to_bitrix_disk(
                used_base_url,
                folder_id,
                file_name,
                content_bytes,
            )
            if disk_id and _commit_file_to_chat(used_base_url, chat_id, disk_id, message="История диалога"):
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
