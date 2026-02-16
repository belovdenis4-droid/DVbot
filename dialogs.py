import os
from datetime import datetime, timedelta

import requests

OPENLINES_WEBHOOK_URL = os.environ.get("BITRIX_OPENLINES_WEBHOOK_URL") or os.environ.get("BITRIX_OLBOT_WEBHOOK_URL") or os.environ.get("BITRIX_WEBHOOK_URL")


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
        if used_base_url:
            dialog_id_for_history = _get_dialog_id_for_session(used_base_url, session_id)
            normalized = _normalize_dialog_id(dialog_id_for_history)
            if normalized:
                response_dialog_id = normalized

        result = data.get("result") or {}
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

            if not messages:
                _send(send_message, dialog_id, "История диалога пуста.", **kwargs)
                return
        lines = []
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
            lines.append(f"{author}: {text}")
        if not lines:
            _send(send_message, dialog_id, "В истории нет текстовых сообщений.", **kwargs)
            return
        output = "\n".join(lines)
        for chunk in _chunk_text(output):
            _send(send_message, response_dialog_id, chunk, **kwargs)
    except Exception as e:
        _send(send_message, dialog_id, f"Ошибка получения истории: {e}", **kwargs)
