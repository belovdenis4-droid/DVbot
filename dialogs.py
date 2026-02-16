import os
import requests

OPENLINES_WEBHOOK_URL = os.environ.get("BITRIX_OPENLINES_WEBHOOK_URL") or os.environ.get("BITRIX_OLBOT_WEBHOOK_URL") or os.environ.get("BITRIX_WEBHOOK_URL")


def _send(send_message, dialog_id, text, **kwargs):
    if kwargs:
        send_message(dialog_id, text, **kwargs)
    else:
        send_message(dialog_id, text)


def _chunk_text(text, size=3000):
    return [text[i:i + size] for i in range(0, len(text), size)] if text else []


def handle_dialogs_command(dialog_id, send_message, message_text=None, **kwargs):
    if not message_text or message_text.strip().lower() == "dialogs":
        _send(send_message, dialog_id, f"dialog_id: {dialog_id}", **kwargs)
        return

    parts = message_text.strip().split()
    if len(parts) < 2 or not parts[1].isdigit():
        _send(send_message, dialog_id, "Использование: dialogs <session_id>", **kwargs)
        return

    session_id = parts[1]
    if not OPENLINES_WEBHOOK_URL:
        _send(send_message, dialog_id, "Не задан BITRIX_OPENLINES_WEBHOOK_URL.", **kwargs)
        return

    url = f"{OPENLINES_WEBHOOK_URL.rstrip('/')}/imopenlines.session.history.get.json"
    try:
        res = requests.post(url, json={"SESSION_ID": session_id}, timeout=30)
        res.raise_for_status()
        data = res.json()
        if "result" not in data:
            err = data.get("error_description") or data.get("error") or "Unknown error"
            _send(send_message, dialog_id, f"Ошибка Bitrix: {err}", **kwargs)
            return
        result = data.get("result") or {}
        messages = result.get("MESSAGES") or result.get("messages") or []
        if not messages:
            _send(send_message, dialog_id, "История диалога пуста.", **kwargs)
            return
        lines = []
        for msg in messages:
            text = (msg.get("MESSAGE") or msg.get("message") or "").strip()
            if not text:
                continue
            author = msg.get("AUTHOR_ID") or msg.get("author_id") or "?"
            lines.append(f"{author}: {text}")
        if not lines:
            _send(send_message, dialog_id, "В истории нет текстовых сообщений.", **kwargs)
            return
        output = "\n".join(lines)
        for chunk in _chunk_text(output):
            _send(send_message, dialog_id, chunk, **kwargs)
    except Exception as e:
        _send(send_message, dialog_id, f"Ошибка получения истории: {e}", **kwargs)
