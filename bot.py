
import os
import json
import logging
import asyncio
import hashlib
import re
import requests
import time
from pathlib import Path
import html
import zipfile
from io import BytesIO
from urllib.parse import urljoin
from flask import Flask, request, jsonify
from threading import Thread
from datetime import datetime # НОВОЕ: Добавлен импорт datetime

import gspread
from google.oauth2.service_account import Credentials
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters

# ---------- НАСТРОЙКИ ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
GOOGLE_JSON = os.environ.get("GOOGLE_JSON")
SPREADSHEET_ID = os.environ.get("SPREADSHEET_ID")
LLAMA_KEY = os.environ.get("LLAMA_CLOUD_API_KEY")
OCR_SPACE_KEY = os.environ.get("OCR_SPACE_KEY")
BITRIX_URL = os.environ.get("BITRIX_WEBHOOK_URL") 
BITRIX_TOKEN = os.environ.get("BITRIX_TOKEN")
BITRIX_BOT_ID = os.environ.get("BITRIX_BOT_ID") # ID вашего бота из Битрикс
BITRIX_CLIENT_ID = os.environ.get("BITRIX_CLIENT_ID")
BITRIX_OLBOT_CLIENT_ID = os.environ.get("BITRIX_OLBOT_CLIENT_ID")
BITRIX_OLBOT_ID = os.environ.get("BITRIX_OLBOT_ID")
BITRIX_OLBOT_WEBHOOK_URL = os.environ.get("BITRIX_OLBOT_WEBHOOK_URL")
BITRIX_KB_URL = os.environ.get("BITRIX_KB_URL")
BITRIX_KB_PUBLIC_URL = os.environ.get("BITRIX_KB_PUBLIC_URL", "https://apcom.bitrix24.ru/~4YqKJ")
BITRIX_KB_GOOGLE_DOC_URL = os.environ.get("BITRIX_KB_GOOGLE_DOC_URL")
KB_CACHE_TTL = int(os.environ.get("KB_CACHE_TTL", "900"))
BITRIX_EVENT_HANDLER_URL = os.environ.get("BITRIX_EVENT_HANDLER_URL")
BITRIX_APP_ACCESS_TOKEN = os.environ.get("BITRIX_APP_ACCESS_TOKEN")
BITRIX_PORTAL_URL = os.environ.get("BITRIX_PORTAL_URL")
BITRIX_APP_CLIENT_ID = os.environ.get("BITRIX_APP_CLIENT_ID")
BITRIX_APP_CLIENT_SECRET = os.environ.get("BITRIX_APP_CLIENT_SECRET")
BITRIX_APP_REDIRECT_URL = os.environ.get("BITRIX_APP_REDIRECT_URL")
BITRIX_OAUTH_URL = os.environ.get("BITRIX_OAUTH_URL", "https://oauth.bitrix.info/oauth/token/")
BITRIX_CLIENT_IDS = [c.strip() for c in os.environ.get("BITRIX_CLIENT_IDS", "").split(",") if c.strip()]
if BITRIX_CLIENT_ID:
    BITRIX_CLIENT_IDS.append(BITRIX_CLIENT_ID)
if BITRIX_OLBOT_CLIENT_ID:
    BITRIX_CLIENT_IDS.append(BITRIX_OLBOT_CLIENT_ID)
LAST_APP_AUTH = {}
KB_CACHE = {"ts": 0, "items": [], "errors": []}

# ID разрешенных чатов Битрикс (для ONIMMESSAGEADD), если используется
ALLOWED_BX_CHATS = os.environ.get("ALLOWED_BITRIX_CHATS", "").replace(" ", "").split(",")
BITRIX_GROUP_AUTO = os.environ.get("BITRIX_GROUP_AUTO", "").strip().lower() in ["1", "true", "yes", "on"]

creds_dict = json.loads(GOOGLE_JSON)
creds = Credentials.from_service_account_info(creds_dict, scopes=["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"])

# Инициализация объектов Google Sheets
gc = gspread.authorize(creds)
spreadsheet = gc.open_by_key(SPREADSHEET_ID)

# Основной лист для данных из PDF
try:
    main_data_sheet = spreadsheet.worksheet("Лист1")
except gspread.exceptions.WorksheetNotFound:
    logger.warning("Worksheet 'Лист1' not found, using first available sheet for main data.")
    main_data_sheet = spreadsheet.get_worksheet(0)

# Лист для тестовых сообщений
try:
    test_message_sheet = spreadsheet.worksheet("Тест")
except gspread.exceptions.WorksheetNotFound:
    logger.info("Worksheet 'Тест' not found, creating it.")
    test_message_sheet = spreadsheet.add_worksheet(title="Тест", rows="100", cols="10")
    # Добавляем заголовки для листа "Тест"
    test_message_sheet.append_row(["Тип", "Дата", "Отправитель", "Сообщение", "Хеш"])


app = Flask(__name__)

# Главная страница для Bitrix iframe
@app.route('/', methods=['GET'])
def index():
    return "Бот активен и слушает события Битрикс24 (локальное приложение).", 200

def exchange_oauth_code(code, server_domain=None):
    if not all([BITRIX_APP_CLIENT_ID, BITRIX_APP_CLIENT_SECRET, BITRIX_APP_REDIRECT_URL]):
        return None, "Missing BITRIX_APP_CLIENT_ID/SECRET/REDIRECT_URL in environment."
    token_url = BITRIX_OAUTH_URL
    if server_domain:
        if server_domain.startswith("http"):
            token_url = f"{server_domain.rstrip('/')}/oauth/token/"
        else:
            token_url = f"https://{server_domain}/oauth/token/"
    params = {
        "grant_type": "authorization_code",
        "client_id": BITRIX_APP_CLIENT_ID,
        "client_secret": BITRIX_APP_CLIENT_SECRET,
        "code": code,
        "redirect_uri": BITRIX_APP_REDIRECT_URL,
    }
    token_res = requests.get(token_url, params=params)
    token_res.raise_for_status()
    return token_res.json(), None

def _extract_auth_payload(form_data, json_data):
    auth = {
        "access_token": form_data.get("auth[access_token]") or (json_data.get("auth") or {}).get("access_token"),
        "refresh_token": form_data.get("auth[refresh_token]") or (json_data.get("auth") or {}).get("refresh_token"),
        "client_id": form_data.get("auth[client_id]") or (json_data.get("auth") or {}).get("client_id"),
        "application_token": form_data.get("auth[application_token]") or (json_data.get("auth") or {}).get("application_token"),
        "domain": form_data.get("auth[domain]") or (json_data.get("auth") or {}).get("domain"),
        "member_id": form_data.get("auth[member_id]") or (json_data.get("auth") or {}).get("member_id"),
        "expires_in": form_data.get("auth[expires_in]") or (json_data.get("auth") or {}).get("expires_in"),
    }
    return auth

def _mask_token(value):
    if not value:
        return "none"
    value = str(value)
    if len(value) <= 6:
        return f"{value[0]}...{value[-1]}(len={len(value)})"
    return f"{value[:3]}...{value[-3:]}(len={len(value)})"

def _is_login_page(html_text):
    if not html_text:
        return True
    return "Войти в Битрикс24" in html_text or "auth" in html_text.lower()

def _normalize_text(text):
    text = text.lower()
    text = re.sub(r"[^a-zа-я0-9]+", " ", text, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", text).strip()

def _tokenize(text):
    if not text:
        return set()
    return set(_normalize_text(text).split())

def _extract_docx_text(content_bytes):
    with zipfile.ZipFile(BytesIO(content_bytes)) as zf:
        if "word/document.xml" not in zf.namelist():
            return ""
        xml = zf.read("word/document.xml").decode("utf-8", errors="ignore")
    texts = re.findall(r"<w:t[^>]*>(.*?)</w:t>", xml)
    if not texts:
        return ""
    return re.sub(r"\s+", " ", html.unescape(" ".join(texts))).strip()

def _extract_doc_links(html_text, base_url):
    anchors = re.findall(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', html_text, flags=re.IGNORECASE | re.DOTALL)
    items = []
    for href, text in anchors:
        name = re.sub(r"\s+", " ", _strip_html(text)).strip()
        if not name.lower().endswith(".docx"):
            continue
        url = urljoin(base_url, href)
        items.append({"name": name, "url": url})
    if not items:
        download_match = re.search(r'href="([^"]*?/download/[^"]*)"', html_text, flags=re.IGNORECASE)
        if download_match:
            url = urljoin(base_url, download_match.group(1))
            title_match = re.search(r"<title[^>]*>(.*?)</title>", html_text, flags=re.IGNORECASE | re.DOTALL)
            name = re.sub(r"\s+", " ", _strip_html(title_match.group(1) if title_match else "Документ.docx")).strip()
            if not name.lower().endswith(".docx"):
                name = f"{name}.docx"
            items.append({"name": name, "url": url})
    return items

def _fetch_kb_source(url):
    if not url:
        return ""
    if "docs.google.com/document" in url:
        if "/document/d/e/" in url:
            if "output=txt" not in url:
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}output=txt"
        else:
            doc_id_match = re.search(r"/d/([a-zA-Z0-9_-]+)", url)
            if doc_id_match:
                doc_id = doc_id_match.group(1)
                url = f"https://docs.google.com/document/d/{doc_id}/export?format=txt"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    }
    res = requests.get(url, headers=headers, timeout=30)
    res.raise_for_status()
    return res.text

def _load_kb_documents():
    now = time.time()
    if KB_CACHE["items"] and (now - KB_CACHE["ts"] < KB_CACHE_TTL):
        return KB_CACHE["items"]
    sources = [BITRIX_KB_GOOGLE_DOC_URL, BITRIX_KB_URL, BITRIX_KB_PUBLIC_URL]
    items = []
    KB_CACHE["errors"] = []
    for source in sources:
        if not source:
            continue
        try:
            html_text = _fetch_kb_source(source)
            if source == BITRIX_KB_GOOGLE_DOC_URL:
                if "<html" in html_text.lower() or "sign in" in html_text.lower() or "browser version is no longer supported" in html_text.lower():
                    KB_CACHE["errors"].append("Google Doc требует публикации/доступа по ссылке.")
                    continue
                text = re.sub(r"\s+", " ", html_text).strip()
                if text:
                    items.append({
                        "name": "GoogleDoc",
                        "url": source,
                        "text": text,
                        "tokens": _tokenize(text),
                    })
                else:
                    KB_CACHE["errors"].append("Google Doc пуст или недоступен.")
                continue
            if _is_login_page(html_text):
                KB_CACHE["errors"].append("Bitrix KB требует авторизации или недоступна.")
                continue
            links = _extract_doc_links(html_text, source)
            for link in links:
                try:
                    file_res = requests.get(link["url"], timeout=30)
                    file_res.raise_for_status()
                    text = _extract_docx_text(file_res.content)
                    if not text:
                        continue
                    items.append({
                        "name": link["name"],
                        "url": link["url"],
                        "text": text,
                        "tokens": _tokenize(text),
                    })
                except Exception as e:
                    logger.warning(f"KB doc fetch failed: {link['url']} {e}", exc_info=True)
        except Exception as e:
            logger.warning(f"KB source fetch failed: {source} {e}", exc_info=True)
            KB_CACHE["errors"].append(f"KB source fetch failed: {source}")
    KB_CACHE["items"] = items
    KB_CACHE["ts"] = now
    return items

def find_kb_answer(query):
    docs = _load_kb_documents()
    if not docs:
        return None
    q_tokens = _tokenize(query)
    if not q_tokens:
        return None
    best = None
    best_score = 0
    for doc in docs:
        score = len(q_tokens & doc["tokens"])
        if score > best_score:
            best_score = score
            best = doc
    if not best or best_score == 0:
        return None
    snippet = best["text"][:800].strip()
    return {
        "name": best["name"],
        "snippet": snippet,
        "score": best_score,
        "query_terms": len(q_tokens),
    }

def build_kb_response(query):
    result = find_kb_answer(query)
    if not result:
        return None
    score = result["score"]
    query_terms = result["query_terms"] or 1
    ratio = score / query_terms
    if score < 2 and ratio < 0.2:
        return None
    return (
        "Я нашёл подходящую информацию по вашему вопросу:\n"
        f"{result['snippet']}\n\n"
        f"Источник: {result['name']}"
    )

def bind_events(access_token, portal_url, handler_url, event_names, rest_endpoint=None):
    if not (access_token and handler_url):
        return {"error": "missing_params"}
    if rest_endpoint:
        bind_url = f"{rest_endpoint.rstrip('/')}/event.bind.json"
    elif portal_url:
        bind_url = f"{portal_url.rstrip('/')}/rest/event.bind.json"
    else:
        return {"error": "missing_endpoint"}
    variants = list(event_names or [])
    last_res = None
    for event_name in variants:
        for auth_type in [1, None]:
            bind_payload = {
                "event": event_name,
                "handler": handler_url,
            }
            if auth_type is not None:
                bind_payload["auth_type"] = auth_type
            last_res = requests.post(bind_url, params={"auth": access_token}, json=bind_payload).json()
            if last_res.get("result") is True:
                last_res["event_name"] = event_name
                last_res["auth_type"] = auth_type
                return last_res
    if isinstance(last_res, dict):
        last_res["event_name"] = variants[-1] if variants else None
    return last_res

def get_bitrix_events(access_token, portal_url, rest_endpoint=None):
    if not access_token:
        return []
    if rest_endpoint:
        url = f"{rest_endpoint.rstrip('/')}/event.get.json"
    elif portal_url:
        url = f"{portal_url.rstrip('/')}/rest/event.get.json"
    else:
        return []
    res = requests.post(url, params={"auth": access_token}).json()
    return res.get("result", []) if isinstance(res, dict) else []

@app.route('/bitrix/install', methods=['GET', 'POST'], strict_slashes=False)
def bitrix_install():
    logger.info(
        "Bitrix install callback method=%s keys=%s args=%s",
        request.method,
        list(request.values.keys()),
        dict(request.args),
    )
    code = request.values.get("code")
    json_data = request.get_json(silent=True) or {}
    auth_payload = _extract_auth_payload(request.values, json_data)
    if auth_payload.get("access_token"):
        LAST_APP_AUTH.update(auth_payload)
        logger.info(
            "Bitrix install auth received: client_id=%s domain=%s member_id=%s access=%s",
            _mask_token(auth_payload.get("client_id")),
            auth_payload.get("domain"),
            _mask_token(auth_payload.get("member_id")),
            _mask_token(auth_payload.get("access_token")),
        )
        if BITRIX_EVENT_HANDLER_URL:
            portal_url = f"https://{auth_payload.get('domain')}" if auth_payload.get("domain") else get_bitrix_portal_url()
            rest_endpoint = auth_payload.get("client_endpoint") or auth_payload.get("server_endpoint")
            available_events = get_bitrix_events(auth_payload.get("access_token"), portal_url, rest_endpoint=rest_endpoint)
            available_names = [ev.get("event") for ev in available_events if isinstance(ev, dict) and ev.get("event")]
            logger.info("event.get count=%s names=%s", len(available_names), available_names[:30])
            im_events = ["OnImMessageAdd", "onimmessageadd", "ONIMMESSAGEADD"]
            ol_events = ["OnImOpenLineMessageAdd", "onimopenlinemessageadd", "ONIMOPENLINEMESSAGEADD"]
            if any(name in available_names for name in im_events):
                event_candidates = im_events
            elif any(name in available_names for name in ol_events):
                event_candidates = ol_events
            else:
                event_candidates = im_events
            bind_res = bind_events(
                auth_payload.get("access_token"),
                portal_url,
                BITRIX_EVENT_HANDLER_URL,
                event_candidates,
                rest_endpoint=rest_endpoint,
            )
            logger.info("event.bind during install: %s", bind_res)
        return (
            "OK\n"
            f"access_token={auth_payload.get('access_token')}\n"
            f"refresh_token={auth_payload.get('refresh_token')}\n"
            f"expires_in={auth_payload.get('expires_in')}\n"
            f"member_id={auth_payload.get('member_id')}\n"
            f"domain={auth_payload.get('domain')}\n",
            200,
        )
    if not code:
        if request.values.get("APP_SID"):
            return "OK", 200
        return "Missing code parameter.", 400
    try:
        token_json, err = exchange_oauth_code(code, request.values.get("server_domain"))
        if err:
            return err, 500
        access_token = token_json.get("access_token")
        refresh_token = token_json.get("refresh_token")
        if access_token:
            return (
                "OK\n"
                f"access_token={access_token}\n"
                f"refresh_token={refresh_token}\n"
                f"expires_in={token_json.get('expires_in')}\n"
                f"member_id={token_json.get('member_id')}\n"
                f"domain={token_json.get('domain')}\n",
                200,
            )
        return f"Token error: {token_json}", 400
    except Exception as e:
        logger.error(f"OAuth token error: {e}", exc_info=True)
        return f"OAuth error: {e}", 500

# ---------- ОБЩАЯ ЛОГИКА ОБРАБОТКИ ----------

def get_text_llama_parse(file_path):
    try:
        url = "https://api.cloud.llamaindex.ai/api/parsing/upload"
        headers = {"Authorization": f"Bearer {LLAMA_KEY}"}
        data = {"language": "ru", "parsing_instruction": "Extract table: No, Date, Name, Qty, Unit, Price, Sum."}
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f, "application/pdf")}
            response = requests.post(url, headers=headers, files=files, data=data)
            response.raise_for_status() # Проверка на ошибки HTTP
        job_id = response.json()["id"]
        result_url = f"https://api.cloud.llamaindex.ai/api/parsing/job/{job_id}/result/markdown"
        for _ in range(50):
            res = requests.get(result_url, headers=headers)
            if res.status_code == 200: return res.json()["markdown"]
            time.sleep(2)
        return ""
    except Exception as e:
        logger.error(f"Ошибка LlamaIndex парсинга: {e}", exc_info=True)
        return ""

def ocr_image_ocr_space(file_path):
    if not OCR_SPACE_KEY:
        return "", "OCR_SPACE_KEY не задан"
    try:
        url = "https://api.ocr.space/parse/image"
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            data = {
                "apikey": OCR_SPACE_KEY,
                "language": "rus",
                "OCREngine": 2,
                "isOverlayRequired": False,
            }
            response = requests.post(url, files=files, data=data, timeout=60)
            response.raise_for_status()
        result = response.json()
        if result.get("IsErroredOnProcessing"):
            return "", "OCR ошибка"
        parsed = result.get("ParsedResults", [])
        text = "\n".join(item.get("ParsedText", "") for item in parsed).strip()
        return text, None
    except Exception as e:
        logger.error(f"OCR.Space ошибка: {e}", exc_info=True)
        return "", "OCR ошибка"

def summarize_ocr_promos(text):
    ads_count = None
    ads_match = re.search(r"(\d+)\s+объявлений", text, flags=re.IGNORECASE)
    if ads_match:
        ads_count = ads_match.group(1)
    promo_count = 0
    base_count = 0
    for match in re.finditer(r"\d[\d\s]*₽", text):
        tail = text[match.end():match.end() + 20]
        if "до 00:00" in tail:
            promo_count += 1
        else:
            base_count += 1
    total = promo_count + base_count
    summary_lines = []
    if ads_count is not None:
        summary_lines.append(f"[b]Объявлений: {ads_count}[/b]")
    summary_lines.append(f"[b]Найдено строк: {total}[/b]")
    summary_lines.append(f"[b]Акция: {promo_count}[/b]")
    summary_lines.append(f"[b]Базовая: {base_count}[/b]")
    summary = "\n".join(summary_lines)
    return summary

def _strip_html(value):
    text = re.sub(r"<[^>]+>", " ", value or "")
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()

def fetch_sud_cases():
    url = (
        "https://reputation.su/search?"
        "query=%D0%B1%D0%B5%D0%BB%D0%BE%D0%B2+%D0%B4%D0%B5%D0%BD%D0%B8%D1%81+%D0%B2%D0%B8%D0%BA%D1%82%D0%BE%D1%80%D0%BE%D0%B2%D0%B8%D1%87"
        "&region=18&region=76&region=35"
    )
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        "Referer": "https://reputation.su/",
    }
    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code in [401, 403]:
        return None, f"{response.status_code} Forbidden"
    content_type = response.headers.get("content-type", "").lower()
    if "charset=windows-1251" in content_type or "charset=cp1251" in content_type:
        response.encoding = "cp1251"
    elif not response.encoding or response.encoding.lower() in ["iso-8859-1", "latin-1", "latin1"]:
        response.encoding = response.apparent_encoding or "utf-8"
    response.raise_for_status()
    return response.text, None

def _html_to_text(html_text):
    text = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", html_text)
    text = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", text)
    text = re.sub(r"(?i)<br\\s*/?>", "\n", text)
    text = re.sub(r"(?i)</(tr|p|div|li)>", "\n", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\\s*\n+", "\n", text)
    return text.strip()

def parse_sud_cases(html_text):
    rows = []
    plain = _html_to_text(html_text)
    lines = [line.strip() for line in plain.splitlines() if line.strip()]
    case_number_re = re.compile(r"\b\d{1,3}-\d{1,6}/\d{4}\b")
    case_indices = [i for i, line in enumerate(lines) if case_number_re.search(line)]
    if not case_indices:
        case_indices = [i for i, line in enumerate(lines) if line.lower() == "посмотреть дело"]

    def _collect_section(block_lines, section_name):
        items = []
        for i, line in enumerate(block_lines):
            if line.lower() == section_name.lower():
                for next_line in block_lines[i + 1:]:
                    if next_line.lower() in [
                        "категория",
                        "истцы",
                        "ответчики",
                        "другие участники",
                        "судья",
                        "движение по делу",
                        "регистрация",
                        "посмотреть дело",
                    ]:
                        break
                    items.append(next_line)
                break
        return items

    for idx, start in enumerate(case_indices):
        end = case_indices[idx + 1] if idx + 1 < len(case_indices) else len(lines)
        block_lines = lines[start:end]
        plaintiffs = _collect_section(block_lines, "Истцы")
        defendants = _collect_section(block_lines, "Ответчики")
        reg_date = None
        for i, line in enumerate(block_lines):
            if line.lower() == "регистрация" and i + 1 < len(block_lines):
                reg_date = block_lines[i + 1]
                break
        if plaintiffs or defendants or reg_date:
            rows.append(
                "Дата регистрации: {date}; Истцы: {plaintiffs}; Ответчики: {defendants}".format(
                    date=reg_date or "не указана",
                    plaintiffs=", ".join(plaintiffs) if plaintiffs else "не указаны",
                    defendants=", ".join(defendants) if defendants else "не указаны",
                )
            )
    return rows

def process_and_save(markdown_text):
    rows = []
    try: 
        # Используем main_data_sheet для получения хешей
        existing_hashes = main_data_sheet.col_values(8) if main_data_sheet.row_count > 0 else []
    except Exception as e: 
        logger.error(f"Ошибка чтения Google Sheet (main_data_sheet): {e}", exc_info=True)
        existing_hashes = []
        
    lines = markdown_text.split('\n')
    for line in lines:
        if '|' not in line or '---' in line: continue
        parts = [p.strip() for p in line.split('|') if p.strip()]
        if len(parts) >= 5 and re.match(r'^\d+$', parts[0]): # Проверяем, что первый элемент - число (номер строки)
            try:
                no, naim = parts[0], " ".join(parts[1:-4]).strip()
                
                def clean_num(val): 
                    return re.sub(r'[^\d,.]', '', val).replace(',', '.').replace(' ', '')
                
                qty_str, price_str, summa_str = parts[-4], parts[-2], parts[-1]
                
                qty = clean_num(qty_str)
                price = clean_num(price_str)
                summa = clean_num(summa_str)

                u_raw = parts[-3].lower()
                unit = "кг" if any(c in u_raw for c in ['к', 'k', 'g', 'γ']) else "шт" if any(c in u_raw for c in ['ш', 'w', 't']) else u_raw
                
                date_match = re.search(r'(\d{2}\.\d{2}\.\d{4})', naim)
                date = date_match.group(1) if date_match else "---"
                
                # Хеш для проверки дубликатов
                row_hash = hashlib.md5(f"{date}{naim}{summa}".encode('utf-8')).hexdigest()
                
                if row_hash not in existing_hashes:
                    rows.append([no, date, naim, qty, unit, price, summa, row_hash])
            except Exception as e:
                logger.warning(f"Пропуск строки из-за ошибки парсинга: {line} | Ошибка: {e}", exc_info=True)
                continue
                
    if rows:
        try:
            # Используем main_data_sheet для добавления строк PDF
            main_data_sheet.append_rows(rows)
            logger.info(f"Успешно добавлено {len(rows)} строк в Google Sheet (main_data_sheet).")
            return len(rows)
        except Exception as e:
            logger.error(f"Ошибка при добавлении строк в Google Sheet (main_data_sheet): {e}", exc_info=True)
            return 0
    return 0

def get_bitrix_portal_url():
    if BITRIX_PORTAL_URL:
        return BITRIX_PORTAL_URL.rstrip("/")
    if BITRIX_URL and "/rest/" in BITRIX_URL:
        return BITRIX_URL.split("/rest/")[0]
    return None

# ---------- БИТРИКС24 ----------

def bitrix_send_message(dialog_id, text):
    return bitrix_send_message_custom(dialog_id, text)

def bitrix_send_message_custom(dialog_id, text, base_url=None, bot_id=None, client_id=None):
    """Отправляет сообщение в чат Битрикс24. DIALOG_ID может быть 'chatN' или ID пользователя."""
    base_url = base_url or BITRIX_URL
    if not base_url:
        logger.warning("BITRIX_URL не задан, сообщение в Битрикс не отправлено.")
        return
    try:
        # Сначала пытаемся отправить от имени бота (если BOT_ID задан)
        effective_bot_id = bot_id or BITRIX_BOT_ID
        effective_client_id = client_id or BITRIX_CLIENT_ID
        if effective_bot_id:
            bot_url = f"{base_url.rstrip('/')}/imbot.message.add.json"
            bot_payload = {
                "BOT_ID": effective_bot_id,
                "DIALOG_ID": dialog_id,
                "MESSAGE": text,
            }
            if effective_client_id:
                bot_payload["CLIENT_ID"] = effective_client_id
            logger.info(f"Отправка сообщения (бот) в Битрикс: URL={bot_url}, Payload={bot_payload}")
            bot_response = requests.post(bot_url, json=bot_payload)
            if bot_response.ok:
                bot_result = bot_response.json()
                if "result" in bot_result:
                    logger.info(f"Сообщение успешно отправлено ботом. ID: {bot_result['result']}")
                    return
                else:
                    error_msg = bot_result.get('error_description', bot_result.get('error', 'Неизвестная ошибка API'))
                    logger.error(f"Ошибка API imbot.message.add: {error_msg}. Ответ: {bot_result}")
            else:
                logger.error(f"HTTP ошибка imbot.message.add: {bot_response.status_code} - {bot_response.text}")

        # Фолбэк: обычная отправка от имени пользователя вебхука
        send_url = f"{base_url.rstrip('/')}/im.message.add.json"
        payload = {
            "DIALOG_ID": dialog_id,
            "MESSAGE": text,
        }
        logger.info(f"Отправка сообщения в Битрикс: URL={send_url}, Payload={payload}")
        response = requests.post(send_url, json=payload)
        response.raise_for_status()

        result_data = response.json()
        if "result" in result_data:
            logger.info(f"Сообщение успешно отправлено в Битрикс. ID: {result_data['result']}")
        else:
            error_msg = result_data.get('error_description', result_data.get('error', 'Неизвестная ошибка API'))
            logger.error(f"Ошибка API Битрикс при отправке сообщения: {error_msg}. Ответ: {result_data}")
            
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP Ошибка при отправке в Битрикс: {http_err.response.status_code} - {http_err.response.text}", exc_info=True)
    except Exception as e:
        logger.error(f"Общая ошибка при отправке сообщения в Битрикс: {e}", exc_info=True)

def bitrix_send_long_message(dialog_id, text, chunk_size=3000):
    if not text:
        return
    for i in range(0, len(text), chunk_size):
        bitrix_send_message(dialog_id, text[i:i + chunk_size])

@app.route('/bitrix', methods=['GET', 'POST', 'HEAD'])
def bitrix_webhook():
    if request.method in ['GET', 'HEAD']:
        logger.info(f"Bitrix GET /bitrix query={dict(request.args)}")
        if request.args.get("code"):
            try:
                token_json, err = exchange_oauth_code(
                    request.args.get("code"),
                    request.args.get("server_domain"),
                )
                if err:
                    return err, 500
                access_token = token_json.get("access_token")
                refresh_token = token_json.get("refresh_token")
                if access_token:
                    return (
                        "OK\n"
                        f"access_token={access_token}\n"
                        f"refresh_token={refresh_token}\n"
                        f"expires_in={token_json.get('expires_in')}\n"
                        f"member_id={token_json.get('member_id')}\n"
                        f"domain={token_json.get('domain')}\n",
                        200,
                    )
                return f"Token error: {token_json}", 400
            except Exception as e:
                logger.error(f"OAuth token error: {e}", exc_info=True)
                return f"OAuth error: {e}", 500
        return "OK", 200
    data = request.form
    json_data = request.get_json(silent=True) or {}
    if data.get('APP_SID') or request.args.get('APP_SID') or data.get('auth[client_id]') or (json_data.get('auth') or {}).get('client_id'):
        access_token = (
            data.get('auth[access_token]')
            or json_data.get('auth[access_token]')
            or (json_data.get('auth') or {}).get('access_token')
        )
        logger.info(
            "Bitrix app ping meta: app_sid=%s auth_client_id=%s access_token=%s",
            _mask_token(data.get('APP_SID') or request.args.get('APP_SID')),
            _mask_token(data.get('auth[client_id]') or (json_data.get('auth') or {}).get('client_id')),
            _mask_token(access_token),
        )
    # Локальное приложение: Bitrix может вызывать обработчик без event
    if not (data.get('event') or json_data.get('event')):
        if data.get('APP_SID') or request.args.get('APP_SID'):
            logger.info(f"Bitrix APP_SID ping: {data.get('APP_SID')}")
            return "OK", 200
        if data.get('auth[client_id]') or (json_data.get('auth') or {}).get('client_id'):
            auth_payload = _extract_auth_payload(data, json_data)
            logger.info(
                "Bitrix app ping with auth client_id=%s domain=%s access=%s",
                _mask_token(auth_payload.get("client_id")),
                auth_payload.get("domain"),
                _mask_token(auth_payload.get("access_token")),
            )
            if auth_payload.get("access_token"):
                LAST_APP_AUTH.update(auth_payload)
                if BITRIX_EVENT_HANDLER_URL:
                    portal_url = f"https://{auth_payload.get('domain')}" if auth_payload.get("domain") else get_bitrix_portal_url()
                    rest_endpoint = auth_payload.get("client_endpoint") or auth_payload.get("server_endpoint")
                    available_events = get_bitrix_events(auth_payload.get("access_token"), portal_url, rest_endpoint=rest_endpoint)
                    available_names = [ev.get("event") for ev in available_events if isinstance(ev, dict) and ev.get("event")]
                    logger.info("event.get count=%s names=%s", len(available_names), available_names[:30])
                    im_events = ["OnImMessageAdd", "onimmessageadd", "ONIMMESSAGEADD"]
                    ol_events = ["OnImOpenLineMessageAdd", "onimopenlinemessageadd", "ONIMOPENLINEMESSAGEADD"]
                    if any(name in available_names for name in im_events):
                        event_candidates = im_events
                    elif any(name in available_names for name in ol_events):
                        event_candidates = ol_events
                    else:
                        event_candidates = im_events
                    bind_res = bind_events(
                        auth_payload.get("access_token"),
                        portal_url,
                        BITRIX_EVENT_HANDLER_URL,
                        event_candidates,
                        rest_endpoint=rest_endpoint,
                    )
                    logger.info("event.bind during app ping: %s", bind_res)
            return "OK", 200
    
    # 1. Проверка токена (безопасность)
    token_from_request = (
        data.get('auth[application_token]')
        or json_data.get('auth[application_token]')
        or (json_data.get('auth') or {}).get('application_token')
    )
    auth_client_id = (
        data.get('auth[client_id]')
        or json_data.get('auth[client_id]')
        or (json_data.get('auth') or {}).get('client_id')
    )
    auth_app_id = (
        data.get('auth[application_id]')
        or json_data.get('auth[application_id]')
        or (json_data.get('auth') or {}).get('application_id')
    )
    client_id_query = request.args.get('CLIENT_ID')
    request_client_id = auth_client_id or client_id_query

    token_ok = token_from_request == BITRIX_TOKEN
    client_ok = bool(request_client_id and request_client_id in BITRIX_CLIENT_IDS)
    if not (token_ok or client_ok):
        def _mask_token(value):
            if not value:
                return "none"
            value = str(value)
            if len(value) <= 6:
                return f"{value[0]}...{value[-1]}(len={len(value)})"
            return f"{value[:3]}...{value[-3:]}(len={len(value)})"
        logger.warning(
            "Неверный токен авторизации. req=%s env=%s auth_client_id=%s auth_app_id=%s query_client_id=%s",
            _mask_token(token_from_request),
            _mask_token(BITRIX_TOKEN),
            _mask_token(auth_client_id),
            _mask_token(auth_app_id),
            _mask_token(client_id_query),
        )
        return "Forbidden", 403

    # 2. Обработка событий: ONIMBOTMESSAGEADD (сообщения боту) и ONIMMESSAGEADD (обычные сообщения в чате)
    event = data.get('event') or json_data.get('event')
    is_olbot_request = request.path.endswith("/bitrix/olbot")
    if event in ['ONIMBOTMESSAGEADD', 'ONIMMESSAGEADD']:
        chat_id = data.get('data[PARAMS][CHAT_ID]') or (json_data.get('data') or {}).get('PARAMS', {}).get('CHAT_ID') # ID чата или пользователя, куда писать ответ
        user_id_from_bx = data.get('data[PARAMS][FROM_USER_ID]') or (json_data.get('data') or {}).get('PARAMS', {}).get('FROM_USER_ID') # ID отправителя из Битрикс
        message_id = data.get('data[PARAMS][MESSAGE_ID]') or (json_data.get('data') or {}).get('PARAMS', {}).get('MESSAGE_ID') # ID сообщения

        # Если это сообщение от самого себя (бота), пропускаем.
        if user_id_from_bx == BITRIX_BOT_ID:
            logger.warning(f"Пропущено сообщение от самого бота (ID: {BITRIX_BOT_ID}).")
            return "OK"

        # 3. Фильтр по разрешенным чатам (для ONIMMESSAGEADD)
        if event == 'ONIMMESSAGEADD' and str(chat_id) not in ALLOWED_BX_CHATS:
            logger.info(f"Сообщение из чата ID: {chat_id} (от пользователя {user_id_from_bx}) не в белом списке. Пропускаю.")
            return "OK"

        # Определяем, куда будем писать ответ.
        # В Bitrix лучше отвечать в DIALOG_ID, который прислал сам обработчик.
        # Для лички бота это будет ID пользователя, для групп — "chatN".
        dialog_id_for_response = (
            data.get('data[PARAMS][DIALOG_ID]')
            or (json_data.get('data') or {}).get('PARAMS', {}).get('DIALOG_ID')
            or (f"chat{chat_id}" if chat_id else None)
            or user_id_from_bx
        )
        
        if not dialog_id_for_response:
            logger.error("Не удалось определить DIALOG_ID для ответа.")
            return "OK"

        # Текст сообщения нужен раньше (например, для упоминаний в группах)
        message_text = (
            data.get('data[PARAMS][MESSAGE]')
            or (json_data.get('data') or {}).get('PARAMS', {}).get('MESSAGE')
            or ''
        ).strip()

        if is_olbot_request and message_text:
            if message_text.strip().lower() == "тест":
                docs = _load_kb_documents()
                if docs:
                    response_text = docs[0]["text"][:500].strip()
                else:
                    errors = "; ".join(KB_CACHE.get("errors") or [])
                    response_text = "База знаний не загружена."
                    if errors:
                        response_text = f"{response_text} {errors}"
            else:
                kb_answer = build_kb_response(message_text)
                response_text = (
                    kb_answer
                    or "Пока не нашел ответ в базе знаний. "
                    "Пожалуйста, переформулируйте вопрос так, чтобы он касался работы отдела бронирования."
                )
            bitrix_send_message_custom(
                dialog_id_for_response,
                response_text,
                base_url=BITRIX_OLBOT_WEBHOOK_URL or BITRIX_URL,
                bot_id=BITRIX_OLBOT_ID or BITRIX_BOT_ID,
                client_id=BITRIX_OLBOT_CLIENT_ID,
            )
            return "OK", 200

        def is_bot_mentioned(text):
            if not text:
                return False
            text_lower = text.lower()
            if BITRIX_BOT_ID:
                if f"[user={str(BITRIX_BOT_ID).lower()}]" in text_lower:
                    return True
                if f"[bot={str(BITRIX_BOT_ID).lower()}]" in text_lower:
                    return True
            mention_alias = os.environ.get("BITRIX_BOT_MENTION", "").strip()
            if mention_alias and f"@{mention_alias.lower()}" in text_lower:
                return True
            return False

        # Получаем информацию о сообщении (включая файлы)
        files_data = {}
        event_data = json_data.get('data') or {}
        params_data = event_data.get('PARAMS') or {}
        form_params = {}
        form_param_keys = []
        for key in data.keys():
            if key.startswith("data[PARAMS][") and key.endswith("]"):
                inner_key = key[len("data[PARAMS]["):-1]
                form_params[inner_key] = data.get(key)
                form_param_keys.append(inner_key)
        if form_params:
            params_data = {**form_params, **params_data}

        def _extract_file_ids(value):
            ids = []
            if not value:
                return ids
            if isinstance(value, dict):
                if "id" in value or "ID" in value:
                    ids.append(str(value.get("id") or value.get("ID")))
                else:
                    ids.extend([str(k) for k in value.keys()])
            elif isinstance(value, list):
                for item in value:
                    ids.extend(_extract_file_ids(item))
            elif isinstance(value, str):
                parts = [p.strip() for p in value.replace(";", ",").split(",") if p.strip()]
                ids.extend(parts)
            else:
                ids.append(str(value))
            return ids

        # Сначала пытаемся извлечь ID файлов прямо из payload события
        candidate_values = [
            params_data.get("FILES"),
            params_data.get("FILE_ID"),
            params_data.get("FILE_IDS"),
            params_data.get("FILEID"),
            params_data.get("FILEIDS"),
            params_data.get("ATTACH"),
            params_data.get("ATTACH_ID"),
            params_data.get("ATTACH_IDS"),
            params_data.get("ATTACHES"),
            event_data.get("FILES"),
            event_data.get("FILE_ID"),
            event_data.get("FILE_IDS"),
        ]
        for key, value in params_data.items():
            if any(tag in key.upper() for tag in ["FILE", "ATTACH"]):
                candidate_values.append(value)
        file_ids = []
        for value in candidate_values:
            file_ids.extend(_extract_file_ids(value))
        for raw_key in form_param_keys:
            match = re.search(r"(FILES|ATTACH)\]\[(\d+)\]", raw_key)
            if match:
                file_ids.append(match.group(2))
        file_ids = [fid for fid in file_ids if fid and fid.lower() != "none"]
        if file_ids:
            files_data = {fid: {} for fid in dict.fromkeys(file_ids)}
        else:
            logger.info("Bitrix payload params keys: %s", list(params_data.keys()))
            if form_params:
                logger.info("Bitrix form params keys: %s", list(form_params.keys()))

        has_file_hints = bool(file_ids)
        if not has_file_hints:
            for key in params_data.keys():
                if any(tag in key.upper() for tag in ["FILE", "ATTACH"]):
                    has_file_hints = True
                    break
        if not has_file_hints:
            for key in form_param_keys:
                if "FILE" in key.upper() or "ATTACH" in key.upper():
                    has_file_hints = True
                    break
        command_text = message_text.lower()
        is_text_command = command_text in ["статус", "chat_id", "chatid", "помощь", "help", "sud"]

        # Если из payload не удалось — пробуем получить сообщение через API
        if not files_data and (has_file_hints or not is_text_command):
            try:
                msg_url = f"{BITRIX_URL.rstrip('/')}/im.message.getById.json"
                msg_res = requests.get(msg_url, params={"ID": message_id})
                if msg_res.status_code == 404:
                    alt_url = f"{BITRIX_URL.rstrip('/')}/im.message.get.json"
                    msg_res = requests.get(alt_url, params={"MESSAGE_ID": message_id})
                msg_res.raise_for_status()
                msg_json = msg_res.json()
                if "result" in msg_json:
                    result = msg_json.get('result', {})
                    if isinstance(result, dict) and str(message_id) in result:
                        msg_data = result.get(str(message_id), {})
                    elif isinstance(result, list) and result:
                        msg_data = result[0]
                    else:
                        msg_data = result
                    files_data = msg_data.get('FILES', {})
                else:
                    logger.error(f"Bitrix API error im.message.getById: {msg_json}")
            except Exception as e:
                logger.error(f"Не удалось получить информацию о сообщении {message_id}: {e}", exc_info=True)
                if has_file_hints:
                    bitrix_send_message(
                        dialog_id_for_response,
                        "⚠️ Не удалось получить информацию о вложении. "
                        "Проверьте права входящего вебхука (IM, Disk, IMBot) и попробуйте отправить PDF как файл."
                    )

        # --- Обработка вложений (файлов) ---
        if files_data:
            if event == 'ONIMMESSAGEADD' and not is_bot_mentioned(message_text):
                bitrix_send_message(
                    dialog_id_for_response,
                    "ℹ️ Чтобы обработать PDF в групповом чате, упомяните бота в тексте сообщения "
                    "(например, @dvbot) и приложите файл."
                )
                return "OK", 200

            valid_file_ids = [f_id for f_id in files_data.keys() if str(f_id).isdigit()]
            if not valid_file_ids:
                logger.info("Нет корректных числовых ID файлов в событии.")
            else:
                bitrix_send_message(dialog_id_for_response, "⏳ Начинаю распознавание файла...")

            for f_id in valid_file_ids:
                try:
                    # Получаем URL для скачивания файла
                    disk_file_info_url = f"{BITRIX_URL.rstrip('/')}/disk.file.get.json"
                    disk_file_response = requests.post(disk_file_info_url, json={"id": f_id})
                    if not disk_file_response.ok:
                        logger.info(f"Пропускаю файл ID={f_id}: {disk_file_response.status_code}")
                        continue
                    
                    disk_file_data = disk_file_response.json().get('result', {})
                    download_url = disk_file_data.get('DOWNLOAD_URL')
                    file_name = disk_file_data.get('NAME', f'bx_{f_id}.pdf')
                    
                    if not download_url:
                        logger.info(f"Пропускаю файл без ссылки: {file_name}.")
                        continue

                    file_ext = file_name.lower().rsplit(".", 1)[-1] if "." in file_name else ""
                    path = f"downloads/{file_name}"
                    Path("downloads").mkdir(exist_ok=True)

                    f_res = requests.get(download_url)
                    f_res.raise_for_status()
                    with open(path, "wb") as f: f.write(f_res.content)

                    if file_ext == "pdf":
                        md = get_text_llama_parse(path)
                        count = process_and_save(md)
                        bitrix_send_message(dialog_id_for_response, f"✅ Битрикс: добавлено строк: {count} на основной лист.")
                    elif file_ext in ["jpg", "jpeg", "png", "webp", "bmp", "gif"]:
                        text, err = ocr_image_ocr_space(path)
                        if err:
                            bitrix_send_message(dialog_id_for_response, f"❌ OCR ошибка: {err}")
                        elif text:
                            summary = summarize_ocr_promos(text)
                            bitrix_send_long_message(dialog_id_for_response, f"{summary}\n\n{text}")
                        else:
                            bitrix_send_message(dialog_id_for_response, "⚠️ OCR не нашел текста на изображении.")
                    else:
                        logger.info(f"Пропускаю файл не PDF/не look: {file_name}.")

                    if os.path.exists(path):
                        os.remove(path)
                        
                except Exception as e:
                    logger.error(f"Ошибка обработки файла {file_name} (ID: {f_id}): {e}", exc_info=True)
                    # Не спамим пользователя, если пришли некорректные ID или не-PDF
                    continue
        
        # --- Обработка текстовых команд ---
        if message_text and (event != 'ONIMMESSAGEADD' or is_bot_mentioned(message_text)):
            if message_text.lower() == "статус": 
                try:
                    if main_data_sheet.row_count > 0: # Используем main_data_sheet
                        last_row = main_data_sheet.get_all_values()[-1]
                        response = f"✅ Система работает.\nПоследняя запись на основном листе: {last_row[2]} на сумму {last_row[6]}"
                    else:
                        response = "✅ Система работает. Основной лист пуст."
                except Exception as e:
                    response = f"✅ Система работает. Ошибка получения данных с основного листа: {e}"
                bitrix_send_message(dialog_id_for_response, response)

            elif message_text.lower() in ["chat_id", "chatid"]: 
                bitrix_send_message(
                    dialog_id_for_response,
                    f"ID чата: {chat_id}\nDIALOG_ID: {dialog_id_for_response}"
                )

            elif message_text.lower() in ["помощь", "help"]: 
                bitrix_send_message(
                    dialog_id_for_response,
                    "Доступные команды: 'статус', 'помощь' (или 'help'), 'look'. "
                    "Я автоматически распознаю PDF-файлы, отправленные мне в чат, "
                    "и добавляю результаты в Google Таблицу: лист 'Лист1'. "
                    "Команда 'look' + изображение: верну весь распознанный текст."
                )
            
            elif message_text.lower() == "sud":
                try:
                    html_text, fetch_err = fetch_sud_cases()
                    if fetch_err:
                        bitrix_send_message(
                            dialog_id_for_response,
                            "Сайт с данными заблокировал запрос. "
                            "Попробуйте позже или вручную открыть страницу."
                        )
                        return
                    rows = parse_sud_cases(html_text)
                    if rows:
                        response = "\n".join(f"{i + 1}. {row}" for i, row in enumerate(rows))
                    else:
                        response = "Ничего не найдено по указанному запросу."
                    bitrix_send_long_message(dialog_id_for_response, response)
                except Exception as e:
                    bitrix_send_message(dialog_id_for_response, f"❌ Ошибка при запросе суда: {e}")
                    logger.error(f"Ошибка sud: {e}", exc_info=True)

            # НОВОЕ: БЛОК: Запись любого другого текста в таблицу "Тест"
            else:
                try:
                    current_date = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
                    sender_id = data.get('data[PARAMS][FROM_USER_ID]') or (json_data.get('data') or {}).get('PARAMS', {}).get('FROM_USER_ID')
                    
                    # Попытка получить имя отправителя (требует прав 'user' для BITRIX_URL)
                    sender_name = f"Пользователь {sender_id}"
                    try:
                        user_info_response = requests.post(f"{BITRIX_URL.rstrip('/')}/user.get.json", json={"ID": sender_id})
                        user_info_response.raise_for_status()
                        users = user_info_response.json().get('result', [])
                        if users:
                            sender_name = f"{users[0].get('NAME', '')} {users[0].get('LAST_NAME', '')}".strip()
                    except Exception as e:
                        logger.warning(f"Не удалось получить имя отправителя {sender_id}: {e}", exc_info=True)

                    # Создаем уникальный хеш для этого текстового сообщения
                    text_hash = hashlib.md5(f"{current_date}{message_text}{sender_id}".encode('utf-8')).hexdigest()

                    # Формируем строку для листа "Тест"
                    row_to_add = [
                        "Битрикс Текст", # Тип сообщения
                        current_date, # Дата
                        sender_name, # Отправитель
                        message_text, # Сообщение
                        text_hash # Хеш для предотвращения дублей
                    ]
                    
                    # Добавляем строку в Google Таблицу на лист "Тест"
                    test_message_sheet.append_row(row_to_add)
                    bitrix_send_message(dialog_id_for_response, f"✅ Текст '{message_text}' успешно добавлен в Google Таблицу (лист 'Тест')!")
                    logger.info(f"Текст из Битрикс добавлен в таблицу 'Тест': '{message_text}' от {sender_id}")
                except Exception as e:
                    bitrix_send_message(dialog_id_for_response, f"❌ Ошибка при добавлении текста в таблицу 'Тест': {e}")
                    logger.error(f"Ошибка при добавлении текста из Битрикс в таблицу 'Тест': {e}", exc_info=True)

    if event == "ONAPPINSTALL":
        auth_payload = _extract_auth_payload(data, json_data)
        if auth_payload.get("access_token"):
            LAST_APP_AUTH.update(auth_payload)
            logger.info(
                "Bitrix app install auth received: client_id=%s domain=%s member_id=%s access=%s",
                _mask_token(auth_payload.get("client_id")),
                auth_payload.get("domain"),
                _mask_token(auth_payload.get("member_id")),
                _mask_token(auth_payload.get("access_token")),
            )
            if BITRIX_EVENT_HANDLER_URL:
                portal_url = f"https://{auth_payload.get('domain')}" if auth_payload.get("domain") else get_bitrix_portal_url()
                rest_endpoint = auth_payload.get("client_endpoint") or auth_payload.get("server_endpoint")
                available_events = get_bitrix_events(auth_payload.get("access_token"), portal_url, rest_endpoint=rest_endpoint)
                available_names = [ev.get("event") for ev in available_events if isinstance(ev, dict) and ev.get("event")]
                logger.info("event.get count=%s names=%s", len(available_names), available_names[:30])
                im_events = ["OnImMessageAdd", "onimmessageadd", "ONIMMESSAGEADD"]
                ol_events = ["OnImOpenLineMessageAdd", "onimopenlinemessageadd", "ONIMOPENLINEMESSAGEADD"]
                if any(name in available_names for name in im_events):
                    event_candidates = im_events
                elif any(name in available_names for name in ol_events):
                    event_candidates = ol_events
                else:
                    event_candidates = im_events
                bind_res = bind_events(
                    auth_payload.get("access_token"),
                    portal_url,
                    BITRIX_EVENT_HANDLER_URL,
                    event_candidates,
                    rest_endpoint=rest_endpoint,
                )
                logger.info("event.bind during install: %s", bind_res)
        return "OK", 200

    return "OK", 200 # Возвращаем OK, чтобы Битрикс знал, что сообщение получено

@app.route('/bitrix/olbot', methods=['GET', 'POST', 'HEAD'])
def bitrix_olbot_webhook():
    return bitrix_webhook()

# ---------- TELEGRAM ----------

async def check_bitrix(update: Update, context):
    """
    Проверяет связь с Bitrix24, получает ID пользователя и отправляет тестовое сообщение.
    """
    if not BITRIX_URL:
        await update.message.reply_text("❌ URL вебхука Bitrix24 не задан в секретах (BITRIX_WEBHOOK_URL)")
        return
    try:
        base_url_for_check = BITRIX_URL.rstrip('/') 
        check_url = f"{base_url_for_check}/user.current.json"
        
        logger.info(f"Checking Bitrix24 connection via: {check_url}")
        
        res = requests.get(check_url).json() 
        
        if "result" in res:
            user = res["result"]
            user_id = user.get('ID')
            name = f"{user.get('NAME', '')} {user.get('LAST_NAME', '')}".strip()
            
            await update.message.reply_text(f"✅ Связь с Bitrix24 установлена!\n👤 Аккаунт: {name}\nID пользователя: {user_id}\n⏳ Пробую отправить тестовое сообщение в личный чат Битрикс...")
            
            send_url = f"{base_url_for_check}/im.message.add.json"
            payload = {
                "DIALOG_ID": user_id, 
                "MESSAGE": f"🚀 Денис, привет! Это твой Laundry Bot. Если ты видишь это сообщение, значит 'труба' из Telegram в Битрикс работает идеально!"
            }
            logger.info(f"Попытка отправки в Битрикс (user.current): URL={send_url}, Payload={payload}")
            send_response = requests.post(send_url, json=payload)
            
            send_response.raise_for_status() 

            bitrix_add_result = send_response.json()
            if "result" in bitrix_add_result:
                await update.message.reply_text(f"✅ Сообщение успешно отправлено в Битрикс24!\n(ID сообщения: {bitrix_add_result['result']})")
                logger.info(f"Сообщение успешно отправлено в Битрикс. Результат: {bitrix_add_result}")
            else:
                error_description = bitrix_add_result.get('error_description', bitrix_add_result.get('error', 'Неизвестная ошибка Bitrix API'))
                await update.message.reply_text(f"⚠️ Ошибка при отправке сообщения в Битрикс: {error_description}")
                logger.error(f"Ошибка Bitrix API при отправке сообщения: {error_description}. Полный ответ: {bitrix_add_result}")

            # Регистрируем событие ONIMMESSAGEADD, если указан handler URL
            if BITRIX_EVENT_HANDLER_URL:
                try:
                    bind_payload = {
                        "event": "ONIMMESSAGEADD",
                        "handler": BITRIX_EVENT_HANDLER_URL,
                    }
                    if BITRIX_APP_ACCESS_TOKEN:
                        portal_url = get_bitrix_portal_url()
                        if not portal_url:
                            await update.message.reply_text("⚠️ Не задан BITRIX_PORTAL_URL, не могу вызвать event.bind.")
                            return
                        bind_url = f"{portal_url}/rest/event.bind.json"
                        bind_res = requests.post(bind_url, params={"auth": BITRIX_APP_ACCESS_TOKEN}, json=bind_payload).json()
                    else:
                        bind_url = f"{base_url_for_check}/event.bind.json"
                        bind_res = requests.post(bind_url, json=bind_payload).json()
                    if bind_res.get("result") is True:
                        await update.message.reply_text("🚀 Событие ONIMMESSAGEADD успешно зарегистрировано.")
                    elif bind_res.get("error") == "ERROR_EVENT_ALREADY_INSTALLED":
                        await update.message.reply_text("✅ Событие ONIMMESSAGEADD уже было зарегистрировано.")
                    else:
                        err_desc = bind_res.get("error_description", bind_res.get("error", "Неизвестная ошибка"))
                        await update.message.reply_text(f"⚠️ Не удалось зарегистрировать событие: {err_desc}")
                        logger.error(f"Ошибка event.bind: {bind_res}")
                except Exception as e:
                    await update.message.reply_text(f"⚠️ Ошибка регистрации события: {e}")
                    logger.error(f"Ошибка event.bind: {e}", exc_info=True)
            else:
                await update.message.reply_text(
                    "ℹ️ Не задан BITRIX_EVENT_HANDLER_URL. "
                    "Если нужно зарегистрировать ONIMMESSAGEADD, добавьте этот секрет."
                )
            
        else:
            error_description = res.get('error_description', res.get('error', 'Неизвестная ошибка Bitrix24'))
            await update.message.reply_text(f"⚠️ Ошибка Bitrix24 при проверке пользователя: {error_description}")
            logger.error(f"Ошибка Bitrix24 при проверке пользователя: {error_description}. Полный ответ: {res}")
            
    except requests.exceptions.HTTPError as http_err:
        error_details = f"Status: {http_err.response.status_code}, Response: {http_err.response.text}"
        await update.message.reply_text(f"❌ HTTP Ошибка при отправке в Битрикс: {http_err} ({error_details})")
        logger.error(f"HTTP Ошибка при отправке в Битрикс: {error_details}")
    except Exception as e:
        await update.message.reply_text(f"❌ Общая ошибка подключения к Bitrix24: {str(e)}")
        logger.error(f"Общая ошибка подключения к Bitrix24: {e}", exc_info=True)

async def handle_tg_doc(update: Update, context):
    if update.message.document and update.message.document.mime_type == "application/pdf":
        status = await update.message.reply_text("⏳ Обработка в Telegram...")
        path = f"downloads/tg_{update.message.document.file_id}.pdf"
        Path("downloads").mkdir(exist_ok=True)
        try:
            file = await update.message.document.get_file()
            await file.download_to_drive(path)
            
            md = await asyncio.to_thread(get_text_llama_parse, path)
            count = process_and_save(md)
            
            await status.edit_text(f"✅ Telegram: добавлено строк: {count}")
            
        except Exception as e:
            logger.error(f"Ошибка при обработке PDF файла из Telegram: {e}", exc_info=True)
            await status.edit_text(f"❌ Ошибка при обработке файла: {e}")
        finally:
            if os.path.exists(path):
                os.remove(path)
    else:
        await update.message.reply_text("Пожалуйста, отправьте PDF файл.")

async def sud_command(update: Update, context):
    try:
        html_text, fetch_err = fetch_sud_cases()
        if fetch_err:
            await update.message.reply_text(
                "Сайт с данными заблокировал запрос. "
                "Попробуйте позже или вручную открыть страницу."
            )
            return
        rows = parse_sud_cases(html_text)
        if rows:
            response = "\n".join(f"{i + 1}. {row}" for i, row in enumerate(rows))
        else:
            response = "Ничего не найдено по указанному запросу."
        await update.message.reply_text(response)
    except Exception as e:
        await update.message.reply_text(f"❌ Ошибка при запросе суда: {e}")
        logger.error(f"Ошибка sud (Telegram): {e}", exc_info=True)

# ---------- ЗАПУСК ----------

def run_flask():
    """Запускает Flask веб-сервер."""
    app.run(host='0.0.0.0', port=8080)

async def main():
    """Основная функция запуска бота."""
    # Запускаем Flask сервер в отдельном потоке
    Thread(target=run_flask, daemon=True).start()
    
    # Инициализация Telegram бота
    tg_app = ApplicationBuilder().token(BOT_TOKEN).build()
    
    # Добавляем обработчики команд и сообщений
    tg_app.add_handler(CommandHandler("check_bitrix", check_bitrix))
    tg_app.add_handler(CommandHandler("sud", sud_command))
    tg_app.add_handler(MessageHandler(filters.Document.PDF, handle_tg_doc))
    
    logger.info("🚀 Бот (Telegram + Bitrix) запущен. Ожидание команд...")
    
    # Запуск Telegram бота
    await tg_app.initialize()
    await tg_app.updater.start_polling()
    await tg_app.start()
    
    # Держим основной цикл работы бота
    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    # Проверяем, что все необходимые переменные окружения заданы
    if not all([BOT_TOKEN, GOOGLE_JSON, SPREADSHEET_ID, LLAMA_KEY, BITRIX_URL, BITRIX_TOKEN, BITRIX_BOT_ID]):
        logger.error("Одна или несколько обязательных переменных окружения не заданы! Проверьте Secrets в Replit.")
    else:
        asyncio.run(main())
