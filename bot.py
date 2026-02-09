
import os
import json
import logging
import asyncio
import hashlib
import re
import requests
import time
from pathlib import Path
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
BITRIX_URL = os.environ.get("BITRIX_WEBHOOK_URL") 
BITRIX_TOKEN = os.environ.get("BITRIX_TOKEN")
BITRIX_BOT_ID = os.environ.get("BITRIX_BOT_ID") # ID вашего бота из Битрикс
BITRIX_CLIENT_ID = os.environ.get("BITRIX_CLIENT_ID")

# ID разрешенных чатов Битрикс (для ONIMMESSAGEADD), если используется
ALLOWED_BX_CHATS = os.environ.get("ALLOWED_BITRIX_CHATS", "").replace(" ", "").split(",")

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

# ---------- БИТРИКС24 ----------

def bitrix_send_message(dialog_id, text):
    """Отправляет сообщение в чат Битрикс24. DIALOG_ID может быть 'chatN', 'userN', 'botN'."""
    if not BITRIX_URL:
        logger.warning("BITRIX_URL не задан, сообщение в Битрикс не отправлено.")
        return
    try:
        # Формируем URL для отправки сообщения
        send_url = f"{BITRIX_URL.rstrip('/')}/im.message.add.json"
        
        # Формируем payload. DIALOG_ID должен быть корректным (например, 'chat123', 'user456', 'bot789')
        payload = {
            "DIALOG_ID": dialog_id, 
            "MESSAGE": text
        }
        
        logger.info(f"Отправка сообщения в Битрикс: URL={send_url}, Payload={payload}")
        response = requests.post(send_url, json=payload)
        response.raise_for_status() # Проверка на ошибки HTTP
        
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

@app.route('/bitrix', methods=['POST'])
def bitrix_webhook():
    data = request.form
    json_data = request.get_json(silent=True) or {}
    
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
    client_ok = bool(BITRIX_CLIENT_ID and request_client_id == BITRIX_CLIENT_ID)
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
            or chat_id
            or user_id_from_bx
        )
        
        if not dialog_id_for_response:
            logger.error("Не удалось определить DIALOG_ID для ответа.")
            return "OK"

        # Получаем ID самого сообщения для дальнейшей обработки (например, для файлов)
        # Ресурс с информацией о сообщении (включая файлы)
        try:
            msg_res = requests.post(f"{BITRIX_URL.rstrip('/')}/im.message.get.json", json={"MESSAGE_ID": message_id})
            msg_res.raise_for_status()
            msg_data = msg_res.json().get('result', {})
            files_data = msg_data.get('FILES', {})
        except Exception as e:
            logger.error(f"Не удалось получить информацию о сообщении {message_id}: {e}", exc_info=True)
            files_data = {}

        # --- Обработка вложений (файлов) ---
        if files_data:
            bitrix_send_message(dialog_id_for_response, "⏳ Начинаю распознавание файла...")
            
            for f_id, f_info in files_data.items():
                try:
                    # Получаем URL для скачивания файла
                    disk_file_info_url = f"{BITRIX_URL.rstrip('/')}/disk.file.get.json"
                    disk_file_response = requests.post(disk_file_info_url, json={"id": f_id})
                    disk_file_response.raise_for_status()
                    
                    disk_file_data = disk_file_response.json().get('result', {})
                    download_url = disk_file_data.get('DOWNLOAD_URL')
                    file_name = disk_file_data.get('NAME', f'bx_{f_id}.pdf')
                    
                    if download_url and file_name.lower().endswith('.pdf'):
                        path = f"downloads/{file_name}"
                        Path("downloads").mkdir(exist_ok=True)
                        
                        f_res = requests.get(download_url)
                        f_res.raise_for_status()
                        with open(path, "wb") as f: f.write(f_res.content)
                        
                        md = get_text_llama_parse(path)
                        count = process_and_save(md)
                        
                        bitrix_send_message(dialog_id_for_response, f"✅ Битрикс: добавлено строк: {count} на основной лист.")
                        if os.path.exists(path): os.remove(path)
                    else:
                        logger.warning(f"Файл {file_name} не является PDF или ссылка на скачивание отсутствует.")
                        bitrix_send_message(dialog_id_for_response, f"⚠️ Не удалось обработать файл: {file_name}. Убедитесь, что это PDF.")
                        
                except Exception as e:
                    logger.error(f"Ошибка обработки файла {file_name} (ID: {f_id}): {e}", exc_info=True)
                    bitrix_send_message(dialog_id_for_response, f"❌ Произошла ошибка при обработке файла {file_name}.")
        
        # --- Обработка текстовых команд ---
        message_text = (
            data.get('data[PARAMS][MESSAGE]')
            or (json_data.get('data') or {}).get('PARAMS', {}).get('MESSAGE')
            or ''
        ).strip()
        if message_text:
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

            elif message_text.lower() == "помощь": 
                bitrix_send_message(dialog_id_for_response, "Доступные команды: 'статус', 'помощь'. Я также автоматически обрабатываю PDF-файлы, отправленные мне в чат.")
            
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

    return "OK", 200 # Возвращаем OK, чтобы Битрикс знал, что сообщение получено

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
