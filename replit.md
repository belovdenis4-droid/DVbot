# Laundry Bot

A Telegram bot that automatically imports laundry invoices (PDF files) into Google Sheets.

## Overview

This bot receives PDF files via Telegram, extracts text from them, and appends the data to a Google Sheets spreadsheet.

## Architecture

- **bot.py**: Main bot logic with Telegram handlers and Google Sheets integration
- **Python 3.12** with poetry for dependency management

## Required Environment Variables

- `TELEGRAM_TOKEN`: Your Telegram Bot API token (get from @BotFather)
- `GOOGLE_SERVICE_ACCOUNT_FILE`: Path to Google service account JSON file (default: `service_account.json`)
- `SPREADSHEET_NAME`: Name of the Google Sheets spreadsheet (default: `Счета прачки`)

## Setup

1. Create a Telegram bot via @BotFather and set the `TELEGRAM_TOKEN` secret
2. Create a Google Cloud service account with Sheets API access
3. Download the service account JSON and save it as `service_account.json` (or set the path via `GOOGLE_SERVICE_ACCOUNT_FILE`)
4. Share your Google Sheet with the service account email
5. Set `SPREADSHEET_NAME` to your spreadsheet's name

## Running

The bot runs via the "Telegram Bot" workflow and uses polling to receive messages.

## Recent Changes

- 2026-01-07: Adapted for Replit environment, made Google credentials path configurable via environment variable
