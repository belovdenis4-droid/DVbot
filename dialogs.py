def handle_dialogs_command(dialog_id, send_message, **kwargs):
    if kwargs:
        send_message(dialog_id, f"dialog_id: {dialog_id}", **kwargs)
    else:
        send_message(dialog_id, f"dialog_id: {dialog_id}")
