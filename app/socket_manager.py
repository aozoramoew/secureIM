"""
python-socketio AsyncServer singleton.
Imported by both app/__init__.py (to build the ASGI app) and
app/chat.py (to register socket event handlers).
"""
import socketio

sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins='*',
    logger=False,
    engineio_logger=False,
    # 25 MB: encrypted_payloads is base64 ciphertext (~1.37x)
    # duplicated per recipient/sender device, so a 2 MB attachment
    # can need ~10MB+ across several devices.
    max_http_buffer_size=25 * 1024 * 1024,
)
