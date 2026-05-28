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
)
