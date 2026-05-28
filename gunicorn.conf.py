"""
Gunicorn configuration for production.
Uses gevent worker with WebSocket support (gevent-websocket).
Single worker — required for Socket.IO sticky sessions.
Scale horizontally with a load balancer + Redis pub/sub adapter.
"""
import multiprocessing, os

bind             = f"0.0.0.0:{os.environ.get('PORT', 5000)}"
workers          = 1          # Socket.IO requires 1 worker per process (or Redis adapter)
worker_class     = "uvicorn.workers.UvicornWorker"
worker_connections = 1000
timeout          = 120
keepalive        = 5
loglevel         = os.environ.get('LOG_LEVEL', 'info')
accesslog        = "-"        # stdout
errorlog         = "-"        # stderr
preload_app      = True
