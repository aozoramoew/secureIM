from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_cors import CORS
from flask_mail import Mail
from config import config_map
import os

db       = SQLAlchemy()
socketio = SocketIO()
mail     = Mail()


def create_app(env: str | None = None):
    env = env or os.environ.get('FLASK_ENV', 'development')
    config_class = config_map.get(env, config_map['default'])

    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates'),
        static_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static'),
        instance_path=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'instance'),
        instance_relative_config=False,
    )
    app.config.from_object(config_class)

    # Extensions
    db.init_app(app)
    CORS(app, resources={r'/api/*': {'origins': '*'}})
    mail.init_app(app)
    socketio.init_app(
        app,
        async_mode=app.config['SOCKETIO_ASYNC_MODE'],
        cors_allowed_origins='*',
        logger=False,
        engineio_logger=False,
    )

    # Rate limiter
    from app.limiter import limiter
    limiter.init_app(app)

    # Security headers (CSP etc.)
    from app.security import init_security
    init_security(app)

    # Blueprints
    from app.auth   import auth_bp
    from app.chat   import chat_bp
    from app.routes import routes_bp
    app.register_blueprint(auth_bp,   url_prefix='/api/auth')
    app.register_blueprint(chat_bp,   url_prefix='/api/chat')
    app.register_blueprint(routes_bp)

    # SocketIO handlers
    from app import chat as _chat_events  # noqa: F401

    with app.app_context():
        db.create_all()

    # Background scheduler (only in main process, not reloader child)
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        from app.scheduler import start_scheduler
        start_scheduler(app)

    return app
