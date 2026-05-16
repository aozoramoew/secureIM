from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_cors import CORS
from flask_mail import Mail
from config import Config

db       = SQLAlchemy()
socketio = SocketIO()
mail     = Mail()


import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def create_app(config_class=Config):
    app = Flask(
        __name__,
        template_folder=os.path.join(BASE_DIR, 'templates'),
        static_folder=os.path.join(BASE_DIR, 'static'),
        instance_path=os.path.join(BASE_DIR, 'instance'),
        instance_relative_config=False,
    )
    app.config.from_object(config_class)

    db.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    mail.init_app(app)
    socketio.init_app(
        app,
        async_mode=app.config['SOCKETIO_ASYNC_MODE'],
        cors_allowed_origins="*",
        logger=False,
        engineio_logger=False,
    )

    # Register blueprints
    from app.auth   import auth_bp
    from app.chat   import chat_bp
    from app.routes import routes_bp

    app.register_blueprint(auth_bp,   url_prefix='/api/auth')
    app.register_blueprint(chat_bp,   url_prefix='/api/chat')
    app.register_blueprint(routes_bp)

    # Register SocketIO event handlers
    from app import chat as _chat_events  # noqa: F401

    with app.app_context():
        db.create_all()

    return app
