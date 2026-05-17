import os
from app import create_app, socketio

env = os.environ.get('FLASK_ENV', 'development')
app = create_app(env)

if __name__ == '__main__':
    print("=" * 60)
    print("  SecureIM — Zero-Trust Messaging System")
    print(f"  Environment : {env}")
    print("  Running at  : http://localhost:5000")
    print("  Email links : check terminal (MAIL_SUPPRESS_SEND=true)")
    print("=" * 60)
    socketio.run(
        app,
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=(env == 'development'),
        allow_unsafe_werkzeug=True,
    )
