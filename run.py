from app import create_app, socketio

app = create_app()

if __name__ == '__main__':
    print("=" * 60)
    print("  SecureIM — Zero-Trust Messaging System")
    print("  Running at http://localhost:5000")
    print("=" * 60)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
