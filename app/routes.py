"""Page routes — serve HTML templates."""
from flask import Blueprint, render_template, redirect, url_for, request

routes_bp = Blueprint('routes', __name__)


@routes_bp.route('/')
def index():
    return redirect(url_for('routes.login_page'))


@routes_bp.route('/login')
def login_page():
    return render_template('login.html')


@routes_bp.route('/register')
def register_page():
    return render_template('register.html')


@routes_bp.route('/chat')
def chat_page():
    return render_template('chat.html')


@routes_bp.route('/verify-email')
def verify_email_page():
    """
    Email links point to /verify-email?token=... (no /api prefix).
    We redirect to the API endpoint which performs DB validation
    and then redirects to /login?verified=1 or /?error=...
    """
    token = request.args.get('token', '')
    if token:
        return redirect(f'/api/auth/verify-email?token={token}')
    return render_template('verify_email.html')


@routes_bp.route('/authorize-device')
def authorize_device_page():
    """
    2FA links point to /authorize-device?token=... (no /api prefix).
    We redirect to the API endpoint which activates the device.
    """
    token = request.args.get('token', '')
    if token:
        return redirect(f'/api/auth/2fa-verify?token={token}')
    return render_template('device_authorized.html')


@routes_bp.route('/two-factor')
def two_factor_page():
    return render_template('two_factor.html')


@routes_bp.route('/device-authorized')
def device_authorized_page():
    """Shown after 2FA device approval (auth.py redirects here)."""
    return render_template('device_authorized.html')
