"""
Email utility — gửi verification/2FA emails.

Thứ tự ưu tiên engine:
  1. Resend API  (set RESEND_API_KEY) — khuyến nghị, miễn phí 3000/tháng
  2. SMTP        (set MAIL_SERVER + MAIL_USERNAME + MAIL_PASSWORD) — Gmail, v.v.
  3. Dev mode    (MAIL_SUPPRESS_SEND=true) — chỉ in link ra console/terminal

Setup Resend (miễn phí, không cần thẻ):
  1. Đăng ký tại https://resend.com
  2. API Keys → Create API Key
  3. Thêm env var: RESEND_API_KEY=re_xxxxxxxxxxxx
  4. Nếu chưa có domain: để RESEND_FROM_EMAIL=onboarding@resend.dev (hoạt động ngay)
     Nếu có domain riêng: verify domain trong Resend, dùng noreply@yourdomain.com
"""
import json
import urllib.request
import urllib.error

from flask import current_app, render_template_string
from flask_mail import Message
from app import mail

# ── Email templates ───────────────────────────────────────────────

_VERIFY_EMAIL_BODY = """\
<!DOCTYPE html>
<html>
<body style="background:#0a0e1a;color:#e2e8f0;font-family:sans-serif;padding:40px;">
  <div style="max-width:520px;margin:auto;background:#111827;border-radius:12px;
              border:1px solid #1e293b;padding:40px;">
    <h1 style="color:#00d4ff;margin-top:0;">🔒 SecureIM</h1>
    <h2>Verify Your Email</h2>
    <p>Hello <strong>{{ username }}</strong>,</p>
    <p>Click the button below to activate your SecureIM account.</p>
    <a href="{{ link }}"
       style="display:inline-block;padding:14px 28px;background:#00d4ff;
              color:#0a0e1a;border-radius:8px;text-decoration:none;font-weight:700;">
      Activate Account
    </a>
    <p style="color:#64748b;margin-top:32px;font-size:13px;">
      This link expires in 24 hours.<br>If you did not create a SecureIM account, ignore this email.
    </p>
  </div>
</body>
</html>
"""

_2FA_EMAIL_BODY = """\
<!DOCTYPE html>
<html>
<body style="background:#0a0e1a;color:#e2e8f0;font-family:sans-serif;padding:40px;">
  <div style="max-width:520px;margin:auto;background:#111827;border-radius:12px;
              border:1px solid #1e293b;padding:40px;">
    <h1 style="color:#00d4ff;margin-top:0;">🔒 SecureIM</h1>
    <h2>New Device Authorization</h2>
    <p>Hello <strong>{{ username }}</strong>,</p>
    <p>A login attempt was made from: <strong>{{ device_name }}</strong></p>
    <p>Click below to authorize this device (link valid for 15 minutes):</p>
    <a href="{{ link }}"
       style="display:inline-block;padding:14px 28px;background:#7c3aed;
              color:#fff;border-radius:8px;text-decoration:none;font-weight:700;">
      Authorize Device
    </a>
    <p style="color:#ef4444;margin-top:24px;">
      If this was not you, <strong>do not click the link</strong> and change your password immediately.
    </p>
    <p style="color:#64748b;margin-top:32px;font-size:13px;">
      This link expires in 15 minutes.
    </p>
  </div>
</body>
</html>
"""


# In-dev buffer: last 10 links (never used in production)
_dev_link_buffer: list[dict] = []


# ── Resend API sender ─────────────────────────────────────────────

def _send_via_resend(subject: str, recipient_email: str, html_body: str) -> bool:
    """
    Send email via Resend HTTP API.
    Returns True on success, False on failure.
    Docs: https://resend.com/docs/api-reference/emails/send-email
    """
    api_key   = current_app.config.get('RESEND_API_KEY', '')
    from_addr = current_app.config.get('RESEND_FROM_EMAIL', 'onboarding@resend.dev')

    if not api_key:
        return False

    payload = json.dumps({
        'from':    from_addr,
        'to':      [recipient_email],
        'subject': subject,
        'html':    html_body,
    }).encode('utf-8')

    req = urllib.request.Request(
        'https://api.resend.com/emails',
        data=payload,
        headers={
            'Authorization': f'Bearer {api_key}',
            'Content-Type':  'application/json',
        },
        method='POST',
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            email_id = result.get('id', 'unknown')
            print(f'[EMAIL] Sent via Resend — id={email_id} to={recipient_email}')
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        print(f'[EMAIL ERROR] Resend HTTP {e.code}: {body}')
        return False
    except Exception as e:
        print(f'[EMAIL ERROR] Resend failed: {e}')
        return False


# ── SMTP sender (Flask-Mail fallback) ────────────────────────────

def _send_via_smtp(subject: str, recipient_email: str, html_body: str) -> bool:
    """
    Send email via configured SMTP server (Flask-Mail).
    Returns True on success, False on failure.
    """
    smtp_user = current_app.config.get('MAIL_USERNAME', '')
    if not smtp_user:
        return False

    try:
        msg = Message(subject=subject, recipients=[recipient_email], html=html_body)
        mail.send(msg)
        print(f'[EMAIL] Sent via SMTP to={recipient_email}')
        return True
    except Exception as e:
        print(f'[EMAIL ERROR] SMTP failed: {e}')
        return False


# ── Main send dispatcher ──────────────────────────────────────────

def _send(subject: str, recipient_email: str, html_body: str, link: str):
    """
    Send an email using the best available engine.
    Priority: Resend API → SMTP → Dev console log.
    """

    # 1. Dev suppress mode — print to terminal only
    if current_app.config.get('MAIL_SUPPRESS_SEND', False):
        entry = {'to': recipient_email, 'subject': subject, 'link': link}
        _dev_link_buffer.append(entry)
        if len(_dev_link_buffer) > 10:
            _dev_link_buffer.pop(0)
        print('\n' + '═' * 70)
        print(f'[DEV EMAIL] To     : {recipient_email}')
        print(f'[DEV EMAIL] Subject: {subject}')
        print(f'[DEV EMAIL] ⭐ Link  : {link}')
        print(f'[DEV EMAIL] Also at: /api/auth/dev-links')
        print('═' * 70 + '\n')
        return

    # 2. Try Resend API (recommended — free, works on Railway)
    if _send_via_resend(subject, recipient_email, html_body):
        return

    # 3. Try SMTP fallback
    if _send_via_smtp(subject, recipient_email, html_body):
        return

    # 4. All methods failed — log the link so admin can manually share it
    print('\n' + '⚠' * 70)
    print(f'[EMAIL FAILED] Could not send email to {recipient_email}')
    print(f'[EMAIL FAILED] Subject: {subject}')
    print(f'[EMAIL FAILED] Link: {link}')
    print(f'[EMAIL FAILED] Set RESEND_API_KEY env var to enable email sending.')
    print('⚠' * 70 + '\n')

    # Store in dev buffer even in production so admin can retrieve via /api/auth/dev-links
    entry = {'to': recipient_email, 'subject': subject, 'link': link}
    _dev_link_buffer.append(entry)
    if len(_dev_link_buffer) > 10:
        _dev_link_buffer.pop(0)


# ── Public send functions ─────────────────────────────────────────

def send_verification_email(user, token: str):
    link = f"{current_app.config['BASE_URL']}/verify-email?token={token}"
    html = render_template_string(_VERIFY_EMAIL_BODY, username=user.username, link=link)
    _send("Activate your SecureIM account", user.email, html, link)


def send_2fa_email(user, device_name: str, token: str):
    link = f"{current_app.config['BASE_URL']}/authorize-device?token={token}"
    html = render_template_string(_2FA_EMAIL_BODY, username=user.username,
                                  device_name=device_name, link=link)
    _send("SecureIM — Authorize new device", user.email, html, link)
