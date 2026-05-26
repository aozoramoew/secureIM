"""
Email utility — sends verification/2FA emails.
When MAIL_SUPPRESS_SEND=true (default in dev) the link is printed to the console
so you can test without configuring an SMTP server.
"""
from flask import current_app, render_template_string
from flask_mail import Message
from app import mail

# ── Email templates (inline for simplicity) ───────────────────────

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


def _send(subject: str, recipient_email: str, html_body: str, link: str):
    """Internal send helper — logs to console when MAIL_SUPPRESS_SEND=true."""
    if current_app.config.get('MAIL_SUPPRESS_SEND', True):
        entry = {'to': recipient_email, 'subject': subject, 'link': link}
        _dev_link_buffer.append(entry)
        if len(_dev_link_buffer) > 10:
            _dev_link_buffer.pop(0)
        # Print loudly so it's visible in the terminal
        print('\n' + '\u2550' * 70)
        print(f'[DEV EMAIL] To     : {recipient_email}')
        print(f'[DEV EMAIL] Subject: {subject}')
        print(f'[DEV EMAIL] ⭐ Link  : {link}')
        print(f'[DEV EMAIL] Also at: http://localhost:5000/api/auth/dev-links')
        print('\u2550' * 70 + '\n')
        return

    msg = Message(subject=subject, recipients=[recipient_email], html=html_body)
    mail.send(msg)


def send_verification_email(user, token: str):
    link = f"{current_app.config['BASE_URL']}/verify-email?token={token}"
    html = render_template_string(_VERIFY_EMAIL_BODY, username=user.username, link=link)
    _send("Activate your SecureIM account", user.email, html, link)


def send_2fa_email(user, device_name: str, token: str):
    link = f"{current_app.config['BASE_URL']}/authorize-device?token={token}"
    html = render_template_string(_2FA_EMAIL_BODY, username=user.username,
                                  device_name=device_name, link=link)
    _send("SecureIM — Authorize new device", user.email, html, link)
