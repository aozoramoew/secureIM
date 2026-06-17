"""Cross-Site Scripting (XSS) payloads."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from _common import req, report, summary, BASE_URL, BOLD, CYAN, RESET

print(f'\n{BOLD}[02] XSS — target: {CYAN}{BASE_URL}{RESET}')
print('─' * 55)

CASES = [
    ("Reflected XSS in query string",
     'GET', '/api/chat/users?q=<script>alert(1)</script>',
     None, True),

    ("Stored XSS attempt via username field",
     'POST', '/api/auth/register',
     {'username': '<script>alert("xss")</script>',
      'password': 'Test@1234', 'device_id': 'bbb', 'device_name': 'x',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     True),

    ("img onerror payload",
     'GET', '/api/chat/users?q=<img+src=x+onerror=alert(1)>',
     None, True),

    ("SVG/onload variant",
     'POST', '/api/auth/login',
     {'username': '<svg onload=alert(1)>', 'password': 'x',
      'device_id': 'bbb', 'device_name': 'x',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     True),

    ("javascript: URI",
     'GET', '/api/chat/users?q=javascript:alert(document.cookie)',
     None, True),

    ("HTML entity bypass attempt",
     'POST', '/api/auth/login',
     {'username': '&lt;script&gt;alert(1)&lt;/script&gt;', 'password': 'x',
      'device_id': 'bbb', 'device_name': 'x',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     True),

    # Benign
    ("Normal search with special chars (benign)",
     'GET', '/api/chat/users?q=alice+bob', None, False),

    ("Normal login attempt (benign)",
     'POST', '/api/auth/login',
     {'username': 'alice', 'password': 'Test@1234',
      'device_id': 'bbb', 'device_name': 'MyPhone',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     False),
]

for label, method, path, body, expect_block in CASES:
    status, _ = req(method, path, body)
    payload = str(body.get('username', path)) if body else path
    report(label, status, expect_block, payload)

summary('XSS')
