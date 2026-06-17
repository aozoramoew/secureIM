"""Benign traffic baseline — kiểm tra WAF không over-block normal requests.

Đây là false-positive check: tất cả requests này phải đi qua (không bị 403).
"""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from _common import req, report, summary, BASE_URL, BOLD, CYAN, RESET

print(f'\n{BOLD}[07] BENIGN BASELINE (false-positive check) — target: {CYAN}{BASE_URL}{RESET}')
print('─' * 55)

CASES = [
    # Page routes
    ("GET /login page",               'GET',  '/login',           None),
    ("GET /register page",            'GET',  '/register',        None),
    ("GET / redirects to /login",     'GET',  '/',                None),
    ("GET /api/health",               'GET',  '/api/health',      None),

    # Auth endpoints with valid-looking data
    ("POST /api/auth/register (valid shape)",
     'POST', '/api/auth/register',
     {'username': 'demo_user_99', 'password': 'StrongPass@99',
      'device_id': 'abcdef123456', 'device_name': 'Chrome on Windows',
      'ecdsa_public_key': '{"kty":"EC","crv":"P-384"}',
      'ecdh_public_key':  '{"kty":"EC","crv":"P-256"}'}),

    ("POST /api/auth/login (valid shape)",
     'POST', '/api/auth/login',
     {'username': 'demo_user_99', 'password': 'StrongPass@99',
      'device_id': 'abcdef123456', 'device_name': 'Chrome on Windows',
      'ecdsa_public_key': '{"kty":"EC","crv":"P-384"}',
      'ecdh_public_key':  '{"kty":"EC","crv":"P-256"}'}),

    # Search with normal strings
    ("GET /api/chat/users?q=alice",   'GET', '/api/chat/users?q=alice', None),
    ("GET /api/chat/users?q=bob123",  'GET', '/api/chat/users?q=bob123', None),

    # Strings that look suspicious but are benign
    ("Username with numbers (benign)", 'GET', '/api/chat/users?q=user42', None),
    ("Username with underscore",       'GET', '/api/chat/users?q=alice_smith', None),
    ("Search with accented chars",     'GET', '/api/chat/users?q=nguy%E1%BB%85n', None),
]

for item in CASES:
    label, method, path = item[0], item[1], item[2]
    body = item[3] if len(item) > 3 else None
    status, _ = req(method, path, body)
    # expect_block=False for all benign cases
    report(label, status, expect_block=False, payload='')

summary('Benign Baseline (false-positive check)')
