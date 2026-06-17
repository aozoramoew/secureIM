"""SQL Injection payloads — gửi vào các endpoint của SecureIM."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from _common import req, report, summary, BASE_URL, BOLD, CYAN, RESET

print(f'\n{BOLD}[01] SQL INJECTION — target: {CYAN}{BASE_URL}{RESET}')
print('─' * 55)

CASES = [
    # (label, method, path, body_or_params, expect_block)

    # Classic auth bypass in login body
    ("Classic OR bypass in username",
     'POST', '/api/auth/login',
     {'username': "' OR '1'='1", 'password': 'x',
      'device_id': 'aaa', 'device_name': 'x',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     True),

    ("UNION SELECT in username",
     'POST', '/api/auth/login',
     {'username': "admin' UNION SELECT 1,2,3--", 'password': 'x',
      'device_id': 'aaa', 'device_name': 'x',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     True),

    ("Stacked query with DROP TABLE",
     'POST', '/api/auth/login',
     {'username': "x'; DROP TABLE users;--", 'password': 'x',
      'device_id': 'aaa', 'device_name': 'x',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     True),

    ("Blind SQLi time-based (SLEEP)",
     'POST', '/api/auth/login',
     {'username': "1' AND SLEEP(5)--", 'password': 'x',
      'device_id': 'aaa', 'device_name': 'x',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     True),

    ("SQLi in query string",
     'GET', '/api/chat/users?q=%27+OR+1%3D1--',
     None, True),

    ("Hex-encoded SQLi",
     'POST', '/api/auth/login',
     {'username': "0x27 OR 0x313d31", 'password': 'x',
      'device_id': 'aaa', 'device_name': 'x',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     True),

    # Benign — should NOT be blocked
    ("Normal username (benign)",
     'POST', '/api/auth/login',
     {'username': 'alice', 'password': 'Test@1234',
      'device_id': 'aaa', 'device_name': 'MyPhone',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     False),

    ("Normal search query (benign)",
     'GET', '/api/chat/users?q=bob', None, False),
]

for label, method, path, body, expect_block in CASES:
    status, _ = req(method, path, body)
    payload = str(body.get('username', path)) if body else path
    report(label, status, expect_block, payload)

summary('SQL Injection')
