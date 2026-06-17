"""SSRF (Server-Side Request Forgery) payloads.

Test đặc biệt quan trọng vì commit fix gần đây liên quan đến SSRF false positive
trong WAF middleware (full_url được build từ Host header thay vì scope['server']).
"""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from _common import req, report, summary, BASE_URL, BOLD, CYAN, RESET

print(f'\n{BOLD}[05] SSRF — target: {CYAN}{BASE_URL}{RESET}')
print('─' * 55)

# Các endpoint nhận URL/redirect là nơi SSRF thường xuất hiện
CASES = [
    ("SSRF via avatar/image URL param pointing to internal",
     'POST', '/api/auth/register',
     {'username': 'ssrf_test1', 'password': 'Test@1234',
      'device_id': 'ddd', 'device_name': 'x',
      'ecdsa_public_key': 'http://169.254.169.254/latest/meta-data/',
      'ecdh_public_key': '{}'},
     True),

    ("SSRF AWS metadata endpoint in body",
     'POST', '/api/auth/login',
     {'username': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      'password': 'x', 'device_id': 'ddd', 'device_name': 'x',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     True),

    ("SSRF localhost redirect",
     'GET', '/api/chat/users?q=http://localhost:22/ssh-banner', None, True),

    ("SSRF internal RFC1918 10.x.x.x",
     'GET', '/api/chat/users?q=http://10.0.0.1/admin', None, True),

    ("SSRF internal 192.168.x.x",
     'GET', '/api/chat/users?q=http://192.168.1.1/router-admin', None, True),

    ("SSRF via URL-encoded internal",
     'GET', '/api/chat/users?q=http%3A%2F%2F127.0.0.1%3A8080%2Fadmin', None, True),

    ("SSRF Railway internal 100.64.x.x (should be caught now after fix)",
     'GET', '/api/chat/users?q=http://100.64.1.1/internal-service', None, True),

    # Benign — false positive check (critical after the fix)
    ("Normal HTTPS URL in search (benign — WAF must NOT block)",
     'GET', '/api/chat/users?q=alice', None, False),

    ("Health check (benign — must not be blocked)",
     'GET', '/api/health', None, False),
]

for label, method, path, body, expect_block in CASES:
    status, _ = req(method, path, body)
    payload = path if not body else str(list(body.values())[:2])
    report(label, status, expect_block, payload)

summary('SSRF')
