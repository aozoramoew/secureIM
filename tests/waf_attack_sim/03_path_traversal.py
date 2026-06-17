"""Path Traversal / Directory Traversal payloads."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from _common import req, report, summary, BASE_URL, BOLD, CYAN, RESET

print(f'\n{BOLD}[03] PATH TRAVERSAL — target: {CYAN}{BASE_URL}{RESET}')
print('─' * 55)

CASES = [
    ("../etc/passwd classic",
     'GET', '/static/../../../../etc/passwd', None, True),

    ("URL-encoded traversal (%2e%2e)",
     'GET', '/static/%2e%2e/%2e%2e/%2e%2e/etc/passwd', None, True),

    ("Double-encoded (%252e%252e)",
     'GET', '/static/%252e%252e/%252e%252e/etc/shadow', None, True),

    ("Windows-style traversal (..\\ in path)",
     'GET', '/static/..%5c..%5c..%5cwindows/win.ini', None, True),

    ("Null-byte injection in path",
     'GET', '/static/file.txt%00.jpg', None, True),

    ("Traversal in query string",
     'GET', '/api/chat/users?q=../../../etc/passwd', None, True),

    # Benign
    ("Normal static file request (benign)",
     'GET', '/static/app.js', None, False),

    ("Normal API path (benign)",
     'GET', '/api/health', None, False),
]

for label, method, path, body, expect_block in CASES:
    status, _ = req(method, path, body)
    report(label, status, expect_block, path)

summary('Path Traversal')
