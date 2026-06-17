"""Brute-force / credential stuffing simulation.

Gửi nhiều login request liên tiếp để test:
1. Rate limiter (slowapi) có block 429 không
2. WAF có detect pattern bất thường không
"""
import sys, os, time; sys.path.insert(0, os.path.dirname(__file__))
from _common import req, report, summary, BASE_URL, BOLD, CYAN, YELLOW, RESET
import secrets

print(f'\n{BOLD}[06] BRUTE FORCE / CREDENTIAL STUFFING — target: {CYAN}{BASE_URL}{RESET}')
print('─' * 55)

# Danh sách passwords thường bị thử trong credential stuffing
COMMON_PASSWORDS = [
    'password', '123456', 'qwerty', 'letmein', 'admin',
    'password1', '12345678', 'iloveyou', 'sunshine', 'monkey',
    'master', 'dragon',
]

TARGET_USER = 'alice'

print(f'  {YELLOW}Simulating credential stuffing against user "{TARGET_USER}"...{RESET}')

rate_limited = False
for i, pw in enumerate(COMMON_PASSWORDS):
    status, body = req('POST', '/api/auth/login', {
        'username': TARGET_USER,
        'password': pw,
        'device_id': secrets.token_hex(8),
        'device_name': f'AttackBot-{i}',
        'ecdsa_public_key': '{}',
        'ecdh_public_key': '{}',
    })
    print(f'    attempt {i+1:2d}  pw="{pw:<12}" → HTTP {status}')
    if status == 429:
        rate_limited = True
        print(f'  {CYAN}→ Rate limit triggered at attempt {i+1}{RESET}')
        break

report(
    'Rate limiter blocks credential stuffing (429)',
    429 if rate_limited else 200,
    expect_block=True,
    payload=f'{len(COMMON_PASSWORDS)} rapid login attempts',
)

# Rapid registration flood (account creation abuse)
print(f'\n  {YELLOW}Simulating registration flood...{RESET}')
reg_rate_limited = False
for i in range(8):
    ts = secrets.token_hex(3)
    status, _ = req('POST', '/api/auth/register', {
        'username': f'flood_{ts}',
        'password': 'Test@1234',
        'device_id': secrets.token_hex(8),
        'device_name': 'FloodBot',
        'ecdsa_public_key': '{}',
        'ecdh_public_key': '{}',
    })
    print(f'    reg attempt {i+1} → HTTP {status}')
    if status == 429:
        reg_rate_limited = True
        print(f'  {CYAN}→ Rate limit triggered at reg attempt {i+1}{RESET}')
        break

report(
    'Rate limiter blocks registration flood (429)',
    429 if reg_rate_limited else 200,
    expect_block=True,
    payload='8 rapid registration attempts',
)

summary('Brute Force / Rate Limiting')
