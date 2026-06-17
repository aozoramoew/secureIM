"""Chạy toàn bộ WAF attack simulation và in báo cáo tổng hợp."""
import sys, os, importlib, time

BASE_URL = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else 'http://localhost:8000'
sys.argv = [sys.argv[0], BASE_URL]  # truyền xuống các sub-scripts

GREEN  = '\033[92m'
RED    = '\033[91m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

SCRIPTS = [
    ('01_sqli',          'SQL Injection'),
    ('02_xss',           'XSS'),
    ('03_path_traversal','Path Traversal'),
    ('04_cmdi',          'Command Injection'),
    ('05_ssrf',          'SSRF'),
    ('06_brute_force',   'Brute Force'),
    ('07_benign',        'Benign Baseline'),
]

print(f'\n{BOLD}{"═"*60}')
print(f'  SecureIM — ML-WAF Attack Simulation Suite')
print(f'  Target : {CYAN}{BASE_URL}{RESET}{BOLD}')
print(f'  Time   : {time.strftime("%Y-%m-%d %H:%M:%S")}')
print(f'{"═"*60}{RESET}')

here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)

totals = {'passed': 0, 'total': 0}

for module_name, label in SCRIPTS:
    # Each script uses _common._results; reset between runs
    import _common
    _common._results.clear()

    mod = importlib.import_module(module_name)
    # summary() already printed inside each script; grab counts from _results.
    # Exclude ok=None (429 rate-limited) — those are not WAF detection results.
    scored = [r for r in _common._results if r['ok'] is not None]
    p = sum(1 for r in scored if r['ok'])
    t = len(scored)
    totals['passed'] += p
    totals['total']  += t

    # Force reimport next time
    del sys.modules[module_name]

p, t = totals['passed'], totals['total']
score = int(p / t * 100) if t else 0
color = GREEN if score >= 90 else (YELLOW if score >= 70 else RED)

print(f'\n{BOLD}{"═"*60}')
print(f'  OVERALL WAF DETECTION ACCURACY')
print(f'{"═"*60}{RESET}')
print(f'  Checks : {t}')
print(f'  Correct: {p}')
print(f'  {BOLD}{color}Score  : {score}%{RESET}')
print()
