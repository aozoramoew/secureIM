"""
Mock ML-WAF sidecar — dùng khi chưa có WAF sidecar thật.

Chế độ:
  ALLOW mode (mặc định): in snapshot, luôn trả ALLOW — dùng để xem WAF nhận gì
  BLOCK mode: set MOCK_WAF_MODE=block — block bất kỳ request nào có keyword nguy hiểm

Chạy:
  python mock_waf_sidecar.py
  MOCK_WAF_MODE=block python mock_waf_sidecar.py
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

BLOCK_MODE = os.environ.get('MOCK_WAF_MODE', 'allow').lower() == 'block'

BLOCK_KEYWORDS = [
    "'", 'union select', 'drop table', 'sleep(',
    '<script', 'onerror=', 'javascript:',
    '../', '..\\', '%2e%2e', '%252e',
    '; ls', '| whoami', '`id`', '$(', 'cmd.exe',
    '169.254.169.254', '/etc/passwd', '/etc/shadow',
]

GREEN  = '\033[92m'
RED    = '\033[91m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
RESET  = '\033[0m'


class WAFHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get('content-length', 0))
        raw = self.rfile.read(length)
        try:
            snap = json.loads(raw)
        except Exception:
            snap = {}

        url    = snap.get('url', '')
        method = snap.get('method', '')
        ip     = snap.get('ip', '')
        body   = snap.get('body', '')
        all_text = (url + body).lower()

        if BLOCK_MODE:
            matched = next((kw for kw in BLOCK_KEYWORDS if kw in all_text), None)
            if matched:
                decision = 'BLOCK'
                attack_type = _classify(matched)
                ref = f'MOCK-{abs(hash(url)) % 10000:04d}'
                color = RED
            else:
                decision = 'ALLOW'
                attack_type = None
                ref = None
                color = GREEN
        else:
            decision = 'ALLOW'
            attack_type = None
            ref = None
            color = CYAN

        short_url = (url[:80] + '…') if len(url) > 80 else url
        print(f'{color}[{decision}]{RESET} {method} {short_url}  ip={ip}  '
              + (f'attack={attack_type}' if attack_type else ''))

        resp = json.dumps({
            'decision':    decision,
            'attack_type': attack_type,
            'id':          ref,
        }).encode()
        self.send_response(200)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


def _classify(keyword: str) -> str:
    if any(k in keyword for k in ["'", 'union', 'drop', 'sleep']):
        return 'sqli'
    if any(k in keyword for k in ['<script', 'onerror', 'javascript:']):
        return 'xss'
    if any(k in keyword for k in ['../', '..\\', '%2e']):
        return 'path_traversal'
    if any(k in keyword for k in ['; ls', 'whoami', '`id`', '$(']):
        return 'cmdi'
    if '169.254' in keyword or '/etc/passwd' in keyword:
        return 'ssrf'
    return 'unknown'


if __name__ == '__main__':
    mode_label = f'{RED}BLOCK{RESET}' if BLOCK_MODE else f'{CYAN}ALLOW (observe only){RESET}'
    print(f'Mock ML-WAF sidecar — mode: {mode_label}')
    print('Listening on http://127.0.0.1:8001/analyze')
    print('Set MOCK_WAF_MODE=block to enable blocking\n')
    HTTPServer(('127.0.0.1', 8001), WAFHandler).serve_forever()
