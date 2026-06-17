"""Shared helpers for WAF attack simulation scripts."""
import json
import sys
import urllib.error
import urllib.request

BASE_URL = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else 'http://localhost:8000'

GREEN  = '\033[92m'
RED    = '\033[91m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

_results: list[dict] = []



# Headers mà mọi browser thật đều gửi — thiếu các headers này sẽ bị anti_bot block.
_BROWSER_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/125.0.0.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'vi-VN,vi;q=0.9,en;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
}

# Headers dùng khi gửi JSON API request (POST login, register, …)
_API_HEADERS = {
    **_BROWSER_HEADERS,
    'Accept': 'application/json',
    'Content-Type': 'application/json',
}


def req(method: str, path: str, data=None, headers: dict | None = None) -> tuple[int, dict]:
    url = BASE_URL + path
    base = _API_HEADERS if data is not None else _BROWSER_HEADERS
    h = {**base, **(headers or {})}
    body = json.dumps(data).encode() if data is not None else None
    request = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(request, timeout=5) as r:
            try:
                return r.status, json.loads(r.read())
            except Exception:
                return r.status, {}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except Exception as ex:
        return 0, {'error': str(ex)}


def report(label: str, status: int, expect_block: bool, payload: str = ''):
    # 429 = secureIM's own slowapi rate limiter rejected the request before
    # it ever reached the WAF or the route handler. It says nothing about
    # whether the WAF would have detected this payload, so it must not be
    # scored as either a correct or incorrect WAF detection — otherwise
    # running the suite twice in quick succession silently inflates or
    # deflates the score with results that have nothing to do with the WAF.
    if status == 429:
        print(f'  {YELLOW}⊘ RATE-LIMITED (429) — skipped, not a WAF result{RESET}  |  {label}')
        _results.append({'label': label, 'status': status, 'ok': None, 'expect_block': expect_block})
        return None

    blocked = status == 403
    if expect_block:
        ok = blocked
        tag = f'{GREEN}BLOCKED (403){RESET}' if ok else f'{YELLOW}ALLOWED ({status}){RESET} ← false negative'
    else:
        ok = not blocked
        tag = f'{GREEN}ALLOWED ({status}){RESET}' if ok else f'{RED}BLOCKED (403){RESET} ← false positive'

    short_payload = (payload[:60] + '…') if len(payload) > 60 else payload
    print(f'  {"✓" if ok else "✗"} {tag}  |  {label}')
    if short_payload:
        print(f'    {CYAN}payload: {short_payload}{RESET}')
    _results.append({'label': label, 'status': status, 'ok': ok, 'expect_block': expect_block})
    return ok


def summary(section: str):
    scored = [r for r in _results if r['ok'] is not None]
    skipped = len(_results) - len(scored)
    total  = len(scored)
    passed = sum(1 for r in scored if r['ok'])
    print(f'\n{BOLD}{"─"*55}{RESET}')
    print(f'{BOLD}{section} — {passed}/{total} correct detections{RESET}'
          + (f'  ({skipped} skipped: rate-limited)' if skipped else ''))
    if passed == total:
        print(f'{GREEN}All checks passed{RESET}')
    else:
        missed = [r for r in scored if not r['ok']]
        for r in missed:
            exp = 'block' if r['expect_block'] else 'allow'
            print(f'  {YELLOW}✗ expected {exp}: {r["label"]}{RESET}')
    return passed, total
