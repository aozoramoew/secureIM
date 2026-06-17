"""
ML-WAF middleware — forwards each HTTP request to the ML-WAF sidecar for analysis.

Implemented as pure ASGI (not BaseHTTPMiddleware) for the same reason as
SecurityHeadersMiddleware: avoids Starlette's exception-swallowing bug.

Behaviour:
- WebSocket / lifespan scopes are passed through untouched.
- On BLOCK decision  → 403 JSON response, request never reaches the app.
- On timeout / error → fail-open (request continues). Keeps latency impact
  bounded and avoids WAF becoming a single point of failure.
- Socket.IO polling (/socket.io/) passes through — the WAF analyzes these
  only if MLWAF_INSPECT_SOCKETIO=true (default off, high-volume path).
"""
import ipaddress
import json
import logging
import os
import time
from collections import deque

import httpx

from config import settings

_log = logging.getLogger(__name__)

_INSPECT_SOCKETIO = os.environ.get('MLWAF_INSPECT_SOCKETIO', 'false').lower() == 'true'

# Cheap per-IP rate limit applied before any DB/WAF-sidecar work, so a flood
# of malicious traffic can't starve the single event loop worker of CPU/IO
# needed to service legitimate requests (incl. Socket.IO polling/handshakes).
_RATE_LIMIT_REQUESTS = int(os.environ.get('MLWAF_RATE_LIMIT_REQUESTS', '200'))
_RATE_LIMIT_WINDOW = float(os.environ.get('MLWAF_RATE_LIMIT_WINDOW', '10'))
_request_log: dict[str, deque] = {}


def _is_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    bucket = _request_log.setdefault(ip, deque())
    while bucket and now - bucket[0] > _RATE_LIMIT_WINDOW:
        bucket.popleft()
    bucket.append(now)
    return len(bucket) > _RATE_LIMIT_REQUESTS

# Private / carrier-grade NAT ranges — skip WAF for internal traffic
# (health checks, load balancers, Railway internal network 100.64.0.0/10)
_TRUSTED_NETS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('100.64.0.0/10'),  # RFC 6598 — Railway / Fly.io internal
]


def _is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _TRUSTED_NETS)
    except ValueError:
        return False

_403_HEADERS = [
    (b'content-type', b'application/json'),
]


def _build_403(attack_type: str | None, ref: str | None) -> bytes:
    body = {
        'error': 'Blocked by ML-WAF',
        'attack_type': attack_type,
        'reference': ref,
    }
    return json.dumps(body).encode()


class MLWafMiddleware:
    """Pure ASGI middleware — sends each HTTP request snapshot to the ML-WAF sidecar."""

    def __init__(self, app):
        self.app = app
        self._waf_url = f'{settings.MLWAF_URL}/analyze'
        self._timeout = settings.MLWAF_TIMEOUT

    async def __call__(self, scope, receive, send):
        # Only inspect HTTP; leave WebSocket and lifespan untouched.
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return

        path: str = scope.get('path', '')

        # Resolve the real client IP.
        # On Railway/Fly/Heroku the actual client IP arrives in
        # X-Forwarded-For; scope['client'] is the internal proxy address.
        raw_headers = {
            k.decode('latin-1').lower(): v.decode('latin-1')
            for k, v in scope.get('headers', [])
        }
        xff = raw_headers.get('x-forwarded-for', '')
        if xff:
            # XFF is a comma-separated list; leftmost is the originating client.
            ip = xff.split(',')[0].strip()
        else:
            client = scope.get('client')
            ip = client[0] if client else '0.0.0.0'

        # Skip internal / health-check traffic (load balancers, Railway probes).
        if _is_internal(ip):
            await self.app(scope, receive, send)
            return

        # Cheap per-IP flood guard — checked before any DB/WAF-sidecar work
        # (incl. Socket.IO polling) so one noisy IP can't starve the single
        # event loop worker of the CPU/IO legitimate clients need.
        if _is_rate_limited(ip):
            _log.warning('Rate limit exceeded | ip=%s path=%s', ip, path)
            body_bytes = json.dumps({'error': 'Too many requests'}).encode()
            await send({
                'type': 'http.response.start',
                'status': 429,
                'headers': _403_HEADERS + [(b'content-length', str(len(body_bytes)).encode())],
            })
            await send({
                'type': 'http.response.body',
                'body': body_bytes,
                'more_body': False,
            })
            return

        # Optionally skip high-volume Socket.IO polling path (still subject
        # to the flood guard above, just not the slower WAF-sidecar check).
        if path.startswith('/socket.io') and not _INSPECT_SOCKETIO:
            await self.app(scope, receive, send)
            return

        # Buffer the request body so it can be forwarded to WAF and then
        # replayed to the actual application.
        body_chunks: list[bytes] = []
        more_body = True
        while more_body:
            message = await receive()
            body_chunks.append(message.get('body', b''))
            more_body = message.get('more_body', False)

        full_body = b''.join(body_chunks)

        # Build a fake receive callable that replays the buffered body.
        body_iter = iter([
            {'type': 'http.request', 'body': full_body, 'more_body': False}
        ])

        async def replay_receive():
            return next(body_iter)

        # Collect metadata for the WAF snapshot.
        headers = {
            k.decode('latin-1'): v.decode('latin-1')
            for k, v in scope.get('headers', [])
        }
        method = scope.get('method', 'GET')
        query = scope.get('query_string', b'').decode('latin-1')
        # Use the Host header so WAF sees the public domain, not the
        # internal bind address (0.0.0.0 / 100.64.x.x) which trips SSRF rules.
        host = raw_headers.get('host', 'localhost')
        scheme = raw_headers.get('x-forwarded-proto', scope.get('scheme', 'https'))
        full_url = f"{scheme}://{host}{path}"
        if query:
            full_url += f'?{query}'

        snapshot = {
            'method': method,
            'url': full_url,
            'headers': headers,
            'body': full_body.decode('utf-8', errors='replace'),
            'ip': ip,
        }

        decision = await self._analyze(snapshot)

        if decision and decision.get('decision') == 'BLOCK':
            attack_type = decision.get('attack_type')
            ref = decision.get('id')
            _log.warning(
                'ML-WAF BLOCK | ip=%s method=%s path=%s attack=%s ref=%s',
                ip, method, path, attack_type, ref,
            )
            body_bytes = _build_403(attack_type, ref)
            await send({
                'type': 'http.response.start',
                'status': 403,
                'headers': _403_HEADERS + [(b'content-length', str(len(body_bytes)).encode())],
            })
            await send({
                'type': 'http.response.body',
                'body': body_bytes,
                'more_body': False,
            })
            return

        await self.app(scope, replay_receive, send)

    async def _analyze(self, snapshot: dict) -> dict | None:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(self._waf_url, json=snapshot)
                resp.raise_for_status()
                return resp.json()
        except httpx.TimeoutException:
            _log.debug('ML-WAF timeout — fail-open')
        except Exception as exc:  # noqa: BLE001
            _log.debug('ML-WAF error — fail-open: %s', exc)
        return None
