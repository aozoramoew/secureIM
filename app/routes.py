"""Page routes — serve Jinja2 HTML templates."""
import os
import time

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()

_templates_dir = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates'
)
templates = Jinja2Templates(directory=_templates_dir)

# Cache-busting version injected into every template as {{ v }}.
# Uses process start time so each server restart invalidates browser caches.
_STATIC_VER = str(int(time.time()))


def _ctx(request: Request, **extra):
    return {'request': request, 'v': _STATIC_VER, **extra}


@router.get('/')
def index():
    return RedirectResponse(url='/login')


@router.get('/login')
def login_page(request: Request):
    return templates.TemplateResponse('login.html', _ctx(request))


@router.get('/register')
def register_page(request: Request):
    return templates.TemplateResponse('register.html', _ctx(request))


@router.get('/chat')
def chat_page(request: Request):
    return templates.TemplateResponse('chat.html', _ctx(request))
