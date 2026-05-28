"""Page routes — serve Jinja2 HTML templates. FastAPI conversion."""
import os

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()

_templates_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates')
templates = Jinja2Templates(directory=_templates_dir)


@router.get('/')
def index():
    return RedirectResponse(url='/login')


@router.get('/login')
def login_page(request: Request):
    return templates.TemplateResponse('login.html', {'request': request})


@router.get('/register')
def register_page(request: Request):
    return templates.TemplateResponse('register.html', {'request': request})


@router.get('/chat')
def chat_page(request: Request):
    return templates.TemplateResponse('chat.html', {'request': request})


@router.get('/verify-email')
def verify_email_page(request: Request, token: str = ''):
    """
    Email links point to /verify-email?token=...
    Redirect to the API endpoint which does DB validation.
    """
    if token:
        return RedirectResponse(url=f'/api/auth/verify-email?token={token}')
    return templates.TemplateResponse('verify_email.html', {'request': request})


@router.get('/authorize-device')
def authorize_device_page(request: Request, token: str = ''):
    """
    2FA links point to /authorize-device?token=...
    Redirect to the API endpoint which activates the device.
    """
    if token:
        return RedirectResponse(url=f'/api/auth/2fa-verify?token={token}')
    return templates.TemplateResponse('device_authorized.html', {'request': request})


@router.get('/two-factor')
def two_factor_page(request: Request):
    return templates.TemplateResponse('two_factor.html', {'request': request})


@router.get('/device-authorized')
def device_authorized_page(request: Request):
    return templates.TemplateResponse('device_authorized.html', {'request': request})
