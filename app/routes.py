"""Page routes — serve Jinja2 HTML templates."""
import os

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()

_templates_dir = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates'
)
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
