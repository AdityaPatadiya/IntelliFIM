# your_project_name/asgi.py
import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolHttpRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'your_project_name.settings')
django.setup()

from django.urls import path
from fim.consumers import FIMEventConsumer  # we'll create this

application = ProtocolHttpRouter(
    http=get_asgi_application(),
    ws=AuthMiddlewareStack(
        URLRouter([
            path("ws/fim/stream/", FIMEventConsumer.as_asgi()),
        ])
    )
)
