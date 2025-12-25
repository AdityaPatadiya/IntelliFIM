# your_project_name/asgi.py
import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.urls import path
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'IntelliFIM.settings')
django.setup()

from fim.consumers import FIMEventConsumer

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter([
            path("ws/fim/stream/", FIMEventConsumer.as_asgi()),
        ])
    )
})
