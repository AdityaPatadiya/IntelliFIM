# fim/consumers.py
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from fim.core.fim_shared import event_queue
import json
import asyncio
from datetime import datetime

class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)

class FIMEventConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        user = self.scope.get("user")
        if not user or user.is_anonymous or not (user.is_staff or user.is_superuser):
            await self.close(code=4001)
            return

        await self.accept()
        self.task = asyncio.create_task(self.stream_events())

    async def disconnect(self, code):
        if hasattr(self, "task"):
            self.task.cancel()

    async def stream_events(self):
        try:
            while True:
                if not event_queue.empty():
                    event = await asyncio.to_thread(event_queue.get)
                    event_json = json.dumps(event, cls=DateTimeEncoder)
                    await self.send(text_data=f"data: {event_json}\n\n")
                else:
                    await asyncio.sleep(0.5)  # Prevent CPU spin
        except asyncio.CancelledError:
            pass
        except Exception as e:
            await self.send(text_data=f"data: {{\"error\": \"Stream error: {str(e)}\"}}\n\n")
