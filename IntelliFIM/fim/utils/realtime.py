"""Cross-process event bus for FIM real-time events.

The watchdog file-change handler runs in the Celery worker process, but the
SSE endpoint runs in the runserver/Daphne process. They need a shared message
channel that survives a process boundary; an in-memory `asyncio.Queue` does
not.

We use Redis pub/sub on a dedicated channel. Pub/sub doesn't persist messages
— subscribers only receive events sent while they're connected — which is the
right semantics for a live event stream (no replay of stale events on
reconnect).
"""
import json
import logging
import os

import redis
import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

# DB index doesn't actually affect pub/sub channel scoping (pub/sub is
# server-wide), but using /3 keeps the connection visually separate from the
# Celery broker (/0), result backend (/1), and Django cache (/2).
REDIS_EVENTS_URL = os.getenv('FIM_EVENTS_REDIS_URL', 'redis://localhost:6379/3')
EVENTS_CHANNEL = 'fim:events'


def publish_event(event: dict) -> None:
    """Sync publisher — safe to call from Celery worker / watchdog handlers.

    Errors are logged and swallowed: a transient Redis hiccup must not break
    the file-change pipeline.
    """
    try:
        client = redis.Redis.from_url(REDIS_EVENTS_URL)
        client.publish(EVENTS_CHANNEL, json.dumps(event, default=str))
    except Exception as exc:
        logger.warning("Failed to publish FIM event to Redis: %s", exc)
