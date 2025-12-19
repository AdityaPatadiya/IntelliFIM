# src/FIM/fim_shared.py
"""
Shared components for FIM to avoid circular imports.
Contains event queue and event loop reference.
"""
import asyncio
from typing import Optional

# Create event queue for SSE
event_queue = asyncio.Queue()

# Will be set when FastAPI starts
_fim_loop: Optional[asyncio.AbstractEventLoop] = None

def set_fim_loop(loop: asyncio.AbstractEventLoop):
    """Set the FIM event loop (call this on startup)."""
    global _fim_loop
    _fim_loop = loop

def get_fim_loop() -> asyncio.AbstractEventLoop:
    """Get the FIM event loop safely."""
    if _fim_loop is not None:
        return _fim_loop
    
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.get_event_loop()
