"""Shared fixtures for simulator tests."""
from __future__ import annotations

from dataclasses import dataclass

import pytest


@dataclass
class FakeMessage:
    """Stand-in for aiokafka.ConsumerRecord — only needs .value bytes."""
    value: bytes


@pytest.fixture
def fake_message_cls():
    return FakeMessage
