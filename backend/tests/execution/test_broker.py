"""Tests for execution.broker — Dramatiq Redis broker config."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import execution.broker as broker_mod
from execution.broker import QUEUE_NAMES, REDIS_URL, get_broker


class TestQueueNames:
    """QUEUE_NAMES contains all expected queues."""

    def test_has_control_queue(self) -> None:
        assert "control" in QUEUE_NAMES

    def test_has_package_queue(self) -> None:
        assert "package" in QUEUE_NAMES

    def test_has_fuzz_queue(self) -> None:
        assert "fuzz" in QUEUE_NAMES

    def test_has_replay_queue(self) -> None:
        assert "replay" in QUEUE_NAMES

    def test_queue_count(self) -> None:
        assert len(QUEUE_NAMES) == 4

    def test_queue_values_are_prefixed(self) -> None:
        for value in QUEUE_NAMES.values():
            assert value.startswith("qh_")


class TestRedisURL:
    """REDIS_URL defaults correctly."""

    def test_default_url(self) -> None:
        assert REDIS_URL == "redis://localhost:6380"


class TestGetBroker:
    """get_broker returns a usable broker without hitting Redis."""

    def setup_method(self) -> None:
        # Reset the singleton before each test
        broker_mod._broker = None

    @patch("execution.broker.RedisBroker")
    @patch("execution.broker.dramatiq")
    def test_returns_broker_with_enqueue(
        self, mock_dramatiq: MagicMock, mock_redis_broker_cls: MagicMock
    ) -> None:
        mock_broker = MagicMock()
        mock_redis_broker_cls.return_value = mock_broker

        result = get_broker()

        assert result is mock_broker
        assert hasattr(result, "enqueue")

    @patch("execution.broker.RedisBroker")
    @patch("execution.broker.dramatiq")
    def test_creates_broker_with_redis_url(
        self, mock_dramatiq: MagicMock, mock_redis_broker_cls: MagicMock
    ) -> None:
        get_broker()

        mock_redis_broker_cls.assert_called_once_with(url=REDIS_URL)

    @patch("execution.broker.RedisBroker")
    @patch("execution.broker.dramatiq")
    def test_declares_all_queues(
        self, mock_dramatiq: MagicMock, mock_redis_broker_cls: MagicMock
    ) -> None:
        mock_broker = MagicMock()
        mock_redis_broker_cls.return_value = mock_broker

        get_broker()

        declared = {call.args[0] for call in mock_broker.declare_queue.call_args_list}
        assert declared == set(QUEUE_NAMES.values())

    @patch("execution.broker.RedisBroker")
    @patch("execution.broker.dramatiq")
    def test_sets_global_broker(
        self, mock_dramatiq: MagicMock, mock_redis_broker_cls: MagicMock
    ) -> None:
        mock_broker = MagicMock()
        mock_redis_broker_cls.return_value = mock_broker

        get_broker()

        mock_dramatiq.set_broker.assert_called_once_with(mock_broker)

    @patch("execution.broker.RedisBroker")
    @patch("execution.broker.dramatiq")
    def test_singleton_returns_same_instance(
        self, mock_dramatiq: MagicMock, mock_redis_broker_cls: MagicMock
    ) -> None:
        mock_broker = MagicMock()
        mock_redis_broker_cls.return_value = mock_broker

        first = get_broker()
        second = get_broker()

        assert first is second
        # RedisBroker should only be constructed once
        mock_redis_broker_cls.assert_called_once()
