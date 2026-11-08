"""Asynchronous notification dispatcher with retries and per-channel rate limiting."""
from __future__ import annotations

import queue
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

from eldoctor.notify.channels import Channel, ChannelError, build_channel, build_message


class Dispatcher:
    def __init__(self, cfg: Dict[str, Any], exclude_types: Optional[List[str]] = None, synchronous: bool = False) -> None:
        nc = cfg.get("notifications", {})
        self.min_severity = nc.get("min_severity", "medium")
        self.include_actions = bool(nc.get("include_actions", True))
        self.rate = int(nc.get("rate_limit_per_minute", 30))
        self.channels: List[Channel] = []
        from eldoctor.housekeeping import LoggedErrors
        self.errors = LoggedErrors(50)          # also written to <data>/logs/eldoctor.log
        self.sent: Dict[str, int] = {}
        exclude = set(exclude_types or [])
        for c in nc.get("channels", []) or []:
            if c.get("enabled", True) and c.get("type") not in exclude:
                self.channels.append(build_channel(c))
        self._hist: Dict[str, Deque[float]] = {ch.name: deque() for ch in self.channels}
        self.synchronous = synchronous
        self.q: "queue.Queue[Optional[tuple]]" = queue.Queue()
        self._worker: Optional[threading.Thread] = None
        if not synchronous:
            self._worker = threading.Thread(target=self._run, daemon=True, name="notify")
            self._worker.start()

    def _allowed(self, ch: Channel) -> bool:
        now = time.time()
        h = self._hist[ch.name]
        while h and now - h[0] > 60:
            h.popleft()
        if len(h) >= self.rate:
            return False
        h.append(now)
        return True

    def notify(self, alert: Dict[str, Any], actions: Optional[List[Dict[str, Any]]] = None, kind: str = "alert",
               note: str = "", channels: Optional[List[str]] = None, force: bool = False) -> None:
        msg = build_message(alert, (actions or []) if self.include_actions else [], kind, note)
        for ch in self.channels:
            if channels and "all" not in channels and ch.name not in channels and ch.type not in channels:
                continue
            if not force and not ch.wants(msg["severity"], self.min_severity):
                continue
            if self.synchronous:
                self._deliver(ch, msg)
            else:
                self.q.put((ch, msg))

    def _deliver(self, ch: Channel, msg: Dict[str, Any]) -> bool:
        if not self._allowed(ch):
            self.errors.append(f"{ch.name}: rate limited")
            return False
        delay = 1.0
        for attempt in range(3):
            try:
                ch.send(msg)
                self.sent[ch.name] = self.sent.get(ch.name, 0) + 1
                return True
            except ChannelError as exc:
                err = str(exc)
            except Exception as exc:  # never let a notifier crash the agent
                err = f"{type(exc).__name__}: {exc}"
            if attempt < 2 and "not set" not in err:
                time.sleep(delay)
                delay *= 2
            else:
                break
        self.errors.append(f"{time.strftime('%H:%M:%S')} {ch.name}: {err}")
        return False

    def _run(self) -> None:
        while True:
            item = self.q.get()
            if item is None:
                break
            self._deliver(*item)
            self.q.task_done()

    def flush(self, timeout: float = 10) -> None:
        if self.synchronous:
            return
        end = time.time() + timeout
        while self.q.unfinished_tasks and time.time() < end:
            time.sleep(0.05)

    def close(self) -> None:
        self.flush()
        if self._worker and self._worker.is_alive():
            self.q.put(None)
            self._worker.join(timeout=2)
