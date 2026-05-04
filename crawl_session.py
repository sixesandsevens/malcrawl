from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Set


CancelCheck = Callable[[Optional[str]], bool]
StatusUpdate = Callable[..., None]


@dataclass
class CrawlState:
    visited: Set[str] = field(default_factory=set)
    pages_seen: int = 0
    scripts_seen: int = 0
    bytes_html: int = 0
    start_time: float = field(default_factory=time.time)


@dataclass
class CrawlSession:
    """Per-scan crawl state + callbacks.

    This is intentionally small: it exists to remove module-level globals
    and break the dependency on the Flask app for cancellation/status.
    """

    scan_id: Optional[str] = None
    state: CrawlState = field(default_factory=CrawlState)
    cancel_check: CancelCheck = lambda _scan_id: False
    status_update: StatusUpdate = lambda _scan_id, **_kw: None

    def reset(self) -> None:
        self.state = CrawlState()

    def cancelled(self) -> bool:
        try:
            return bool(self.cancel_check(self.scan_id))
        except Exception:
            return False

    def update(self, **kw) -> None:
        try:
            self.status_update(self.scan_id, **kw)
        except Exception:
            # Status updates should never break a crawl.
            return
