from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class InlineEvent:
    event: str
    tag: str
    code: Optional[str] = None


@dataclass(frozen=True)
class ScriptArtifact:
    original: str | None
    deobfuscated: str | None
    intent: str | None = None
    changed: bool = False
    target_hit: bool = False


@dataclass(frozen=True)
class SignatureMatch:
    script_index: int | None
    tool: str | None
    rule: str | None
    snippet: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class CrawlResult:
    id: int
    url: str
    timestamp: str
    links: int
    images: int
    videos: int
    issues: list[str]
    inline_events: list[InlineEvent]
    deobfuscated_scripts: list[ScriptArtifact]
    signatures: list[SignatureMatch]
    screenshot: str | None
    status: str
    sandbox_behavior: list[dict[str, Any]] | None = None

