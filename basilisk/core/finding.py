"""
Basilisk Finding — represents a discovered vulnerability in an AI system.

Each finding has a unique ID (BSLK-YYYY-XXXX), severity classification,
full attack conversation replay, and remediation guidance mapped to
OWASP LLM Top 10.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Vulnerability severity classification aligned with CVSS."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "red",
            Severity.HIGH: "orange1",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }[self]

    @property
    def icon(self) -> str:
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }[self]

    @property
    def numeric(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]


class AttackCategory(str, Enum):
    """Attack classification mapped to OWASP LLM Top 10."""
    PROMPT_INJECTION = "prompt_injection"          # LLM01
    INSECURE_OUTPUT = "insecure_output"            # LLM02
    DATA_POISONING = "data_poisoning"              # LLM03
    DENIAL_OF_SERVICE = "denial_of_service"        # LLM04
    SUPPLY_CHAIN = "supply_chain"                  # LLM05
    SENSITIVE_DISCLOSURE = "sensitive_disclosure"   # LLM06
    INSECURE_PLUGIN = "insecure_plugin"            # LLM07
    EXCESSIVE_AGENCY = "excessive_agency"           # LLM08
    OVERRELIANCE = "overreliance"                   # LLM09
    MODEL_THEFT = "model_theft"                     # LLM10

    @property
    def owasp_id(self) -> str:
        mapping = {
            AttackCategory.PROMPT_INJECTION: "LLM01",
            AttackCategory.INSECURE_OUTPUT: "LLM02",
            AttackCategory.DATA_POISONING: "LLM03",
            AttackCategory.DENIAL_OF_SERVICE: "LLM04",
            AttackCategory.SUPPLY_CHAIN: "LLM05",
            AttackCategory.SENSITIVE_DISCLOSURE: "LLM06",
            AttackCategory.INSECURE_PLUGIN: "LLM07",
            AttackCategory.EXCESSIVE_AGENCY: "LLM08",
            AttackCategory.OVERRELIANCE: "LLM09",
            AttackCategory.MODEL_THEFT: "LLM10",
        }
        return mapping[self]


@dataclass
class Message:
    """Single message in a conversation."""
    role: str           # "user", "assistant", "system", "tool"
    content: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Message:
        return cls(
            role=data["role"],
            content=data["content"],
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.now(timezone.utc).isoformat())),
            metadata=data.get("metadata", {}),
        )


@dataclass
class Finding:
    """
    Represents a confirmed vulnerability discovered during a Basilisk scan.

    Each finding carries the complete evidence chain: the payload that triggered
    the vulnerability, the model's response, and the full conversation history
    for replay and verification.
    """
    id: str = field(default_factory=lambda: f"BSLK-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}")
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    category: AttackCategory = AttackCategory.PROMPT_INJECTION
    attack_module: str = ""
    payload: str = ""
    response: str = ""
    conversation: list[Message] = field(default_factory=list)
    evolution_generation: int | None = None
    confidence: float = 0.0
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "owasp_id": self.category.owasp_id,
            "attack_module": self.attack_module,
            "payload": self.payload,
            "response": self.response,
            "conversation": [m.to_dict() for m in self.conversation],
            "evolution_generation": self.evolution_generation,
            "confidence": self.confidence,
            "remediation": self.remediation,
            "references": self.references,
            "tags": self.tags,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            id=data["id"],
            title=data["title"],
            description=data.get("description", ""),
            severity=Severity(data["severity"]),
            category=AttackCategory(data["category"]),
            attack_module=data["attack_module"],
            payload=data["payload"],
            response=data["response"],
            conversation=[Message.from_dict(m) for m in data.get("conversation", [])],
            evolution_generation=data.get("evolution_generation"),
            confidence=data.get("confidence", 0.0),
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            tags=data.get("tags", []),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.now(timezone.utc).isoformat())),
            metadata=data.get("metadata", {}),
        )

    @property
    def severity_icon(self) -> str:
        return self.severity.icon

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.id}: {self.title}"
