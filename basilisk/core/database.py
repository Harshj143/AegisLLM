"""
Basilisk Database — SQLite persistence with WAL mode for concurrent access.

Stores scan sessions, findings, conversations, and evolution state.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import aiosqlite

SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    provider TEXT NOT NULL,
    mode TEXT NOT NULL,
    profile_json TEXT,
    config_json TEXT,
    status TEXT DEFAULT 'running',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    summary_json TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    attack_module TEXT NOT NULL,
    payload TEXT,
    response TEXT,
    conversation_json TEXT,
    evolution_generation INTEGER,
    confidence REAL DEFAULT 0.0,
    remediation TEXT,
    references_json TEXT,
    tags_json TEXT,
    timestamp TEXT NOT NULL,
    metadata_json TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS evolution_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    best_fitness REAL,
    avg_fitness REAL,
    population_size INTEGER,
    mutations_applied INTEGER,
    breakthroughs INTEGER DEFAULT 0,
    best_payload TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    attack_module TEXT NOT NULL,
    messages_json TEXT NOT NULL,
    result TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_evolution_session ON evolution_log(session_id);
CREATE INDEX IF NOT EXISTS idx_conversations_session ON conversations(session_id);
"""


class BasiliskDatabase:
    """
    Async SQLite database for persisting scan data.

    Uses WAL mode for concurrent read/write access during live scans.
    """

    def __init__(self, db_path: str = "./basilisk-sessions.db") -> None:
        self.db_path = Path(db_path)
        self._db: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        """Open database connection and initialize schema."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self.db_path))
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA foreign_keys=ON")
        await self._db.executescript(SCHEMA_SQL)
        await self._db.commit()

    async def close(self) -> None:
        """Close database connection."""
        if self._db:
            await self._db.close()
            self._db = None

    @property
    def db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._db

    # --- Sessions ---

    async def save_session(self, session_data: dict[str, Any]) -> None:
        await self.db.execute(
            """INSERT OR REPLACE INTO sessions
               (id, target_url, provider, mode, profile_json, config_json, status, started_at, finished_at, summary_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_data["id"],
                session_data["target_url"],
                session_data["provider"],
                session_data["mode"],
                json.dumps(session_data.get("profile")),
                json.dumps(session_data.get("config")),
                session_data.get("status", "running"),
                session_data["started_at"],
                session_data.get("finished_at"),
                json.dumps(session_data.get("summary")),
            ),
        )
        await self.db.commit()

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        async with self.db.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            cols = [d[0] for d in cursor.description]
            data = dict(zip(cols, row))
            for key in ("profile_json", "config_json", "summary_json"):
                if data.get(key):
                    data[key.replace("_json", "")] = json.loads(data[key])
            return data

    async def list_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        async with self.db.execute(
            "SELECT id, target_url, provider, mode, status, started_at FROM sessions ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in rows]

    async def update_session_status(self, session_id: str, status: str, finished_at: str | None = None, summary: dict[str, Any] | None = None) -> None:
        await self.db.execute(
            "UPDATE sessions SET status = ?, finished_at = ?, summary_json = ? WHERE id = ?",
            (status, finished_at, json.dumps(summary) if summary else None, session_id),
        )
        await self.db.commit()

    # --- Findings ---

    async def save_finding(self, session_id: str, finding_data: dict[str, Any]) -> None:
        await self.db.execute(
            """INSERT OR REPLACE INTO findings
               (id, session_id, title, severity, category, attack_module, payload, response,
                conversation_json, evolution_generation, confidence, remediation,
                references_json, tags_json, timestamp, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding_data["id"],
                session_id,
                finding_data["title"],
                finding_data["severity"],
                finding_data["category"],
                finding_data["attack_module"],
                finding_data.get("payload", ""),
                finding_data.get("response", ""),
                json.dumps(finding_data.get("conversation", [])),
                finding_data.get("evolution_generation"),
                finding_data.get("confidence", 0.0),
                finding_data.get("remediation", ""),
                json.dumps(finding_data.get("references", [])),
                json.dumps(finding_data.get("tags", [])),
                finding_data["timestamp"],
                json.dumps(finding_data.get("metadata", {})),
            ),
        )
        await self.db.commit()

    async def get_findings(self, session_id: str) -> list[dict[str, Any]]:
        async with self.db.execute(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY severity, timestamp",
            (session_id,),
        ) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            results = []
            for row in rows:
                data = dict(zip(cols, row))
                for key in ("conversation_json", "references_json", "tags_json", "metadata_json"):
                    if data.get(key):
                        data[key.replace("_json", "")] = json.loads(data[key])
                results.append(data)
            return results

    # --- Evolution Log ---

    async def save_evolution_entry(self, session_id: str, entry: dict[str, Any]) -> None:
        await self.db.execute(
            """INSERT INTO evolution_log
               (session_id, generation, best_fitness, avg_fitness, population_size,
                mutations_applied, breakthroughs, best_payload, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                entry["generation"],
                entry.get("best_fitness", 0.0),
                entry.get("avg_fitness", 0.0),
                entry.get("population_size", 0),
                entry.get("mutations_applied", 0),
                entry.get("breakthroughs", 0),
                entry.get("best_payload", ""),
                entry["timestamp"],
            ),
        )
        await self.db.commit()

    async def get_evolution_log(self, session_id: str) -> list[dict[str, Any]]:
        async with self.db.execute(
            "SELECT * FROM evolution_log WHERE session_id = ? ORDER BY generation",
            (session_id,),
        ) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in rows]

    # --- Conversations ---

    async def save_conversation(self, session_id: str, attack_module: str, messages: list[dict[str, Any]], result: str, timestamp: str) -> None:
        await self.db.execute(
            "INSERT INTO conversations (session_id, attack_module, messages_json, result, timestamp) VALUES (?, ?, ?, ?, ?)",
            (session_id, attack_module, json.dumps(messages), result, timestamp),
        )
        await self.db.commit()

    async def get_conversations(self, session_id: str, attack_module: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM conversations WHERE session_id = ?"
        params: list[Any] = [session_id]
        if attack_module:
            query += " AND attack_module = ?"
            params.append(attack_module)
        query += " ORDER BY timestamp"
        async with self.db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            results = []
            for row in rows:
                data = dict(zip(cols, row))
                if data.get("messages_json"):
                    data["messages"] = json.loads(data["messages_json"])
                results.append(data)
            return results
