import aiosqlite
import json
from datetime import datetime
from app.config import DB_URL

DB_PATH = DB_URL.replace("sqlite+aiosqlite:///", "")


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS log_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT,
                raw TEXT,
                ip TEXT,
                user TEXT,
                action TEXT,
                status TEXT,
                severity TEXT DEFAULT 'INFO',
                rule_triggered TEXT,
                extra TEXT DEFAULT '{}'
            )
        """)
        await db.commit()


async def save_event(event: dict):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO log_events
                (timestamp, source, raw, ip, user, action, status, severity, rule_triggered, extra)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("timestamp"),
            event.get("source"),
            event.get("raw"),
            event.get("ip"),
            event.get("user"),
            event.get("action"),
            event.get("status"),
            event.get("severity", "INFO"),
            event.get("rule_triggered"),
            json.dumps(event.get("extra", {})),
        ))
        await db.commit()


async def get_events(limit: int = 100, severity: str = None, source: str = None) -> list:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        query = "SELECT * FROM log_events WHERE 1=1"
        params = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if source:
            query += " AND source = ?"
            params.append(source)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        cursor = await db.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_stats() -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        stats = {}
        for severity in ("INFO", "WARNING", "CRITICAL"):
            cursor = await db.execute(
                "SELECT COUNT(*) FROM log_events WHERE severity = ?", (severity,)
            )
            row = await cursor.fetchone()
            stats[severity.lower()] = row[0]
        cursor = await db.execute("SELECT COUNT(*) FROM log_events")
        row = await cursor.fetchone()
        stats["total"] = row[0]
        return stats
