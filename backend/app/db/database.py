import aiomysql
import json
from app.config import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, DB_SSL

_pool: aiomysql.Pool | None = None


async def _get_pool() -> aiomysql.Pool:
    global _pool
    if _pool is None:
        _pool = await aiomysql.create_pool(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            db=DB_NAME,
            autocommit=True,
            ssl=DB_SSL or None,
            minsize=1,
            maxsize=5,
        )
    return _pool


async def init_db():
    pool = await _get_pool()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("""
                CREATE TABLE IF NOT EXISTS log_events (
                    id            INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp     VARCHAR(32)  NOT NULL,
                    source        VARCHAR(16),
                    raw           TEXT,
                    ip            VARCHAR(45),
                    user          VARCHAR(64),
                    action        VARCHAR(64),
                    status        VARCHAR(16),
                    severity      VARCHAR(16)  DEFAULT 'INFO',
                    rule_triggered VARCHAR(64),
                    extra         TEXT         DEFAULT '{}'
                )
            """)


async def save_event(event: dict):
    pool = await _get_pool()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("""
                INSERT INTO log_events
                    (timestamp, source, raw, ip, user, action, status, severity, rule_triggered, extra)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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


async def get_events(limit: int = 100, severity: str = None, source: str = None) -> list:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            query = "SELECT * FROM log_events WHERE 1=1"
            params = []
            if severity:
                query += " AND severity = %s"
                params.append(severity)
            if source:
                query += " AND source = %s"
                params.append(source)
            query += " ORDER BY timestamp DESC LIMIT %s"
            params.append(limit)
            await cur.execute(query, params)
            return await cur.fetchall()


async def get_stats() -> dict:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            stats = {}
            for severity in ("INFO", "WARNING", "CRITICAL"):
                await cur.execute(
                    "SELECT COUNT(*) FROM log_events WHERE severity = %s", (severity,)
                )
                row = await cur.fetchone()
                stats[severity.lower()] = row[0]
            await cur.execute("SELECT COUNT(*) FROM log_events")
            row = await cur.fetchone()
            stats["total"] = row[0]
            return stats
