from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel
from app.db.database import get_events, get_stats
from app.core.rule_engine import RuleEngine
from app.core.log_collector import update_log_path

router = APIRouter()
_rule_engine: RuleEngine | None = None


def set_rule_engine(engine: RuleEngine):
    global _rule_engine
    _rule_engine = engine


@router.get("/events")
async def list_events(
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    severity: Annotated[str | None, Query()] = None,
    source: Annotated[str | None, Query()] = None,
):
    events = await get_events(limit=limit, severity=severity, source=source)
    return {"events": events}


@router.get("/stats")
async def stats():
    return await get_stats()


@router.post("/rules/reload")
async def reload_rules():
    if _rule_engine:
        _rule_engine.reload_rules()
    return {"status": "rules reloaded"}


class LogPathRequest(BaseModel):
    source: str
    path: str


@router.post("/config/log-path")
async def set_log_path(req: LogPathRequest):
    if req.source not in ("auth", "access", "firewall", "syslog", "fim"):
        return {"status": "error", "message": "source harus 'auth', 'access', 'firewall', 'syslog', atau 'fim'"}
    update_log_path(req.source, req.path)
    return {"status": "ok", "message": f"Path {req.source} diupdate ke {req.path}"}
