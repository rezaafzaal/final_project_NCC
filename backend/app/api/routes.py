from typing import Annotated

from fastapi import APIRouter, Query
from app.db.database import get_events, get_stats
from app.core.rule_engine import RuleEngine

router = APIRouter()
_rule_engine: RuleEngine | None = None


def set_rule_engine(engine: RuleEngine):
    global _rule_engine
    _rule_engine = engine


@router.get("/events")
async def list_events(  # pragma: no cover
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    severity: Annotated[str | None, Query()] = None,
    source: Annotated[str | None, Query()] = None,
):
    events = await get_events(limit=limit, severity=severity, source=source)
    return {"events": events}


@router.get("/stats")
async def stats():  # pragma: no cover
    return await get_stats()


@router.post("/rules/reload")
async def reload_rules():  # pragma: no cover
    if _rule_engine:
        _rule_engine.reload_rules()
    return {"status": "rules reloaded"}
