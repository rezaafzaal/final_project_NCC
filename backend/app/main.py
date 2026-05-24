import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from app.api.routes import router, set_rule_engine
from app.api.websocket import ws_endpoint, broadcast_loop
from app.core.log_collector import start_collector
from app.core.rule_engine import RuleEngine
from app.db.database import init_db, save_event
from app.metrics import events_total, rules_triggered_total
from app.services.discord_webhook import send_alert_dc


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()

    rule_engine = RuleEngine()
    set_rule_engine(rule_engine)

    queue: asyncio.Queue = asyncio.Queue()

    async def pipeline():
        await asyncio.gather(
            start_collector(queue),
            _process_queue(queue, rule_engine),
        )

    app.state.pipeline_task = asyncio.create_task(pipeline())

    def _log_pipeline_error(task: asyncio.Task):
        if not task.cancelled() and task.exception():
            print(f"[PIPELINE] Fatal error: {task.exception()}")

    app.state.pipeline_task.add_done_callback(_log_pipeline_error)
    try:
        yield
    finally:
        app.state.pipeline_task.cancel()


_alert_tasks: set = set()


async def _process_queue(queue: asyncio.Queue, rule_engine: RuleEngine):
    from app.api.websocket import manager
    while True:
        event = await queue.get()
        try:
            event = rule_engine.evaluate(event)
            await save_event(event.to_dict())
            await manager.broadcast(event.to_dict())

            events_total.labels(severity=event.severity, source=event.source).inc()

            if event.rule_triggered:
                rules_triggered_total.labels(rule=event.rule_triggered).inc()

            if event.severity == "CRITICAL":
                task = asyncio.create_task(asyncio.to_thread(send_alert_dc, event))
                _alert_tasks.add(task)
                task.add_done_callback(_alert_tasks.discard)
        except Exception as exc:
            print(f"[PIPELINE] Error processing event: {exc}")


app = FastAPI(title="SIEM Dashboard", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")

app.add_websocket_route("/ws", ws_endpoint)

@app.get("/metrics")
def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# Serve frontend static files
app.mount("/", StaticFiles(directory="/app/frontend", html=True), name="frontend")
