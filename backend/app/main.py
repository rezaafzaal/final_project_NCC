import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes import router, set_rule_engine
from app.api.websocket import ws_endpoint, broadcast_loop
from app.core.log_collector import start_collector
from app.core.rule_engine import RuleEngine
from app.db.database import init_db, save_event


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()

    rule_engine = RuleEngine()
    set_rule_engine(rule_engine)

    queue: asyncio.Queue = asyncio.Queue()

    async def pipeline():
        # Jalankan collector dan broadcast bersamaan
        await asyncio.gather(
            start_collector(queue),
            _process_queue(queue, rule_engine),
        )

    asyncio.create_task(pipeline())
    yield


async def _process_queue(queue: asyncio.Queue, rule_engine: RuleEngine):
    from app.api.websocket import manager
    while True:
        event = await queue.get()
        event = rule_engine.evaluate(event)
        await save_event(event.to_dict())
        await manager.broadcast(event.to_dict())


app = FastAPI(title="SIEM Dashboard", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")

app.add_websocket_route("/ws", ws_endpoint)

# Serve frontend static files
app.mount("/", StaticFiles(directory="/app/frontend", html=True), name="frontend")
