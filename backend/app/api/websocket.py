import asyncio
import json
from fastapi import WebSocket, WebSocketDisconnect
from app.metrics import active_websocket_connections


class ConnectionManager:
    def __init__(self):
        self._clients: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._clients.append(ws)
        active_websocket_connections.inc()

    def disconnect(self, ws: WebSocket):
        self._clients.remove(ws)
        active_websocket_connections.dec()

    async def broadcast(self, data: dict):
        message = json.dumps(data)
        dead = []
        for client in self._clients:
            try:
                await client.send_text(message)
            except Exception:
                dead.append(client)
        for c in dead:
            self._clients.remove(c)


manager = ConnectionManager()


async def ws_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Tetap buka koneksi, tunggu disconnect dari client
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


async def broadcast_loop(queue: asyncio.Queue):
    """Ambil event dari queue, broadcast ke semua WebSocket client."""
    while True:
        event = await queue.get()
        await manager.broadcast(event.to_dict())
