import asyncio
import os

import aiofiles
from app.config import LOG_SOURCE, LOG_FILE_AUTH, LOG_FILE_ACCESS, GENERATOR_INTERVAL
from app.core.log_parser import parse_line
from app.core.log_generator import generate_logs

_log_paths: dict[str, str] = {
    "auth": LOG_FILE_AUTH,
    "access": LOG_FILE_ACCESS,
}


def update_log_path(source: str, path: str) -> None:
    _log_paths[source] = path


async def _read_until_path_change(f, source: str, path: str, queue: asyncio.Queue):
    """Read lines from an open file until the configured path for source changes."""
    while _log_paths[source] == path:
        line = await f.readline()
        if line:
            event = parse_line(line, source)
            if event:
                await queue.put(event)
        else:
            await asyncio.sleep(0.5)


async def _tail_file(source: str, queue: asyncio.Queue):
    """Tail a log file, reopening automatically when the path is updated."""
    while True:
        path = _log_paths[source]
        if not os.path.exists(path):
            await asyncio.sleep(1)
            continue
        async with aiofiles.open(path, "r") as f:
            await f.seek(0, 2)
            await _read_until_path_change(f, source, path, queue)


async def start_collector(queue: asyncio.Queue):
    """
    Jalankan collector sesuai LOG_SOURCE:
    - "file"      → baca auth.log dan access.log asli
    - "generator" → generate log simulasi
    - "both"      → keduanya berjalan bersamaan
    """
    tasks = []

    if LOG_SOURCE in ("file", "both"):
        tasks.append(asyncio.create_task(_tail_file("auth", queue)))
        tasks.append(asyncio.create_task(_tail_file("access", queue)))

    if LOG_SOURCE in ("generator", "both"):
        tasks.append(asyncio.create_task(generate_logs(queue, GENERATOR_INTERVAL)))

    if tasks:
        await asyncio.gather(*tasks)
