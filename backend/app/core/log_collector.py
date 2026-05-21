import asyncio
import os

import aiofiles
from app.config import LOG_SOURCE, LOG_FILE_AUTH, LOG_FILE_ACCESS, GENERATOR_INTERVAL
from app.core.log_parser import parse_line
from app.core.log_generator import generate_logs


async def _tail_file(path: str, source: str, queue: asyncio.Queue):
    """Baca log file dari akhir, terus pantau baris baru (seperti tail -f)."""
    if not os.path.exists(path):
        return
    async with aiofiles.open(path, "r") as f:
        await f.seek(0, 2)  # langsung ke akhir file
        while True:
            line = await f.readline()
            if line:
                event = parse_line(line, source)
                if event:
                    await queue.put(event)
            else:
                await asyncio.sleep(0.5)


async def start_collector(queue: asyncio.Queue):
    """
    Jalankan collector sesuai LOG_SOURCE:
    - "file"      → baca auth.log dan access.log asli
    - "generator" → generate log simulasi
    - "both"      → keduanya berjalan bersamaan
    """
    tasks = []

    if LOG_SOURCE in ("file", "both"):
        tasks.append(asyncio.create_task(_tail_file(LOG_FILE_AUTH, "auth", queue)))
        tasks.append(asyncio.create_task(_tail_file(LOG_FILE_ACCESS, "access", queue)))

    if LOG_SOURCE in ("generator", "both"):
        tasks.append(asyncio.create_task(generate_logs(queue, GENERATOR_INTERVAL)))

    if tasks:
        await asyncio.gather(*tasks)
