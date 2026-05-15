import os

# "file" = baca log asli, "generator" = simulasi, "both" = keduanya
LOG_SOURCE = os.getenv("LOG_SOURCE", "both")

LOG_FILE_AUTH = os.getenv("LOG_FILE_AUTH", "/app/logs/auth.log")
LOG_FILE_ACCESS = os.getenv("LOG_FILE_ACCESS", "/app/logs/access.log")

GENERATOR_INTERVAL = float(os.getenv("GENERATOR_INTERVAL", "2.0"))  # detik antar log

DB_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./siem.db")

RULES_PATH = os.getenv("RULES_PATH", "/app/rules/default_rules.json")
