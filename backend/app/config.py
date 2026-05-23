import os

# "file" = baca log asli, "generator" = simulasi, "both" = keduanya
LOG_SOURCE = os.getenv("LOG_SOURCE", "both")

LOG_FILE_AUTH = os.getenv("LOG_FILE_AUTH", "/app/logs/auth.log")
LOG_FILE_ACCESS = os.getenv("LOG_FILE_ACCESS", "/app/logs/access.log")
LOG_FILE_FIREWALL = os.getenv("LOG_FILE_FIREWALL", "/app/logs/firewall.log")
LOG_FILE_SYSLOG = os.getenv("LOG_FILE_SYSLOG", "/app/logs/syslog.log")
LOG_FILE_FIM = os.getenv("LOG_FILE_FIM", "/app/logs/fim.log")

GENERATOR_INTERVAL = float(os.getenv("GENERATOR_INTERVAL", "2.0"))  # detik antar log

# MySQL config — isi sesuai credential Azure
DB_HOST     = os.getenv("DB_HOST",     "localhost")
DB_PORT     = int(os.getenv("DB_PORT", "3306"))
DB_USER     = os.getenv("DB_USER",     "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME     = os.getenv("DB_NAME",     "siem")
DB_SSL      = os.getenv("DB_SSL",      "false").lower() == "true"
DB_SSL_CA   = os.getenv("DB_SSL_CA",   "")

RULES_PATH = os.getenv("RULES_PATH", "/app/rules/default_rules.json")
