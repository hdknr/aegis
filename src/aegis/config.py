import os

COMPOSE_FILE = os.getenv("AEGIS_COMPOSE_FILE", "./docker-compose.yml")
COMPOSE_PROJECT = os.getenv("AEGIS_COMPOSE_PROJECT", "aegis")
OUTPUT_FORMAT = os.getenv("AEGIS_OUTPUT_FORMAT", "text")
TIMEOUT = int(os.getenv("AEGIS_TIMEOUT", "30"))
