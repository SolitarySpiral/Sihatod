import hashlib
import logging
import os
from pathlib import Path
from typing import Annotated, AsyncGenerator, List, Optional
from urllib.parse import urlparse

import redis.asyncio as redis
import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, Field

# Вычисляем путь относительно этого файла (main.py)
BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = BASE_DIR / "certs"

load_dotenv()  # Эта команда ищет файл .env и загружает его в os.environ
# Настройка логирования для отслеживания инцидентов безопасности
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Sihatod Secure API", version="2.0.0")


# --- КОНФИГУРАЦИЯ ---
REDIS_URL = os.environ.get("REDIS_URL")
KEY_PREFIX = "sihatod:"

if not REDIS_URL:
    logger.critical("REDIS_URL is missing in environment variables")
    raise RuntimeError("Application misconfigured: REDIS_URL required")


# --- ЗАВИСИМОСТИ (DEPENDENCY INJECTION) ---


async def get_redis() -> AsyncGenerator[redis.Redis, None]:
    # 1. Парсим REDIS_URL из .env
    url = urlparse(REDIS_URL)

    client = redis.Redis(
        host=url.hostname,
        port=url.port or 6379,
        username=url.username,
        password=url.password,
        db=int(url.path.lstrip("/") or 0),
        decode_responses=True,
        ssl=True,
        ssl_ca_certs=str(CERTS_DIR / "ca.crt"),
        ssl_certfile=str(CERTS_DIR / "redis.crt"),
        ssl_keyfile=str(CERTS_DIR / "redis.key"),
        ssl_check_hostname=True,
        ssl_cert_reqs="required",
    )
    try:
        yield client
    finally:
        # Важно: в asyncio используем aclose()
        await client.aclose()


# Создаем алиас для зависимости, чтобы избежать B008 и дублирования кода
RedisDep = Annotated[redis.Redis, Depends(get_redis)]


# --- СЛУЖЕБНАЯ ЛОГИКА ---
def to_safe_key(user_key: str) -> str:
    """Гарантирует, что ключ соответствует ACL политикам (префикс sihatod:)."""
    if user_key.startswith(KEY_PREFIX):
        return user_key
    return f"{KEY_PREFIX}{user_key}"


def generate_internal_hash(client_key: str, attr: str) -> str:
    """Создает детерминированный SHA-256 хеш."""
    payload = f"{client_key}:{attr}"
    return hashlib.sha256(payload.encode()).hexdigest()


# --- МОДЕЛИ ДАННЫХ ---
class BatchRequest(BaseModel):
    hashes: List[str] = Field(..., min_items=1, description="Список хешей для поиска")


# --- ЭНДПОИНТЫ ---


@app.post("/hash/batch", status_code=status.HTTP_200_OK)
async def get_batch_data(request: BatchRequest, db: RedisDep):
    safe_keys = [to_safe_key(h) for h in request.hashes]

    try:
        list_values = await db.mget(safe_keys)
    except redis.ResponseError as err:  # Для ACL ошибок
        if "NOPERM" in str(err):
            logger.warning("ACL violation attempt")
            raise HTTPException(status_code=403, detail="Access denied") from err
        raise
    except redis.RedisError as err:
        logger.error(f"Batch read failed: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database service unavailable"
        ) from err

    result = {
        orig_h: val
        for orig_h, val in zip(request.hashes, list_values, strict=True)
        if val is not None
    }

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Requested hashes not found"
        ) from None

    return {"data": result}


@app.get("/hash/{client_key}/{attr}")
async def get_data(client_key: str, attr: str, db: RedisDep, addr: Optional[str] = None):
    raw_hash = addr or generate_internal_hash(client_key, attr)
    target_key = to_safe_key(raw_hash)

    try:
        val = await db.get(target_key)
    except redis.ResponseError as err:  # Для ACL ошибок
        if "NOPERM" in str(err):
            logger.warning("ACL violation attempt")
            raise HTTPException(status_code=403, detail="Access denied") from err
        raise
    except redis.RedisError as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Storage error"
        ) from err

    if val is None:
        raise HTTPException(status_code=404, detail="Key not found") from None

    return {"hash": raw_hash, "value": val}


@app.put("/hash/{client_key}/{attr}", status_code=status.HTTP_200_OK)
async def put_data(
    value: str,
    client_key: str,
    attr: str,
    db: RedisDep,
    addr: Optional[str] = None,
):
    raw_hash = addr or generate_internal_hash(client_key, attr)
    target_key = to_safe_key(raw_hash)

    try:
        # Интоксикация данных: проверяем успешность записи
        await db.set(target_key, value)
    except redis.ResponseError as err:  # Для ACL ошибок
        if "NOPERM" in str(err):
            logger.warning("ACL violation attempt")
            raise HTTPException(status_code=403, detail="Access denied") from err
        raise
    except redis.RedisError as err:
        logger.error(f"Write operation failed for {target_key}: {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to persist data"
        ) from err

    return {"hash": raw_hash, "status": "success"}


@app.delete("/hash/{client_key}/{attr}")
async def delete_data(
    client_key: str,
    attr: str,
    db: RedisDep,
    addr: Optional[str] = None,
):
    raw_hash = addr or generate_internal_hash(client_key, attr)
    target_key = to_safe_key(raw_hash)

    try:
        deleted = await db.delete(target_key)
    except redis.ResponseError as err:  # Для ACL ошибок
        if "NOPERM" in str(err):
            logger.warning("ACL violation attempt")
            raise HTTPException(status_code=403, detail="Access denied") from err
        raise
    except redis.RedisError as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Delete operation failed"
        ) from err

    if not deleted:
        raise HTTPException(status_code=404, detail="Target not found") from None

    return {"hash": raw_hash, "deleted": True}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5001, reload=False)
