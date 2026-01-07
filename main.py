import hashlib
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, AsyncGenerator, List, Optional

import redis.asyncio as redis
import uvicorn
from aiocircuitbreaker import CircuitBreaker
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from loguru import logger
from pydantic import BaseModel, ConfigDict, Field

from audit_middleware import AuditMiddleware
from auth import AuthService
from config import settings
from mlock import lock_memory

# Вычисляем путь относительно этого файла (main.py)
BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = settings.certs_path  # Path("/run/secrets/")  # BASE_DIR / "certs"

# Настраиваем: если 5 ошибок подряд — размыкаем цепь на 30 секунд
cb = CircuitBreaker(failure_threshold=5, recovery_timeout=30)

load_dotenv()  # Эта команда ищет файл .env и загружает его в os.environ
lock_memory()  # Эта команда запрещает системе сбрасывать память на диск

# Настройка красивого вывода (можно вынести в отдельную функцию setup_logging)
logger.remove()
logger.add(
    sys.stderr,
    format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
    level="INFO" if not settings.debug else "DEBUG",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Создаем отдельное долгоживущее соединение для лимитера
    # Используем твои настройки из get_redis
    # url = urlparse(settings.redis_url)
    limiter_redis = redis.Redis(
        host=settings.redis_url.host,
        port=settings.redis_url.port or 6379,
        username=settings.redis_url.username,
        password=settings.redis_url.password,
        db=int(settings.redis_url.path.lstrip("/")) or 0,  # int(url.path.lstrip("/") or 0),
        decode_responses=True,
        ssl=True,
        ssl_ca_certs=str(CERTS_DIR / "ca.crt"),
        ssl_certfile=str(CERTS_DIR / "redis.crt"),
        ssl_keyfile=str(CERTS_DIR / "redis.key"),
        ssl_check_hostname=True,
        ssl_cert_reqs="required",
    )

    # 2. Инициализируем лимитер этим соединением
    await FastAPILimiter.init(limiter_redis, prefix="sihatod-limiter")

    logger.info("🛡️ FastAPILimiter initialized with dedicated mTLS connection")

    yield  # Здесь приложение принимает запросы

    # 3. Закрываем соединение лимитера только при остановке приложения
    await limiter_redis.aclose()
    logger.info("🛑 FastAPILimiter connection closed")


# --- КОНФИГУРАЦИЯ ---
# REDIS_URL = os.environ.get("REDIS_URL")
# KEY_PREFIX = "sihatod:"
# # Отключаем документацию на проде через переменную окружения
# DEBUG = os.getenv("DEBUG", "false").lower() == "true"

if not settings.redis_url:
    logger.critical("REDIS_URL is missing in environment variables")
    raise RuntimeError("Application misconfigured: REDIS_URL required")
app = FastAPI(
    title="Sihatod Secure API",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
)
# 1. Защита от подмены Host
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "sihatod.com"])

# 2. Строгий CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://sihatod.com"],  # Никаких "*"
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

app.add_middleware(AuditMiddleware)


# 3. Security Headers
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    # 1. Защита от MIME-sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # 2.Запрещаем вставку в iframe Защита от кликджекинга
    response.headers["X-Frame-Options"] = "DENY"
    # 3. Усиленный HSTS (2 года + preload)
    # Это заставляет браузер всегда использовать HTTPS
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    # 4. Content Security Policy (НОВИНКА)
    # default-src 'self' — разрешает контент только с твоего домена.
    # frame-ancestors 'none' — запрещает встраивать твой API в любые фреймы.
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    # 5. Реферер (Конфиденциальность)
    # Не передает адрес твоего API при переходе по внешним ссылкам
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# --- ЗАВИСИМОСТИ (DEPENDENCY INJECTION) ---


async def get_redis() -> AsyncGenerator[redis.Redis, None]:
    # 1. Парсим REDIS_URL из .env
    # url = urlparse(settings.redis_url)

    client = redis.Redis(
        host=settings.redis_url.host,
        port=settings.redis_url.port or 6379,
        username=settings.redis_url.username,
        password=settings.redis_url.password,
        db=int(settings.redis_url.path.lstrip("/") or 0),
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

# --- АУТЕНТИФИКАЦИЯ (DEPENDENCIES & ROUTES) ---


# Зависимость для защиты роутов
async def get_current_user(request: Request) -> str:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # AuthService не требует состояния Redis для валидации Access токена (stateless)
    # Но если нужно проверить бан пользователя, можно прокинуть Redis
    auth = AuthService(None)
    return auth.verify_access_token(token)


UserDep = Annotated[str, Depends(get_current_user)]


# Модель для логина (простая)
class LoginRequest(BaseModel):
    username: str
    password: str


# --- ЭНДПОИНТЫ АВТОРИЗАЦИИ ---


@app.post("/auth/login")
async def login(creds: LoginRequest, response: Response, db: RedisDep):
    # В РЕАЛЬНОСТИ: Сверить хеш пароля из БД
    # Для примера хардкодим тестового юзера
    if creds.username != "admin" or creds.password != "secret":
        raise HTTPException(status_code=401, detail="Bad credentials")

    auth = AuthService(db)
    access, refresh = auth.create_tokens(user_id="user_1")  # ID пользователя из БД

    auth.set_cookies(response, access, refresh)
    return {"status": "logged_in"}


@app.post("/auth/refresh")
async def refresh_tokens(request: Request, response: Response, db: RedisDep):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    auth = AuthService(db)
    # Магия ротации: старый токен умирает, рождается новый
    new_access, new_refresh = await auth.rotate_tokens(refresh_token)

    auth.set_cookies(response, new_access, new_refresh)
    return {"status": "refreshed"}


@app.post("/auth/logout")
async def logout(response: Response):
    AuthService.clear_cookies(response)
    return {"status": "logged_out"}


@app.get("/auth/me")
async def me(user_id: UserDep):
    return {"user_id": user_id, "status": "authenticated"}


# --- ЭНДПОИНТ ЗДОРОВЬЯ ---


@app.get("/health", tags=["system"])
async def health_check(db: RedisDep):
    """
    Проверка здоровья:
    1. Приложение дышит?
    2. Redis доступен?
    3. Предохранитель не выбит?
    """
    health_report = {
        "status": "ok",
        "components": {"app": "healthy", "redis": "unknown", "circuit_breaker": "closed"},
    }

    # Проверяем состояние предохранителя через его внутренние атрибуты
    # В aiocircuitbreaker это делается через state
    if cb.state == "open":
        health_report["status"] = "degraded"
        health_report["components"]["circuit_breaker"] = "open"
        return JSONResponse(status_code=503, content=health_report)

    try:
        # Оборачиваем вызов в предохранитель
        with cb:
            await db.ping()

        health_report["components"]["redis"] = "connected"
        return health_report

    except Exception as err:
        logger.exception(err)
        health_report["status"] = "error"
        health_report["components"]["redis"] = str(err)
        # Возвращаем 503, чтобы Docker/K8s знали, что узел не готов
        return JSONResponse(status_code=503, content=health_report)


# --- СЛУЖЕБНАЯ ЛОГИКА ---
def to_safe_key(user_key: str) -> str:
    """Гарантирует, что ключ соответствует ACL политикам (префикс sihatod:)."""
    if user_key.startswith(settings.key_prefix):
        return user_key
    return f"{settings.key_prefix}{user_key}"


def generate_internal_hash(client_key: str, attr: str) -> str:
    """Создает детерминированный SHA-256 хеш."""
    payload = f"{client_key}:{attr}"
    return hashlib.sha256(payload.encode()).hexdigest()


# --- МОДЕЛИ ДАННЫХ ---
class BatchRequest(BaseModel):
    # Применяем строгий режим ко всей модели
    model_config = ConfigDict(strict=True)
    hashes: List[str] = Field(
        ..., min_items=1, max_length=1024 * 1024, description="Список хешей для поиска"
    )


class AttributeUpdate(BaseModel):
    value: str


# --- ЭНДПОИНТЫ ---


@app.post(
    "/hash/batch",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter(times=5, seconds=10))],
)
async def get_batch_data(
    request: BatchRequest,
    db: RedisDep,
    current_user: UserDep,
):
    safe_keys = [to_safe_key(h) for h in request.hashes]
    with cb:
        encrypted_data = await db.mget(safe_keys)
    if not encrypted_data:
        raise HTTPException(status_code=404, detail="Not found")
    try:
        # 2. Расшифровываем данные ПРИ получении из Redis
        from crypto import protector

        decrypted_values = [
            protector.decrypt(encrypted_value) for encrypted_value in encrypted_data
        ]
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
        for orig_h, val in zip(request.hashes, decrypted_values, strict=True)
        if val is not None
    }

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Requested hashes not found"
        ) from None

    return {"data": result}


@app.get(
    "/hash/{client_key}/{attr}",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter(times=5, seconds=10))],
)
async def get_data(
    client_key: str, attr: str, db: RedisDep, current_user: UserDep, addr: Optional[str] = None
):
    raw_hash = addr or generate_internal_hash(client_key, attr)
    target_key = to_safe_key(raw_hash)
    with cb:
        encrypted_data = await db.get(target_key)
    if not encrypted_data:
        raise HTTPException(status_code=404, detail="Not found")
        # 2. Расшифровываем данные ПРИ получении из Redis
    from crypto import protector

    try:
        decrypted_value = protector.decrypt(encrypted_data)
    except redis.ResponseError as err:  # Для ACL ошибок
        if "NOPERM" in str(err):
            logger.warning("ACL violation attempt")
            raise HTTPException(status_code=403, detail="Access denied") from err
        raise
    except redis.RedisError as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Storage error"
        ) from err

    return {"value": decrypted_value, "hash": raw_hash}


@app.put(
    "/hash/{client_key}/{attr}",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter(times=5, seconds=10))],
)
async def put_data(
    data: AttributeUpdate,
    client_key: str,
    attr: str,
    db: RedisDep,
    current_user: UserDep,
    addr: Optional[str] = None,
):
    # 1. Шифруем данные ПЕРЕД отправкой в Redis
    from crypto import protector

    encrypted_value = protector.encrypt(data.value)
    raw_hash = addr or generate_internal_hash(client_key, attr)
    target_key = to_safe_key(raw_hash)

    try:
        with cb:
            # Интоксикация данных: проверяем успешность записи
            await db.set(target_key, encrypted_value)
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


@app.delete(
    "/hash/{client_key}/{attr}",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RateLimiter(times=5, seconds=10))],
)
async def delete_data(
    client_key: str,
    attr: str,
    db: RedisDep,
    current_user: UserDep,
    addr: Optional[str] = None,
):
    raw_hash = addr or generate_internal_hash(client_key, attr)
    target_key = to_safe_key(raw_hash)

    try:
        with cb:
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
    # Читаем из окружения, по умолчанию ставим безопасный localhost
    # listen_host = os.getenv("APP_HOST", "127.0.0.1")
    uvicorn.run("main:app", host=settings.app_host, port=settings.app_port, reload=False)
