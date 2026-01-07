from fastapi import Request
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware

from auth import AuthService


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Пытаемся понять, кто это (не ломая поток, если токена нет)
        user_id = "anonymous"
        token = request.cookies.get("access_token")
        if token:
            try:
                # В идеале тут нужен легкий декодер без проверок в БД,
                # но пока возьмем как есть или просто извлечем sub из JWT без верификации подписи для лога
                # (для скорости)
                user_id = AuthService(None).verify_access_token(token)
            except Exception:
                user_id = "invalid_token"

        response = await call_next(request)

        # Логируем событие. В будущем тут будет отправка в отдельный Redis Stream или файл.
        log_icon = "✅" if response.status_code < 400 else "❌"
        logger.info(
            f"{log_icon} AUDIT: User='{user_id}' | {request.method} {request.url.path} | Status={response.status_code}"
        )

        return response
