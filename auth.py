import uuid
from datetime import datetime, timedelta, timezone
from typing import Tuple

import jwt
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException, Response
from redis.asyncio import Redis

# Настройки
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7
ALGORITHM = "EdDSA"


# Загрузка ключей (читаем при старте модуля)
def load_key(filename):
    with open(filename, "rb") as f:
        return f.read()


PRIVATE_KEY = serialization.load_pem_private_key(load_key("certs/jwt_private.pem"), password=None)
PUBLIC_KEY = serialization.load_pem_public_key(load_key("certs/jwt_public.pem"))


class AuthService:
    def __init__(self, redis: Redis):
        self.redis = redis

    def create_tokens(self, user_id: str) -> Tuple[str, str]:
        token_id = str(uuid.uuid4())  # JTI (JWT ID) для связки пары

        # 1. Access Token
        access_claims = {
            "sub": user_id,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            "iat": datetime.now(timezone.utc),
            "jti": token_id,
            "type": "access",
        }
        access_token = jwt.encode(access_claims, PRIVATE_KEY, algorithm=ALGORITHM)

        # 2. Refresh Token
        refresh_claims = {
            "sub": user_id,
            "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
            "iat": datetime.now(timezone.utc),
            "jti": token_id,
            "type": "refresh",
        }
        refresh_token = jwt.encode(refresh_claims, PRIVATE_KEY, algorithm=ALGORITHM)

        return access_token, refresh_token

    async def rotate_tokens(self, old_refresh_token: str) -> Tuple[str, str]:
        try:
            payload = jwt.decode(old_refresh_token, PUBLIC_KEY, algorithms=[ALGORITHM])
        except jwt.PyJWTError as err:
            raise HTTPException(status_code=401, detail="Invalid token") from err

        if payload["type"] != "refresh":
            raise HTTPException(status_code=401, detail="Not a refresh token")

        jti = payload["jti"]
        user_id = payload["sub"]

        # ПРОВЕРКА BLACKLIST в Redis
        # Если токен там есть - значит его украли и пытаются использовать повторно
        is_blacklisted = await self.redis.exists(f"bl:{jti}")
        if is_blacklisted:
            # Тут можно добавить алерт безопасности: "Взлом аккаунта {user_id}"
            raise HTTPException(status_code=401, detail="Token reuse detected")

        # Добавляем старый токен в Blacklist
        # Время жизни ключа = оставшееся время жизни токена
        exp_timestamp = payload["exp"]
        ttl = int(exp_timestamp - datetime.now(timezone.utc).timestamp())

        if ttl > 0:
            await self.redis.setex(f"bl:{jti}", ttl, "used")

        # Выдаем новую пару
        return self.create_tokens(user_id)

    @staticmethod
    def set_cookies(response: Response, access: str, refresh: str):
        # Access Token: виден везде
        response.set_cookie(
            key="access_token",
            value=access,
            httponly=True,  # JS не имеет доступа
            secure=True,  # Только HTTPS
            samesite="strict",  # Защита от CSRF
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

        # Refresh Token: виден ТОЛЬКО на эндпоинте обновления
        response.set_cookie(
            key="refresh_token",
            value=refresh,
            httponly=True,
            secure=True,
            samesite="strict",
            path="/auth/refresh",  # Усиление безопасности
            max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        )

    @staticmethod
    def clear_cookies(response: Response):
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token", path="/auth/refresh")

    def verify_access_token(self, token: str) -> str:
        try:
            payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
            if payload["type"] != "access":
                raise HTTPException(status_code=401, detail="Invalid token type")
            return payload["sub"]
        except jwt.ExpiredSignatureError as err:
            raise HTTPException(status_code=401, detail="Token expired") from err
        except jwt.PyJWTError as err:
            raise HTTPException(status_code=401, detail="Invalid token") from err
