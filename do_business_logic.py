import asyncio
import logging
from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel

# Настраиваем логи, чтобы видеть, что происходит
logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger("SihatodClient")


# Модель для батч-запросов (дублируем из main.py для удобства)
class BatchRequest(BaseModel):
    hashes: List[str]


class SihatodSecureClient:
    def __init__(self, base_url: str = "https://localhost:5001"):
        # ВАЖНО: Мы используем https и указываем путь к CA сертификату
        # verify="certs/ca.crt" заставляет клиента доверять нашему самописному сертификату
        self.base_url = base_url
        self.client = httpx.AsyncClient(
            base_url=base_url,
            verify="certs/ca.crt",  # Проверяем SSL как взрослые
            timeout=10.0,
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    async def login(self, username: str, password: str) -> bool:
        """Аутентификация и получение HttpOnly Cookies"""
        try:
            response = await self.client.post(
                "/auth/login", json={"username": username, "password": password}
            )
            response.raise_for_status()
            logger.info("✅ Login successful. Cookies secured.")
            return True
        except httpx.HTTPStatusError as e:
            logger.error(f"❌ Login failed: {e.response.text}")
            return False
        except Exception as e:
            logger.error(f"❌ Connection error: {str(e)}")
            return False

    async def request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Универсальная обертка для запросов с автоматической отправкой кук"""
        try:
            response = await self.client.request(method, endpoint, params=params, json=json_data)

            # Если токен протух (401), здесь можно дописать логику вызова /auth/refresh
            if response.status_code == 401:
                logger.warning("⚠️ Token expired or invalid.")

            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(f"Request failed [{method} {endpoint}]: {e.response.text}")
            return {"error": str(e), "details": e.response.text}

    # --- Бизнес-методы (обертки над API) ---

    async def put_attr(self, client_key: str, attr: str, value: str):
        return await self.request("PUT", f"/hash/{client_key}/{attr}", params={"value": value})

    async def get_attr(self, client_key: str, attr: str):
        return await self.request("GET", f"/hash/{client_key}/{attr}")

    async def get_batch(self, hashes: List[str]):
        payload = BatchRequest(hashes=hashes).model_dump()
        return await self.request("POST", "/hash/batch", json_data=payload)


async def main():
    logger.info("🚀 Запуск защищенного клиента Sihatod...")

    # Используем контекстный менеджер (он сам закроет соединение в конце)
    async with SihatodSecureClient() as app:
        # 1. Сначала нужно войти в систему
        if not await app.login("admin", "secret"):
            logger.critical("Не удалось войти. Завершение работы.")
            return

        # Данные для теста
        user_id = "user_1"
        dict_attrs = {"account_type": "checking", "currency": "RUB", "balance": "100500"}
        collected_hashes = []

        # 2. Создаем атрибуты (PUT)
        logger.info("--- 📝 Запись данных ---")
        for key, value in dict_attrs.items():
            res = await app.put_attr(user_id, key, value)
            # Если вернулась ошибка авторизации - прерываем
            if "error" in res:
                break
            print(f"Created {key}: {res}")

        # 3. Читаем атрибуты (GET)
        logger.info("--- 🔍 Чтение данных ---")
        for key in dict_attrs.keys():
            data = await app.get_attr(user_id, key)
            if "hash" in data:
                print(f"Read {key}: {data['value']} (Hash: {data['hash']})")
                collected_hashes.append(data["hash"])

        # 4. Пакетный запрос (BATCH)
        if collected_hashes:
            logger.info("--- 📦 Пакетный запрос ---")
            batch_res = await app.get_batch(collected_hashes)
            print(f"Batch Result: {batch_res}")


if __name__ == "__main__":
    asyncio.run(main())
