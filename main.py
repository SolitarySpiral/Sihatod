import hashlib
from typing import List, Optional

import redis.asyncio as redis
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()
# Подключаемся к Redis (имя хоста 'redis' берем из docker-compose)
r = redis.from_url("redis://redis:6379", decode_responses=True)


# Модель для входящего запроса
class BatchRequest(BaseModel):
    hashes: List[str]


@app.post("/hash/batch")  # Используем POST для передачи списка
async def get_batch_data(request: BatchRequest):
    if not request.hashes:
        return {"values": {}, "status": 200}

    # Одним махом берем все значения из Redis
    list_values = await r.mget(request.hashes)

    # Собираем красивый словарь: { "hash": "value" }
    # Используем zip, чтобы элегантно соединить списки
    result = {
        h: v if v is not None else None for h, v in zip(request.hashes, list_values, strict=True)
    }

    # Проверяем, нашлось ли хоть что-то
    if all(v is None for v in result.values()):
        raise HTTPException(status_code=404, detail="None of the hashes found")

    return {"data": result, "status": 200}


def get_hash(client_key: str, attr: str) -> str:
    payload = f"{client_key}:{attr}"
    return hashlib.sha256(payload.encode()).hexdigest()


@app.get("/hash/{client_key}/{attr}")
async def get_data(client_key: str, attr: str, addr: Optional[str] = None):
    # Если пришел готовый хеш, используем его, иначе генерируем
    target_addr = addr if addr else get_hash(client_key, attr)

    val = await r.get(target_addr)
    if not val:
        raise HTTPException(status_code=404, detail="Not Found")
    return {"hash": target_addr, "value": val, "status": 200}


@app.put("/hash/{client_key}/{attr}")
async def put_data(value: str, client_key: str, attr: str, addr: Optional[str] = None):
    # Проверка значения (FastAPI сам может это делать через Body, но оставим так)
    if value is None:
        raise HTTPException(status_code=400, detail="No value to edit")

    target_addr = addr if addr else get_hash(client_key, attr)

    # Redis set возвращает True при успехе
    success = await r.set(target_addr, value)
    if not success:
        raise HTTPException(status_code=500, detail="Database error")

    return {"hash": target_addr, "status": 200}


@app.delete("/hash/{client_key}/{attr}")
async def delete_data(client_key: str, attr: str, addr: Optional[str] = None):
    target_addr = addr if addr else get_hash(client_key, attr)

    deleted_count = await r.delete(target_addr)
    if not deleted_count:
        raise HTTPException(status_code=404, detail="Not Found")

    return {"hash": target_addr, "deleted": True, "status": 200}


@app.post("/admin/reset")
async def reset_database():
    await r.flushdb()
    return {"message": "Database wiped clean", "status": 200}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5001)
