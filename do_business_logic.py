import asyncio

import httpx

from main import BatchRequest


async def do_api(
    method: str, client_key: str, attr: str, value: str = None, request: BatchRequest = None
):
    url = f"http://localhost:5001/hash/{client_key}/{attr}"
    params = {"value": value} if value else {}

    if request:
        url = "http://localhost:5001/hash/batch"
        params = request.hashes
        async with httpx.AsyncClient() as client:
            try:
                if method.upper() == "POST":
                    response = await client.post(url, json=request.model_dump())

                return response.json()
            except Exception as e:
                return {"error": str(e)}

    else:
        async with httpx.AsyncClient() as client:
            try:
                if method.upper() == "PUT":
                    response = await client.put(url, params=params)
                elif method.upper() == "DELETE":
                    response = await client.delete(url)
                else:
                    response = await client.get(url)

                return response.json()
            except Exception as e:
                return {"error": str(e)}


async def business_logic_example():
    print("🚀 Запуск примера бизнес-логики...")
    list_hashes = []
    dict_attrs = {"account_type": "checking", "account": "30601810"}
    dict_attrs_hashes = {}

    # 1. Создаем счет для клиента (PUT)
    for key, value in dict_attrs.items():
        res = await do_api("PUT", "user_1", attr=key, value=value)
        print(f"✅ Создано: {res}")

    # 2. Получаем этот счет (GET)
    for key, value in dict_attrs.items():
        data = await do_api("GET", "user_1", key)
        print(f"🔍 Получено из БД: {data['value']} (Хеш: {data['hash']})")
        dict_attrs_hashes[key] = data["hash"]
        list_hashes.append(data["hash"])

    # 3. Кладем аттрибуты клиента, чтобы знать, что у него есть
    res = await do_api("PUT", "user_1", "user_attrs", dict_attrs_hashes)
    print(f"✅ Создано: {res}")

    # 4. Проверяем, что в БД есть список аттрибутов нашего пользователя
    data = await do_api("GET", "user_1", "user_attrs")
    print(f"🔍 Получено из БД: {data['value']} (Хеш: {data['hash']})")

    # 5. Получаем значения всех аттрибутов в БД по пользователю
    request = BatchRequest(hashes=list_hashes)
    data = await do_api("POST", None, None, request=request)
    print(f"🔍 Получено из БД: {data}")

    # 6. Красиво отобразим
    for key, value in dict_attrs_hashes.items():
        print(f"{key}={data['data'][value]}")


if __name__ == "__main__":
    asyncio.run(business_logic_example())
