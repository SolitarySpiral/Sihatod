import asyncio

import httpx


async def do_api(method: str, client_key: str, attr: str, value: str = None):
    url = f"http://localhost:5001/hash/{client_key}/{attr}"
    params = {"value": value} if value else {}

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

    # 1. Создаем счет для клиента (PUT)
    res = await do_api("PUT", "user_1", "account_type", "checking")
    print(f"✅ Создано: {res}")

    # 2. Получаем этот счет (GET)
    data = await do_api("GET", "user_1", "account_type")
    print(f"🔍 Получено из БД: {data['value']} (Хеш: {data['hash']})")

    # 3. Кладем аттрибуты клиента, чтобы знать, что у него есть
    attr_dict = {"account_type": data["hash"]}
    res = await do_api("PUT", "user_1", "user_attrs", attr_dict)
    print(f"✅ Создано: {res}")

    # 4. Проверяем, что в БД есть список аттрибутов нашего пользователя
    data = await do_api("GET", "user_1", "user_attrs")
    print(f"🔍 Получено из БД: {data['value']} (Хеш: {data['hash']})")


if __name__ == "__main__":
    asyncio.run(business_logic_example())
