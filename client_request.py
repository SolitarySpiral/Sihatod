import json
import sys

import httpx

BASE_URL = "https://localhost:5001"
CERT = ("certs/redis.crt", "certs/redis.key")
VERIFY = "certs/ca.crt"


def make_request(method, path, body=None):
    # Используем Client как контекстный менеджер для автоматического сохранения кук (JWT)
    with httpx.Client(cert=CERT, verify=VERIFY, http2=True) as client:
        # 1. Авторизация (используем тот же путь, что в работающем скрипте)
        login_data = {"username": "admin", "password": "secret"}
        login_response = client.post(f"{BASE_URL}/auth/login", json=login_data)

        if login_response.status_code != 200:
            print(f"❌ Ошибка входа: {login_response.status_code}")
            print(login_response.text)
            return

        # 2. Выполнение запроса
        try:
            url = f"{BASE_URL}{path}"
            if method.upper() == "GET":
                response = client.get(url)
            elif method.upper() == "PUT":
                response = client.put(url, json=body)
            elif method.upper() == "POST":
                response = client.post(url, json=body)
            elif method.upper() == "DELETE":
                response = client.delete(url)
            else:
                print(f"Метод {method} не поддерживается")
                return

            print(f"--- Результат {method} {path} ---")
            print(f"Status: {response.status_code}")
            print(json.dumps(response.json(), indent=2, ensure_ascii=False))
        except Exception as e:
            print(f"❌ Ошибка: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Использование: python client_request.py [METHOD] [PATH] [VALUE/JSON]")
    else:
        method = sys.argv[1].upper()
        path = sys.argv[2]

        body = None
        if len(sys.argv) > 3:
            val = sys.argv[3]
            # Логика: если путь содержит 'batch', парсим как чистый JSON.
            # В остальных случаях (PUT) оборачиваем в {"value": ...}
            if "batch" in path.lower():
                try:
                    body = json.loads(val)
                except json.JSONDecodeError:
                    print("❌ Ошибка: Для batch-запроса нужен валидный JSON")
                    sys.exit(1)
            else:
                # Автоматическая обертка для обычных PUT запросов
                body = {"value": val}

        make_request(method, path, body)
