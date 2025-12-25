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
        print("Использование: python client_request.py [METHOD] [PATH]")
    else:
        m = sys.argv[1]
        p = sys.argv[2]
        # Для простоты: если нужен PUT с телом, добавим его третьим аргументом как JSON-строку
        b = json.loads(sys.argv[3]) if len(sys.argv) > 3 else None
        make_request(m, p, b)
