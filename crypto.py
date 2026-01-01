import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# from cryptography.fernet import Fernet
# class DataProtector:
#     def __init__(self):
#         # В 2026 году ключ должен браться из переменных окружения
#         # или Secret Manager. Для примера генерируем, если нет в ENV.
#         key = os.getenv("MASTER_ENCRYPTION_KEY")
#         if not key:
#             # Внимание: в продакшене ключ должен быть постоянным!
#             key = Fernet.generate_key().decode()
#         self.cipher = Fernet(key.encode())
#     def encrypt(self, data: str) -> str:
#         """Превращает строку в зашифрованный шум"""
#         return self.cipher.encrypt(data.encode()).decode()
#     def decrypt(self, token: str) -> str:
#         """Восстанавливает исходные данные"""
#         return self.cipher.decrypt(token.encode()).decode()


class DataProtector:
    def __init__(self):
        # Имя файла 'master_key' должно совпадать с target в docker-compose
        secret_path = "/run/secrets/master_key"
        if os.path.exists(secret_path):
            with open(secret_path, "rb") as f:
                # Читаем байты, стрипаем лишние переносы строк
                self.master_key = f.read().strip()
        else:
            # Fallback на случай локального запуска без докера
            master_key_env = os.getenv("MASTER_ENCRYPTION_KEY", "fallback-key-must-be-32-bytes!!")
            self.master_key = master_key_env.encode()

    def _derive_key(self, salt: bytes) -> bytes:
        """Генерация уникального ключа для каждой записи (KDF)"""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"redis-encryption",
        ).derive(self.master_key)

    def encrypt(self, data: str) -> str:  # Теперь возвращаем строку
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(salt)

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data.encode(), None)

        # Упаковываем в JSON-строку для Redis
        result = {
            "v": "v1-gcm",
            "payload": ciphertext.hex(),
            "salt": salt.hex(),
            "nonce": nonce.hex(),
        }
        return json.dumps(result)

    def decrypt(self, encrypted_json: str) -> str:
        # Распаковываем JSON обратно в словарь
        try:
            encrypted_obj = json.loads(encrypted_json)
        except (json.JSONDecodeError, TypeError):
            # Если в Redis лежат старые данные (не JSON),
            # тут нужно либо вернуть ошибку, либо обработать как старый формат
            return "Error: Invalid data format"

        key = self._derive_key(bytes.fromhex(encrypted_obj["salt"]))
        aesgcm = AESGCM(key)

        decrypted = aesgcm.decrypt(
            bytes.fromhex(encrypted_obj["nonce"]), bytes.fromhex(encrypted_obj["payload"]), None
        )
        return decrypted.decode()


# Глобальный экземпляр для приложения
protector = DataProtector()
