import os

from cryptography.fernet import Fernet


class DataProtector:
    def __init__(self):
        # В 2026 году ключ должен браться из переменных окружения
        # или Secret Manager. Для примера генерируем, если нет в ENV.
        key = os.getenv("MASTER_ENCRYPTION_KEY")
        if not key:
            # Внимание: в продакшене ключ должен быть постоянным!
            key = Fernet.generate_key().decode()

        self.cipher = Fernet(key.encode())

    def encrypt(self, data: str) -> str:
        """Превращает строку в зашифрованный шум"""
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt(self, token: str) -> str:
        """Восстанавливает исходные данные"""
        return self.cipher.decrypt(token.encode()).decode()


# Глобальный экземпляр для приложения
protector = DataProtector()
