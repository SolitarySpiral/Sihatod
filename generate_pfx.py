import os

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


def create_pfx():
    if not os.path.exists("certs"):
        print("❌ Папка certs не найдена.")
        return

    # Загружаем приватный ключ
    with open("certs/redis.key", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Загружаем сертификат сервиса
    with open("certs/redis.crt", "rb") as f:
        certificate = x509.load_pem_x509_certificate(f.read())

    # Загружаем CA сертификат
    with open("certs/ca.crt", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Создаем PFX контейнер
    pfx_data = pkcs12.serialize_key_and_certificates(
        name=b"Sihatod Client",
        key=private_key,
        cert=certificate,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(b"1234"),
    )

    with open("certs/client.pfx", "wb") as f:
        f.write(pfx_data)

    print("✅ Файл certs/client.pfx успешно создан. Пароль: 1234")


if __name__ == "__main__":
    create_pfx()
