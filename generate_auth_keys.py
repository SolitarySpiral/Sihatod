import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def generate_ed25519_keys():
    if not os.path.exists("certs"):
        os.makedirs("certs")

    # Генерация приватного ключа
    private_key = ed25519.Ed25519PrivateKey.generate()

    # Сохранение приватного ключа
    with open("certs/jwt_private.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Генерация публичного ключа
    public_key = private_key.public_key()

    # Сохранение публичного ключа
    with open("certs/jwt_public.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("✅ Ed25519 ключи для JWT созданы в папке certs/")


if __name__ == "__main__":
    generate_ed25519_keys()
