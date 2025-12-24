import ipaddress
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_certs():
    if not os.path.exists("certs"):
        os.makedirs("certs")

    now = datetime.now(timezone.utc)

    # 1. Генерируем Корневой CA
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sihatod Root CA")])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)  # Самоподписанный
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        # Указываем, что это CA и выше него никого нет
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    # 2. Универсальный сертификат (mTLS)
    service_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # COMMON_NAME должен быть "redis", так как это имя хоста в сети Docker
    service_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "redis")])

    san = x509.SubjectAlternativeName(
        [
            x509.DNSName("redis"),
            x509.DNSName("app"),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]
    )

    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)

    service_cert = (
        x509.CertificateBuilder()
        .subject_name(service_subject)
        .issuer_name(ca_subject)
        .public_key(service_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(san, critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(service_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski.value),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Сохраняем
    with open("certs/ca.crt", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    # ВАЖНО: Для некоторых версий OpenSSL в цепочку нужно класть и сам сертификат, и CA
    # Но здесь мы сохраняем их раздельно, как требует твой конфиг
    with open("certs/redis.crt", "wb") as f:
        f.write(service_cert.public_bytes(serialization.Encoding.PEM))

    with open("certs/redis.key", "wb") as f:
        f.write(
            service_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    print("✅ Сгенерированы эталонные сертификаты для mTLS.")


if __name__ == "__main__":
    generate_certs()
