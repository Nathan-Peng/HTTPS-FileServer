from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import sys
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)
sys.stderr = open(sys.stderr.fileno(), mode='w', encoding='utf-8', buffering=1)

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
with open("server.key", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost")
])
now = datetime.datetime.now(datetime.UTC)
cert = x509.CertificateBuilder()\
.subject_name(subject).issuer_name(issuer)\
.public_key(private_key.public_key())\
.serial_number(x509.random_serial_number())\
.not_valid_before(now)\
.not_valid_after(now + datetime.timedelta(days=365))\
.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)\
.sign(private_key, hashes.SHA256())

with open("server.crt", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
print("✅ SSL证书生成完成：server.crt / server.key")