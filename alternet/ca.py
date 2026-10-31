# module for creating self-signed certs
from datetime import datetime, timedelta, timezone
import ipaddress
import logging
import warnings

# cryptography is stdlib, but optional, it may not be present
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError as exc:
    warnings.warn("cryptography not present; serving demos will not work & some tests may fail")


CA_DEFAULT_NAME = "Alternet temporary demo CA"


def make_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_ca(private_key: rsa.RSAPrivateKey, directory: Path, name: str = CA_DEFAULT_NAME) -> tuple[x509.Certificate, Path]:
    """creates a temporary CA certificate for signing, and writes file ca.pem to directory

    this certificate is intended only for demo & test contexts; it will expire in 1 day

    returns 2-tuple (x509.Certificate, Path) where Path is location of ca.pem
    """
    now = datetime.now(timezone.utc)
    public_key = private_key.public_key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = x509.CertificateBuilder() \
                  .subject_name(ca_name) \
                  .issuer_name(ca_name) \
                  .public_key(public_key) \
                  .serial_number(x509.random_serial_number()) \
                  .not_valid_before(now - timedelta(minutes=5)) \
                  .not_valid_after(now + timedelta(days=1)) \
                  .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True) \
                  .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False) \
                  .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False) \
                  .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                               key_encipherment=False, data_encipherment=False,
                                               key_agreement=False, key_cert_sign=True, crl_sign=True,
                                               encipher_only=None, decipher_only=None), critical=True)
    ca = builder.sign(private_key, hashes.SHA256())

    ca_path = directory / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    return ca, ca_path


def make_cert(ca: x509.Certificate, ca_key: rsa.RSAPrivateKey, directory: Path, hostname: str = "localhost",
              extra_hosts: tuple[str, ...] = ()) -> tuple[Path, Path]:
    """creates cert for server signed by ca using ca's private ca_key

    files server.pem & server-key.pem are written to directory for public & private keys respectively

    this certificate is intended only for demo & test contexts; it will expire in 1 day

    returns 2-tuple (Path, Path) for server.pem, server-key.pem"""
    now = datetime.now(timezone.utc)
    private_key = make_private_key()
    public_key = private_key.public_key()

    names = []
    for host in [hostname, *extra_hosts]:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))

    builder = x509.CertificateBuilder() \
                  .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])) \
                  .issuer_name(ca.subject) \
                  .public_key(public_key) \
                  .serial_number(x509.random_serial_number()) \
                  .not_valid_before(now - timedelta(minutes=5)) \
                  .not_valid_after(now + timedelta(days=1)) \
                  .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
                  .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False) \
                  .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False) \
                  .add_extension(x509.SubjectAlternativeName(names), critical=False) \
                  .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())

    cert_path, key_path = (directory / filename for filename in ("server.pem", "server-key.pem"))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(private_key.private_bytes(serialization.Encoding.PEM,
                                                   serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
    return cert_path, key_path


def make_certificates(directory: Path, hostname: str = "localhost",
                      extra_hosts: tuple[str, ...] = ()) -> tuple[Path, Path, Path]:
    """creates ca.pem, server.pem, server-key.pem in directory

    A temporary CA is created, and used to sign cert for server
    """
    ca_key = make_private_key()
    ca, ca_path = make_ca(ca_key, directory)
    cert_path, key_path = make_cert(ca, ca_key, directory, hostname, extra_hosts)
    return ca_path, cert_path, key_path

