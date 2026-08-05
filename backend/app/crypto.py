"""
Encrypt/decrypt SSH credentials at rest.

Decrypted values must never be logged, stored in a Celery result backend,
or returned by any API response. They exist only as local variables inside
ssh_executor.py for the lifetime of a single SSH session.
"""
from cryptography.fernet import Fernet

from .config import settings

_fernet = Fernet(settings.secret_encryption_key.encode())

SEP = "\n---PASSPHRASE---\n"


def encrypt_password(password: str) -> str:
    return _fernet.encrypt(password.encode()).decode()


def encrypt_private_key(private_key: str, passphrase: str | None) -> str:
    payload = private_key + SEP + (passphrase or "")
    return _fernet.encrypt(payload.encode()).decode()


def decrypt_password(blob: str) -> str:
    return _fernet.decrypt(blob.encode()).decode()


def decrypt_private_key(blob: str) -> tuple[str, str | None]:
    raw = _fernet.decrypt(blob.encode()).decode()
    key, _, passphrase = raw.partition(SEP)
    return key, (passphrase or None)


def encrypt_text(text: str) -> str:
    return _fernet.encrypt(text.encode()).decode()


def decrypt_text(blob: str) -> str:
    return _fernet.decrypt(blob.encode()).decode()
