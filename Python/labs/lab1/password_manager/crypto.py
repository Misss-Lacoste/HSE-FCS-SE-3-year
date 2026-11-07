"""Cryptographic utilities for password manager."""

import hashlib #sha256
import os #соль
import base64 #байты в строки для json
from cryptography.fernet import Fernet #библ шифр


def generateSalt() -> bytes:
    """Generate random salt for hashing not to have 2 similar hashes"""
    return os.urandom(16)


def hashPassword(password: str, salt: bytes) -> str:
    """Hash password with salt using SHA-256."""
    passwordBytes = password.encode('utf-8') #hashlib работает только с байтами, переводим
    hashBytes = hashlib.sha256(passwordBytes + salt).digest() #перемалываем в 32 сырых байта qwerty123
    return base64.b64encode(hashBytes).decode('utf-8') #кашу превращаем в строку из цифр, букв и символов, чтоб не ломать джсон


def verifyPassword(password: str, salt: bytes, stored_hash: str) -> bool: #чек на соответствие нового введенного пароля с хэщем в бд
    """Verify password against stored hash."""
    computedHash = hashPassword(password, salt) #снова гоним по верхней функции
    return computedHash == stored_hash #если true то разблок


def generateEncryptionKey(masterPassword: str, salt: bytes) -> bytes: #fernet принимает ключ в формате байт
    """Generate encryption key from master password."""
    passwordBytes = masterPassword.encode('utf-8') #пароль в байты
    keyBytes = hashlib.sha256(passwordBytes + salt).digest() #клеим хэшир и извлекаем в формате сырых байт
    return base64.urlsafe_b64encode(keyBytes) #для fernet 32 байта гоним в спец формат


def encryptData(data: str, key: bytes) -> str:
    """Encrypt data using Fernet symmetric encryption."""
    f = Fernet(key) #наш ключ передаем фернету
    encrypted = f.encrypt(data.encode('utf-8'))
    return encrypted.decode('utf-8') #строку в байты и гоним по алгоритму и обратно в строку


def decryptData(encrypted_data: str, key: bytes) -> str:
    """Decrypt data using Fernet symmetric encryption."""
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_data.encode('utf-8'))
    return decrypted.decode('utf-8')


def generatePassw(length: int = 16) -> str: #если не ввели - дефолт 16 символов
    """Generate random strong password."""
    import string
    import secrets #шум для паролей в отличие от randomе где известен seed
    
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))  #клеим пароль
    return password