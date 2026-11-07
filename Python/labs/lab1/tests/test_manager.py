"""Tests for password manager."""

import os
import tempfile
import pytest
from password_manager.manager import PasswordManager
from password_manager.crypto import (
    hashPassword,
    verifyPassword,
    generateSalt,
    generatePassw,
)


@pytest.fixture #декоратор для каждого теста, которому нужен tempstorage, передаеь в нее результат
def temp_storage():
    """Create temporary storage file path"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f: #созд врем файл, запомин путь и удаляем сразу, чтоб тест начинался с 0
        temp_file = f.name
    os.remove(temp_file)
    
    yield temp_file #передает путь к файлу в сам тест
    
    if os.path.exists(temp_file): #после теста файл удаляем
        os.remove(temp_file)


def test_hash_and_verify():
    """Test password hashing and verification"""
    salt = generateSalt()
    password = "test_password"
    
    hash1 = hashPassword(password, salt)
    hash2 = hashPassword(password, salt)
    
    #одинак пароль и соль = одинак хэш
    assert hash1 == hash2 #если нет, тест упадет
    
    #проверка пароля
    assert verifyPassword(password, salt, hash1) is True
    assert verifyPassword("wrong_password", salt, hash1) is False


def test_generatePassw():
    """Test random password generation"""
    password1 = generatePassw(16)
    password2 = generatePassw(16)
    
    assert len(password1) == 16
    assert len(password2) == 16
    assert password1 != password2 #чек длину и разность паролей


def test_init_and_unlock(temp_storage):
    """Test initialization and unlock"""
    manager = PasswordManager(storageFile=temp_storage) #созд менеждер и инициализир его
    
    manager.initMaster("master123")
    
    #создаём нов менеджер и разблокир
    manager2 = PasswordManager(storageFile=temp_storage)
    assert manager2.unlock("master123") is True 
    assert manager2.unlock("wrong_password") is False #не пускает с неправ паролем


def test_add_and_get_entry(temp_storage): #нов файл и инициализ
    """Test adding and retrieving entries"""
    manager = PasswordManager(storageFile=temp_storage)
    manager.initMaster("master-bla-bla-bla") #эмуляц как будто пользователь вводит
    
    manager.add_entry("gmail", "user@gmail.com", "password123")
    
    #провер список
    entries = manager.list_entries()
    assert "gmail" in entries #если условие истинно, тест идет дальше
    
    entry = manager.get_entry("gmail") #вызываем метод get_entry и передаём ему имя gmail

    #Мы берём значение по ключу login из полученного словаря entry и сравниваем его с тем, что мы изначально добавляли. 
    #чтобы убедиться, что при шифровании, сохранении json и расшифровке ни один символ не потерялся и не исказился
    assert entry["login"] == "user@gmail.com"
    assert entry["password"] == "password123"


def test_delete_entry(temp_storage):
    """Test deleting entries."""
    manager = PasswordManager(storageFile=temp_storage)
    manager.initMaster("master123")
    
    manager.add_entry("test", "login", "password") #добавл тестовую запись
    assert "test" in manager.list_entries() #была ли добавлена запись
    
    manager.delete_entry("test") #а теперь ищем эту запись и удаляем
    assert "test" not in manager.list_entries() #снова запрашиваем и проверяем уже отсутствие записи


def test_encryption_in_storage(temp_storage):
    """Test that passwords are encrypted in storage"""
    manager = PasswordManager(storageFile=temp_storage) #свежий объект менеджера
    manager.initMaster("master123") #снова имитация мастер-пароля
    manager.add_entry("test", "login", "secret_password")
    
    #читаем данные файла в переменную
    with open(temp_storage, 'r', encoding='utf-8') as f:
        content = f.read()
    
    assert "secret_password" not in content #этой строки не должно быть в сыром содержании файла
    assert "login" not in content  #логин зашифрован