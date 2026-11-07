"""Password manager logic"""

import json
import os #файл система
from typing import Optional #аннотации
from . import crypto


class PasswordManager:
    """Main password manager class"""
    
    def __init__(self, storageFile: str = "passwords.json"): #конструктор класса для manager
        """Initialize password manager"""
        self.storageFile = storageFile #путь к файлу хранилища как атрибут объекта
        self.masterPassword: Optional[str] = None #храним мастер пароль в памяти аннотация в виде строки или нон
        self.encryptionKey: Optional[bytes] = None #ключ шифрования записей(без него не расшифруем пароли)
        self.data: dict = {} #словарь с содержимым файлв passwords.json (пока пустой)
        
    def initMaster(self, password: str) -> None: #первый запуск создание мастер пароля
        """Initialize master password (first time setup)."""
        if os.path.exists(self.storageFile): #если passwords.json существ, то мастер пароль создан
            raise ValueError("Master password already exists. You should use unlock function")
        
        salt = crypto.generateSalt()
        masterHash = crypto.hashPassword(password, salt)
        
        encryptionSalt = crypto.generateSalt()
        encryptionKey = crypto.generateEncryptionKey(password, encryptionSalt)
        
        #сохр данные
        self.data = {
            "masterHash": masterHash,
            "salt": salt.hex(), #тк байты нельзя хранить в json
            "encryption_salt": encryptionSalt.hex(),
            "entries": {}
        }
        
        self.masterPassword = password #сохр в памяти
        self.encryptionKey = encryptionKey
        self._persist() #self.data в passwords.json
        
    def unlock(self, password: str) -> bool:
        """Unlock manager with master password"""
        if not os.path.exists(self.storageFile):
            raise ValueError("Manager not initialized! Ypu should use init_master function first.")
        
        self._load() #содержиое passwords.json в self.data
        
        salt = bytes.fromhex(self.data["salt"]) #соль из файла в формате hex снова в байты
        storedHash = self.data["masterHash"]
        
        if not crypto.verifyPassword(password, salt, storedHash):
            return False #если не совпали
        
        encryptionSalt = bytes.fromhex(self.data["encryption_salt"]) 
        self.encryptionKey = crypto.generateEncryptionKey(password, encryptionSalt) #генерир ключ шифров из введённого пароля
        self.masterPassword = password #сохр в память
        
        return True
    
    def add_entry(self, name: str, login: str, password: str) -> None: #если ключ шифрования none
        """Add new password entry"""
        if not self.encryptionKey:
            raise ValueError("Manager is locked. You should unlock it first.")
        
        #логин и пароль в json
        entry_data = json.dumps({"login": login, "password": password})
        encrypted = crypto.encryptData(entry_data, self.encryptionKey)
        
        self.data["entries"][name] = encrypted #cохр зашифров строку в словарь под ключом name
        self._persist() #сохр изменения
    
    def list_entries(self) -> list[str]:
        """List all entry names (not passwords)"""
        if not self.encryptionKey:
            raise ValueError("Manager is locked. You should unlock it first.")
        
        return list(self.data["entries"].keys()) #список ключей словаря
    
    def get_entry(self, name: str) -> dict[str, str]:
        """Get entry by name (returns login and password)"""
        if not self.encryptionKey:
            raise ValueError("Manager is locked. Unlock first.")
        
        if name not in self.data["entries"]:
            raise ValueError(f"Entry '{name}' not found.")
        
        encrypted = self.data["entries"][name] #берем зашифр стр из словаря
        decrypted = crypto.decryptData(encrypted, self.encryptionKey) #через fernet
        
        return json.loads(decrypted) #json строка обратно в словарь
    
    def delete_entry(self, name: str) -> None:
        """Delete entry by name."""
        if not self.encryptionKey:
            raise ValueError("Manager is locked. Unlock first.")
        
        if name not in self.data["entries"]:
            raise ValueError(f"Entry '{name}' not found.")
        
        del self.data["entries"][name]
        self._persist()
    
    def _persist(self) -> None:
        """Save data to file"""
        with open(self.storageFile, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False) #записывает словарь в файл и русские буквы тож
    
    def _load(self) -> None: #загружает в self.data
        """Load data from file."""
        with open(self.storageFile, 'r', encoding='utf-8') as f:
            self.data = json.load(f)