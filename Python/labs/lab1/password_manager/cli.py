"""Command-line interface for Margaret's password manager."""

import argparse #парсер аргуметов
import getpass #для скрытого ввода паролейй
import sys #если вдруг ошиьки
from password_manager.manager import PasswordManager
from password_manager.crypto import generatePassw

def main() -> None: 
    """Command-line inteface entry point."""
    #создаем парсер с помощью встроенного класса ArgumentParser
    parser = argparse.ArgumentParser(description="Password Manager") #в случае если хотим help
    parser.add_argument("--init", action="store_true", help="Create master password") #ставим флаг чтоб не писать тру при вводе
    parser.add_argument("--unlock", action="store_true", help="Unlock the password manager")
    parser.add_argument("--generate", type=int, metavar="LENGTH", help="Generate new random password")
    parser.add_argument("--file", default="passwords.json", help="Storage file path") #путь делфолтно к хранилищу passwords.json
    
    args = parser.parse_args() #парсим арг из командной строки
    
    manager = PasswordManager(storageFile=args.file) #объект менеджера передавая путь к файлу куда класть пароли
    
    #генер пароля
    if args.generate:
        password = generatePassw(args.generate)
        print(f"Your generated password is: {password}")
        return
    
    #инициализ
    if args.init:
        print("Creating new master password...")
        password = getpass.getpass("Enter new master password: ")
        confirm = getpass.getpass("Please, confirm master password: ")
        
        if password != confirm:
            print("Error! Passwords differ :(")
            sys.exit(1)
        
        try:
            manager.initMaster(password)
            print("Master password was created successfully!")
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
        
        return
    
    #разблокировка
    if args.unlock:
        try:
            print("Unlocking manager...")
            password = getpass.getpass("Please, enter your master password: ")
            
            if not manager.unlock(password):
                print("Error! Incorrect password!")
                sys.exit(1)
            
            print("Password manager successfully unlocked!")
            menu(manager)
            
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
        
        return
    
    #если не выбрали ничего
    parser.print_help()


def menu(manager: PasswordManager) -> None:
    """Interactive menu after unlock."""
    while True:
        print("*** Hello! Welcome to Margaret's password manager! ***")
        print("1. Add entry note")
        print("2. List of all entries")
        print("3. Get your entry")
        print("4. Delete your entry")
        print("5. Generate new password")
        print("6. Exit")
        
        choice = input("Choose option (1-6): ").strip() #уберем пробелы по краям
        
        try:
            if choice == "1":
                name = input("Your entry name: ").strip()
                login = input("Login: ").strip()
                password = getpass.getpass("Password: ")
                manager.add_entry(name, login, password) #добавляем через менеджер
                print(f"Entry '{name}' added.")
                
            elif choice == "2":
                entries = manager.list_entries()
                if not entries:
                    print("No entries found :(")
                else:
                    print("Entries:")
                    for entry in entries:
                        print(f"  - {entry}")
                        
            elif choice == "3":
                name = input("Entry name: ").strip()
                entry = manager.get_entry(name)
                print(f"Login: {entry['login']}")
                print(f"Password: {entry['password']}")
                
            elif choice == "4":
                name = input("Entry name to delete: ").strip()
                manager.delete_entry(name)
                print(f"Entry '{name}' deleted.")
                
            elif choice == "5":
                length = input("Password length (default is 16): ").strip()
                if not length:
                    length = 16 #по дефолту если ниче не ввели
                else:
                    try:
                        length = int(length)
                        if length < 4:
                            print("Minimum length is 4. Set to 16 digits.")
                            length = 16 #снова по дефолту
                    except ValueError:
                        print("Invalid input!! Set default length of 16 digits.")
                        length = 16
                password = generatePassw(length)
                print(f"Generated password: {password}")
                
            elif choice == "6":
                print("See you later, alligator! See you soon, cute racoon!")
                break
                
            else:
                print("Invalid option or you misspelled :(")
                
        except ValueError as e:
            print(f"Error: {e}") #ловим ошиьки
        except KeyboardInterrupt: #ctrl c
            print("\nGoodbye!")
            break


if __name__ == "__main__":
    main()