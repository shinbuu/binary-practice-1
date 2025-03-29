import lief
print([attr for attr in dir(lief.PE) if "SECTION" in attr])


def analyze_pe(binary):
    """Анализирует PE-файл: тип (EXE/DLL) и импортируемые библиотеки."""
    print(f"[*] Анализ PE-файла...")
    is_dll = (binary.header.characteristics & 0x2000) != 0  # 0x2000 — флаг IMAGE_FILE_DLL
    print(f"    Тип: {'DLL' if is_dll else 'EXE'}")

    print("    Таблица импорта:")
    for lib in binary.imports:
        print(f"      Библиотека: {lib.name}")
        for func in lib.entries:
            print(f"        {func.name if func.name else 'ORDINAL ' + str(func.ordinal)}")

def add_section(binary):
    """Добавляет новую секцию в PE-файл."""
    name = input("Имя секции (по умолчанию .newsec): ") or ".newsec"
    size = int(input("Размер (HEX, по умолчанию 0x1000): ") or "0x1000", 16)

    section = lief.PE.Section(name)
    section.virtual_size = size
    section.sizeof_raw_data = size

    binary.add_section(section)
    print(f"[+] Добавлена секция {name} размером {size:#x}")



    binary.add_section(section)
    print(f"[+] Добавлена секция {name} размером {size:#x}")


def change_entry_point(binary):
    """Изменяет точку входа PE-файла."""
    new_entry = int(input("Новый адрес точки входа (HEX): "), 16)
    binary.optional_header.addressof_entrypoint = new_entry
    print(f"[+] Точка входа изменена на {new_entry:#x}")

def replace_import(binary):
    """Заменяет импортируемую библиотеку в PE-файле."""
    old_lib = input("Старая библиотека (например, kernel32.dll): ")
    new_lib = input("Новая библиотека (например, user32.dll): ")

    for imp in binary.imports:
        if imp.name.lower() == old_lib.lower():
            imp.name = new_lib
            print(f"[+] Импорт {old_lib} заменен на {new_lib}")
            return
    print(f"[!] Библиотека {old_lib} не найдена.")

def detect_malicious_features(binary):
    """Проверяет PE-файл на наличие подозрительных импортов и зашифрованных секций."""
    suspicious_imports = {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "LoadLibrary"}
    encrypted_sections = []

    for section in binary.sections:
        if section.entropy > 7.0:
            encrypted_sections.append(section.name)

    detected_imports = [func.name for lib in binary.imports for func in lib.entries if func.name in suspicious_imports]

    if detected_imports:
        print("[!] Обнаружены подозрительные импорты:", *detected_imports, sep="\n    ")
    if encrypted_sections:
        print("[!] Обнаружены зашифрованные секции:", *encrypted_sections, sep="\n    ")

def save_changes(binary, file_path):
    """Сохраняет изменения в новый файл."""
    modified_file = "modified_" + file_path
    binary.write(modified_file)
    print(f"[*] Измененный файл сохранен как {modified_file}")

def main():
    file_path = input("Введите путь к PE-файлу: ").strip()
    binary = lief.PE.parse(file_path)
    
    if not binary:
        print("[!] Ошибка: Не удалось разобрать PE-файл.")
        return
    
    actions = {
        "1": analyze_pe,
        "2": add_section,
        "3": change_entry_point,
        "4": replace_import,
        "5": detect_malicious_features,
        "6": lambda b: save_changes(b, file_path)
    }

    while True:
        print("\nВыберите действие:")
        print("1 - Анализ PE-файла")
        print("2 - Добавить новую секцию")
        print("3 - Изменить точку входа")
        print("4 - Заменить импортируемую библиотеку")
        print("5 - Проверка на вредоносные признаки")
        print("6 - Сохранить изменения и выйти")
        print("0 - Выйти без сохранения")
        
        choice = input("Введите номер действия: ").strip()
        
        if choice == "0":
            print("Выход без сохранения.")
            break
        if choice in actions:
            actions[choice](binary)
        else:
            print("[!] Неверный ввод. Попробуйте снова.")

if __name__ == "__main__":
    main()
