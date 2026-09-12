"""Завдання 1: Комплексний аналізатор надійності паролів."""

import random
import string


def evaluate_password(pwd: str, all_passwords: list, criteria: dict, forbidden: set) -> str:
    """Оцінює надійність пароля за заданими критеріями."""
    # 1. Заборонений: у списку forbidden або коротший за min_length
    if pwd in forbidden or len(pwd) < criteria["min_length"]:
        return "Заборонений"

    has_digit = any(c.isdigit() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_special = any(c in string.punctuation for c in pwd)

    # Перевірка виконання абсолютно всіх критеріїв безпеки
    meets_all = has_digit and has_upper and has_special and (len(pwd) >= criteria["min_length"])

    # 2. Дуже сильний: всі критерії + довжина >= min_length + 4 + унікальний
    if meets_all and len(pwd) >= (criteria["min_length"] + 4) and all_passwords.count(pwd) == 1:
        return "Дуже сильний"

    # 3. Сильний: всі критерії, але довжина < min_length + 4
    if meets_all and len(pwd) < (criteria["min_length"] + 4):
        return "Сильний"

    # 4. Середній: достатня довжина та деякі (але не всі) критерії
    if len(pwd) >= criteria["min_length"]:
        return "Середній"

    # 5. Слабкий: виконує хоча б один критерій безпеки
    if has_digit or has_upper or has_lower or has_special:
        return "Слабкий"

    return "Заборонений"


def run_task1():
    """Основна функція запуску Завдання 1."""
    passwords = [
        "APT@Detect10n",
        "simple",
        "Red@Team2023",
        "participant",
        "Blue@T3am",
        "common123",
        "Purple@T34m",
        "regular123",
        "Gr33n@Team",
        "normal123",
    ]

    criteria = {
        "min_length": 7,
        "require_digits": True,
        "require_upper": True,
        "require_special": True,
    }

    forbidden_passwords = {
        "simple",
        "participant",
        "common123",
        "regular123",
        "normal123",
        "test",
    }

    # Генерація 3 випадкових індексів і додавання дублікатів
    for _ in range(3):
        rand_idx = random.randint(0, len(passwords) - 1)
        passwords.append(passwords[rand_idx])

    # Виведення результатів у табличному форматі
    print(f"{'Пароль':<20} | {'Категорія надійності':<20}")
    print("-" * 43)
    for pwd in passwords:
        category = evaluate_password(pwd, passwords, criteria, forbidden_passwords)
        print(f"{pwd:<20} | {category:<20}")