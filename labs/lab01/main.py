import sys
import os

# Додаємо шлях для імпорту спільного модуля student.py
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))


def main():
    print("=== Запуск Лабораторної роботи №1 ===")

    print("\n--- Завдання 1: Аналізатор паролів ---")

    print("\n--- Завдання 2: Система контролю доступу ---")

    print("\n--- Завдання 3: Хешування та Логування ---")

    print("\n=== Всі завдання виконано успішно ===")


if __name__ == "__main__":
    main()
