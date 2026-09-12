"""Головний модуль для запуску Лабораторної роботи №1."""

import os
import sys

# Додавання кореневої директорії до sys.path для імпорту shared
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path.append(BASE_DIR)

from labs.lab01.task1 import run_task1 # noqa: E402
from labs.lab01.task2 import run_task2 # noqa: E402
from labs.lab01.task3 import run_task3 # noqa: E402
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER # noqa: E402


def main():
    """Точка входу для демонстрації виконання завдань."""
    print("=== Запуск Лабораторної роботи №1 ===")
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")

    print("\n--- Завдання 1: Аналізатор паролів ---")
    run_task1()

    print("\n--- Завдання 2: Система контролю доступу ---")
    run_task2()

    print("\n--- Завдання 3: Хешування та Логування ---")
    run_task3()

    print("\n=== Всі завдання виконано успішно ===")


if __name__ == "__main__":
    main()
