"""Завдання 3: Безпечне хешування, CSV-база та JSON-логування з винятками."""

import csv
import datetime
import functools
import hashlib
import json
import os
import sys

# Додаємо корінь проєкту до sys.path для доступу до shared
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from shared.student import VARIANT_NUMBER # noqa: E402

# Константи для Варіанта 11
MIN_PASSWORD_LENGTH = 12
SALT = str(VARIANT_NUMBER).zfill(5)
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
CSV_PATH = os.path.join(DATA_DIR, "users.csv")
JSON_PATH = os.path.join(DATA_DIR, "log.json")


class ValidationError(Exception):
    """Виняток для паролів, що не відповідають мінімальній довжині."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує blake2b хеш від конкатенації пароля та солі."""
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль занадто короткий. Мінімум {MIN_PASSWORD_LENGTH} символів."
        )

    # Конкатенація пароля та солі
    salted_data = (password + salt).encode("utf-8")
    return hashlib.blake2b(salted_data).hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Створює запис користувача з персональною сіллю варіанта."""
    hash_value = generate_hash(password, salt=SALT)
    return (username, hash_value)


def create_users(users_list: tuple) -> None:
    """Зберігає список користувачів у файл data/users.csv."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CSV_PATH, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["username", "password_hash"])
        for username, pwd in users_list:
            user_entry = create_user(username, pwd)
            writer.writerow(user_entry)


def read_users_db() -> list[dict[str, str]]:
    """Зчитує дані користувачів із CSV-файлу."""
    if not os.path.exists(CSV_PATH):
        raise FileNotFoundError(f"Файл {CSV_PATH} не знайдено.")

    users_db = []
    with open(CSV_PATH, mode="r", newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            users_db.append(row)
    return users_db


def log_event(func):
    """Декоратор для логування кожної спроби входу в log.json."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if len(args) > 0 else kwargs.get("username", "")
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            result_bool = func(*args, **kwargs)
            result_status = "success" if result_bool else "failure"
        except Exception as exc:
            result_status = f"failure ({type(exc).__name__})"
            raise exc
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": (result_status if "result_status" in locals() else "failure"),
                "timestamp": timestamp,
                "args": [str(a) for a in args],
                "kwargs": {k: str(v) for k, v in kwargs.items()},
            }

            os.makedirs(DATA_DIR, exist_ok=True)
            existing_logs = []
            if os.path.exists(JSON_PATH):
                try:
                    with open(JSON_PATH, "r", encoding="utf-8") as jf:
                        existing_logs = json.load(jf)
                except (json.JSONDecodeError, IOError):
                    existing_logs = []

            existing_logs.append(log_entry)
            with open(JSON_PATH, "w", encoding="utf-8") as jf:
                json.dump(existing_logs, jf, indent=2, ensure_ascii=False)

        return result_bool

    return wrapper


@log_event
def login(username: str, password: str, users_db: list[dict[str, str]]) -> bool:
    """Автентифікує користувача шляхом порівняння хешів."""
    if not username or not password:
        raise ValueError("Логін або пароль не можуть бути порожніми.")

    target_hash = generate_hash(password, salt=SALT)
    for user in users_db:
        if user["username"] == username:
            return user["password_hash"] == target_hash
    return False


def run_task3():

    # Кортеж із 10 користувачів (усі паролі >= 12 символів)
    users_to_register = (
        ("admin_sec", "Complex#Pass12"),
        ("cyber_analyst", "SafePassword!99"),
        ("m_zhenchak", "SuperSecret#2026"),
        ("dev_ops_user", "Cluster_Admin1"),
        ("net_engineer", "Router#Secure2"),
        ("audit_lead", "AuditP@ssword3"),
        ("incident_resp", "Incident_Team4"),
        ("cloud_architect", "CloudInfr@2026"),
        ("qa_security", "TestPassw0rd#5"),
        ("guest_monitor", "ReadOnly#Access"),
    )

    try:
        # 1. Створення CSV бази даних
        print("1. Збереження користувачів у CSV...")
        create_users(users_to_register)
        print(f"Дані успішно записано у {CSV_PATH}")

        # 2. Зчитування та виведення таблиці
        print("\n2. Зчитування бази даних users.csv:")
        users_db = read_users_db()
        print(f"{'Username':<20} | {'blake2b Hash':<40}")
        print("-" * 65)
        for u in users_db:
            short_hash = f"{u['password_hash'][:36]}..."
            print(f"{u['username']:<20} | {short_hash:<40}")

        # 3. Тестування автентифікації та декоратора логування
        print("\n3. Тестування автентифікації та логування:")

        # Успішний вхід
        auth_ok = login("m_zhenchak", "SuperSecret#2026", users_db)
        print(f"Спроба 1 (вірні дані): {'Успішно' if auth_ok else 'Невдача'}")

        # Неправильний пароль
        auth_bad_pwd = login("m_zhenchak", "WrongPassword#9", users_db)
        print(f"Спроба 2 (невірний пароль): {'Успішно' if auth_bad_pwd else 'Невдача'}")

        # Неіснуючий користувач
        auth_no_user = login("unknown_user", "RandomPass1234", users_db)
        print(
            f"Спроба 3 (неіснуючий логін): {'Успішно' if auth_no_user else 'Невдача'}"
        )

        print(f"\nЛоги подій успішно оновлено у {JSON_PATH}")

        # 4. Демонстрація перехоплення винятків
        print("\n4. Демонстрація валідації та винятків:")
        try:
            # Спроба передати занадто короткий пароль (< 12 символів)
            generate_hash("short", salt=SALT)
        except ValidationError as e:
            print(f"Успішно перехоплено ValidationError: {e}")

        try:
            # Спроба передати порожній логін
            login("", "SomeValidPassword123", users_db)
        except ValueError as e:
            print(f"Успішно перехоплено ValueError: {e}")

    except (FileNotFoundError, PermissionError, IOError) as file_err:
        print(f"Помилка роботи з файлами: {file_err}")
    except (ValidationError, ValueError) as val_err:
        print(f"Помилка валідації даних: {val_err}")


if __name__ == "__main__":
    run_task3()
