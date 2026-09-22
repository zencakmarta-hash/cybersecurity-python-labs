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

    salted_data = (password + salt).encode("utf-8")
    return hashlib.blake2b(salted_data).hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Створює запис користувача з обробкою винятків всередині."""
    try:
        hash_value = generate_hash(password, salt=SALT)
        return (username, hash_value)
    # Перехоплюємо помилки прямо під час створення конкретного юзера
    except ValidationError as e:
        print(f"[Помилка Валідації] Користувач '{username}': {e}")
        return (username, None)
    except ValueError as e:
        print(f"[Помилка Значення] Користувач '{username}': {e}")
        return (username, None)


def create_users(users_list: tuple) -> None:
    """Зберігає список користувачів у файл data/users.csv."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CSV_PATH, mode="w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["username", "password_hash"])
            for username, pwd in users_list:
                user_entry = create_user(username, pwd)
                # Записуємо тільки тих, хто успішно пройшов валідацію
                if user_entry[1] is not None:
                    writer.writerow(user_entry)
    # ЕКСЕПШИН В СЕРЕДИНІ: Обробка помилок запису
    except (PermissionError, IOError) as e:
        print(f"[Помилка Файлу] Не вдалося записати базу користувачів: {e}")


def read_users_db() -> list[dict[str, str]]:
    """Зчитує дані користувачів із CSV-файлу."""
    users_db = []
    try:
        with open(CSV_PATH, mode="r", newline="", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                users_db.append(row)
    # Обробка відсутності файлу
    except FileNotFoundError:
        print(f"[Помилка] Файл {CSV_PATH} не знайдено. Повертаємо порожню базу.")
    except Exception as e:
        print(f"[Неочікувана помилка] під час читання БД: {e}")

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
            print(f"[Логер] Перехоплено помилку під час входу: {exc}")
            result_bool = False # Не "крешимо" програму, а просто не пускаємо
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": timestamp,
            }
            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                existing_logs = []
                if os.path.exists(JSON_PATH):
                    with open(JSON_PATH, "r", encoding="utf-8") as jf:
                        existing_logs = json.load(jf)

                existing_logs.append(log_entry)
                with open(JSON_PATH, "w", encoding="utf-8") as jf:
                    json.dump(existing_logs, jf, indent=2, ensure_ascii=False)
            except IOError as log_err:
                print(f"[Помилка Логування] Не вдалося оновити JSON: {log_err}")

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
    # Додано одного користувача з коротким паролем для перевірки
    users_to_register = (
        ("admin_sec", "Complex#Pass12"),
        ("cyber_analyst", "SafePassword!99"),
        ("m_zhenchak", "SuperSecret#2026"),
        ("short_user", "123"), # Цей пароль викличе ValidationError
    )

    print("1. Збереження користувачів у CSV...")
    create_users(users_to_register)
    print("Дані оброблено. (Див. повідомлення про помилки вище, якщо вони були)\n")

    print("2. Зчитування бази даних users.csv:")
    users_db = read_users_db()
    if users_db:
        print(f"{'Username':<20} | {'blake2b Hash':<40}")
        print("-" * 65)
        for u in users_db:
            short_hash = f"{u['password_hash'][:36]}..."
            print(f"{u['username']:<20} | {short_hash:<40}")

    print("\n3. Тестування автентифікації та логування:")
    auth_ok = login("m_zhenchak", "SuperSecret#2026", users_db)
    print(f"Спроба 1 (вірні дані): {'Успішно' if auth_ok else 'Невдача'}")

    # Спроба з порожнім паролем (викличе ValueError всередині login, але програма не впаде)
    auth_empty = login("admin_sec", "", users_db)
    print(f"Спроба 2 (порожній пароль): {'Успішно' if auth_empty else 'Невдача'}")

if __name__ == "__main__":
    run_task3()