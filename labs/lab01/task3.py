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

try:
    from shared.student import VARIANT_NUMBER  # noqa: E402
except ImportError as e:
    print(f"[Помилка Імпорту] Не вдалося завантажити VARIANT_NUMBER, встановлено 1 за замовчуванням: {e}")
    VARIANT_NUMBER = 1
except Exception as e:
    print(f"[Неочікувана помилка імпорту]: {e}")
    VARIANT_NUMBER = 1

MIN_PASSWORD_LENGTH = 12
SALT = str(VARIANT_NUMBER).zfill(5)
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
CSV_PATH = os.path.join(DATA_DIR, "users.csv")
JSON_PATH = os.path.join(DATA_DIR, "log.json")


class ValidationError(Exception):
    """Виняток для паролів, що не відповідають мінімальній довжині."""
    pass

def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує blake2b хеш від конкатенації пароля та солі."""

    if not isinstance(password, str) or not isinstance(salt, str):
        raise TypeError("Пароль та сіль повинні бути текстовими рядками (str).")
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми.")


    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль занадто короткий. Мінімум {MIN_PASSWORD_LENGTH} символів."
        )

    try:
        salted_data = (password + salt).encode("utf-8")
        return hashlib.blake2b(salted_data).hexdigest()
    except Exception as e:

        raise RuntimeError(f"Критична помилка при генерації хешу: {e}")


def create_user(username: str, password: str) -> tuple[str, str]:
    """Створює запис користувача з обробкою всіх видів винятків."""
    try:
        hash_value = generate_hash(password, salt=SALT)
        return (username, hash_value)
    except ValidationError as e:
        print(f"[Помилка Валідації] Користувач '{username}': {e}")
    except ValueError as e:
        print(f"[Помилка Значення] Користувач '{username}': {e}")
    except TypeError as e:
        print(f"[Помилка Типу] Користувач '{username}': {e}")
    except RuntimeError as e:
        print(f"[Помилка Виконання] Користувач '{username}': {e}")
    except Exception as e:
        print(f"[Неочікувана помилка] Користувач '{username}': {e}")

    return (username, None)


def create_users(users_list: tuple) -> None:
    """Зберігає список користувачів у файл із максимальною відмовостійкістю."""
    if not isinstance(users_list, (list, tuple)):
        print("[Помилка Типу] Очікувався список або кортеж користувачів.")
        return

    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CSV_PATH, mode="w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["username", "password_hash"])
            for item in users_list:
                try:
                    # Може виникнути ValueError, якщо елемент не має рівно 2 значень
                    username, pwd = item
                    user_entry = create_user(username, pwd)
                    if user_entry[1] is not None:
                        writer.writerow(user_entry)
                except ValueError as e:
                    print(f"[Помилка Розпакування] Неправильний формат даних користувача: {e}")
                except TypeError as e:
                    print(f"[Помилка Типу] Дані користувача пошкоджені: {e}")
                except Exception as e:
                    print(f"[Неочікувана помилка в циклі]: {e}")

    except FileNotFoundError as e:
        print(f"[Помилка Файлу] Директорію або шлях не знайдено: {e}")
    except PermissionError as e:
        print(f"[Помилка Доступу] Немає прав на запис у {CSV_PATH}: {e}")
    except IOError as e:
        print(f"[Помилка Вводу/Виводу] Збій запису файлу: {e}")
    except Exception as e:
        print(f"[Критична помилка збереження БД]: {e}")


def read_users_db() -> list[dict[str, str]]:
    """Зчитує дані користувачів із CSV-файлу з повною перевіркою винятків."""
    users_db = []
    try:
        with open(CSV_PATH, mode="r", newline="", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                users_db.append(row)
    except FileNotFoundError:
        print(f"[Помилка] Файл {CSV_PATH} не знайдено. Повертаємо порожню базу.")
    except PermissionError:
        print(f"[Помилка Доступу] Відмовлено у читанні файлу {CSV_PATH}.")
    except csv.Error as e:
        print(f"[Помилка Парсингу CSV] Файл пошкоджений: {e}")
    except IOError as e:
        print(f"[Помилка Вводу/Виводу] Збій читання: {e}")
    except Exception as e:
        print(f"[Неочікувана помилка під час читання БД]: {e}")

    return users_db


def log_event(func):
    """Декоратор для логування кожної спроби входу з обробкою JSON-помилок та файлових систем."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if len(args) > 0 else kwargs.get("username", "Невідомий")
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            result_bool = func(*args, **kwargs)
            result_status = "success" if result_bool else "failure"
        except ValidationError as exc:
            result_status = "failure (ValidationError)"
            print(f"[Логер] Помилка валідації пароля: {exc}")
            result_bool = False
        except ValueError as exc:
            result_status = "failure (ValueError)"
            print(f"[Логер] Некоректні аргументи: {exc}")
            result_bool = False
        except TypeError as exc:
            result_status = "failure (TypeError)"
            print(f"[Логер] Некоректний тип аргументів: {exc}")
            result_bool = False
        except Exception as exc:
            result_status = f"failure ({type(exc).__name__})"
            print(f"[Логер] Неочікувана помилка під час входу: {exc}")
            result_bool = False
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

            except json.JSONDecodeError as log_err:
                print(f"[Помилка JSON] Файл логів {JSON_PATH} пошкоджено. Лог не записано: {log_err}")
            except FileNotFoundError as log_err:
                print(f"[Помилка Логування] Файл або директорію не знайдено: {log_err}")
            except PermissionError as log_err:
                print(f"[Помилка Логування] Відмовлено в доступі до {JSON_PATH}: {log_err}")
            except IOError as log_err:
                print(f"[Помилка Логування] Не вдалося оновити JSON (IOError): {log_err}")
            except Exception as log_err:
                print(f"[Неочікувана помилка логування]: {log_err}")

        return result_bool

    return wrapper


@log_event
def login(username: str, password: str, users_db: list[dict[str, str]]) -> bool:
    """Автентифікує користувача, викидаючи відповідні винятки при некоректних даних."""
    if not isinstance(username, str) or not isinstance(password, str):
        raise TypeError("Логін та пароль повинні бути строками.")

    if not isinstance(users_db, list):
        raise TypeError("База даних користувачів повинна бути списком (list).")

    if not username or not password:
        raise ValueError("Логін або пароль не можуть бути порожніми.")

    try:
        target_hash = generate_hash(password, salt=SALT)
        for user in users_db:
            if user.get("username") == username:
                return user.get("password_hash") == target_hash
        return False
    except ValidationError:
        raise  # Прокидаємо вище, щоб декоратор це залогував
    except Exception as e:
        raise RuntimeError(f"Помилка під час ітерації по базі даних: {e}")


def run_task3():
    try:
        # Додано одного користувача з коротким паролем і одного з неправильним форматом для перевірки
        users_to_register = (
            ("admin_sec", "Complex#Pass12"),
            ("cyber_analyst", "SafePassword!99"),
            ("m_zhenchak", "SuperSecret#2026"),
            ("short_user", "123"),  # Викличе ValidationError
            ("wrong_format_user",),  # Викличе ValueError (помилка розпакування в create_users)
            12345  # Викличе TypeError у циклі розпакування
        )

        print("1. Збереження користувачів у CSV...")
        create_users(users_to_register)
        print("Дані оброблено. (Див. повідомлення про помилки вище)\n")

        print("2. Зчитування бази даних users.csv:")
        users_db = read_users_db()
        if users_db:
            print(f"{'Username':<20} | {'blake2b Hash':<40}")
            print("-" * 65)
            for u in users_db:
                short_hash = f"{u.get('password_hash', '')[:36]}..."
                print(f"{u.get('username', 'Unknown'):<20} | {short_hash:<40}")

        print("\n3. Тестування автентифікації та логування:")

        # Успішна спроба
        auth_ok = login("m_zhenchak", "SuperSecret#2026", users_db)
        print(f"Спроба 1 (вірні дані): {'Успішно' if auth_ok else 'Невдача'}")

        # Спроба з порожнім паролем (викличе ValueError)
        auth_empty = login("admin_sec", "", users_db)
        print(f"Спроба 2 (порожній пароль): {'Успішно' if auth_empty else 'Невдача'}")

        # Спроба з неправильним типом даних (викличе TypeError)
        auth_type = login("admin_sec", 12345, users_db)
        print(f"Спроба 3 (неправильний тип пароля): {'Успішно' if auth_type else 'Невдача'}")

    except Exception as general_err:
        print(f"[Критичний збій у програмі]: {general_err}")


if __name__ == "__main__":
    run_task3()