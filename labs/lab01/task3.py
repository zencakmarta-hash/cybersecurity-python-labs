import hashlib
import csv
import json
import os
import datetime


class ValidationError(Exception):
    pass  # [cite: 1]


def log_event(func):  # [cite: 1]
    def wrapper(username, password):
        result = "success"
        try:
            res = func(username, password)
            if not res:
                result = "failure"
        except Exception:
            result = "failure"
            raise
        finally:
            log_entry = {
                "event": "login",  # [cite: 1]
                "user": username,  # [cite: 1]
                "result": result,  # [cite: 1]
                "timestamp": datetime.datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),  # [cite: 1]
            }
            os.makedirs("data", exist_ok=True)
            with open("data/log.json", "a") as f:  # [cite: 1]
                f.write(json.dumps(log_entry) + "\n")
        return res

    return wrapper


def generate_hash(password: str, salt: str = "00000") -> str:  # [cite: 1]
    if not password or not salt:
        raise ValueError("Пароль або сіль порожні")  # [cite: 1]
    if len(password) < 12:  # Мінімальна довжина варіанту 11[cite: 1]
        raise ValidationError("Пароль надто короткий")  # [cite: 1]
    return hashlib.blake2b(
        (password + salt).encode()
    ).hexdigest()  # Хеш варіанту 11[cite: 1]


def create_user(username, password):  # [cite: 1]
    return (username, generate_hash(password, "00011"))  # Сіль варіанту 11[cite: 1]


def create_users(users_list):  # [cite: 1]
    os.makedirs("data", exist_ok=True)
    with open("data/users.csv", "w", newline="") as f:  # [cite: 1]
        writer = csv.writer(f)
        for u, p in users_list:
            try:
                writer.writerow(create_user(u, p))
            except Exception:
                pass


@log_event
def login(username: str, password: str) -> bool:  # [cite: 1]
    if not username or not password:
        raise ValueError("Логін чи пароль порожні")  # [cite: 1]

    with open("data/users.csv", "r") as f:
        for row in csv.reader(f):
            if row and row[0] == username:
                return row[1] == generate_hash(password, "00011")
    return False


# Запуск
users_to_register = [("admin", "SuperSecurePass123"), ("user", "Short")]  # [cite: 1]
create_users(users_to_register)
