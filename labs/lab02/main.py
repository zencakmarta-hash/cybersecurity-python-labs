import sys
from pathlib import Path
from labs.lab02.task1 import Admin, User, UserAccount
from labs.lab02.task2 import run_arp_audit


def run_demo():
    print("=== ДЕМОНСТРАЦІЯ ЗАВДАННЯ 1 (ООП Модель Безпеки) ===\n")

    # 1. Створення користувача та адміністратора
    user = User("john_doe", "john.doe@example.com")
    user.set_password("SecurePass123!")

    admin = Admin("alice_admin", "alice.admin@corp.com", permissions={"read", "write"})
    admin.grant_permission("delete")

    print(f"[+] Створено об'єкти:\n - {user}\n - {admin}\n")

    # 2. Перевірка валідації Email
    try:
        user.email = "bad_email_format"
    except ValueError as e:
        print(f"[!] Перехоплено помилку валідації Email: {e}")

    # 3. Авторизація та Сесії
    account = UserAccount(user)
    print("\n--- Спроба входу з невірним паролем ---")
    auth_fail = account.login("john_doe", "WrongPass", "192.168.1.50")
    print(f"Результат входу: {auth_fail} | Сесія активна: {account.is_authenticated()}")

    print("\n--- Спроба входу з вірним паролем ---")
    auth_success = account.login("john_doe", "SecurePass123!", "192.168.1.50")
    print(
        f"Результат входу: {auth_success} | Сесія активна: {account.is_authenticated()}"
    )

    # 4. Перевірка AuditLog
    account.logout()
    print("\n=== Записи Audit Log ===")
    for record in account["audit_log"].show_all():
        print(record)


def main():
    if len(sys.argv) < 2:
        print("Використання:")
        print("  python -m labs.lab02.main demo")
        print("  python -m labs.lab02.main analyze [аргументи task2]")
        sys.exit(1)

    command = sys.argv[1]

    if command == "demo":
        run_demo()
    elif command == "analyze":
        # Передаємо аргументи далі до CLI аналізатора ARP
        import argparse

        parser = argparse.ArgumentParser(prog="python -m labs.lab02.main analyze")
        parser.add_argument(
            "--arp-file",
            type=Path,
            default=Path("labs/lab02/data/data_v11/arp_table.csv"),
        )
        parser.add_argument(
            "--output-json",
            type=Path,
            default=Path("labs/lab02/data/arp_security_alerts.json"),
        )
        parser.add_argument("--detect-spoofing", action="store_true", default=True)
        parser.add_argument("--log-file", type=Path, default=None)

        args = parser.parse_args(sys.argv[2:])
        run_arp_audit(
            args.arp_file, args.output_json, args.detect_spoofing, args.log_file
        )
    else:
        print(f"Невідома команда: {command}")


if __name__ == "__main__":
    main()
