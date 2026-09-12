"""Завдання 2: Багаторівнева система контролю доступу."""


def check_user_access(
    username: str, resource_level: int, users: dict, blocked_users: set
) -> tuple[bool, str]:
    """Перевіряє доступ користувача до ресурсу за алгоритмом безпеки."""
    if username not in users:
        return False, "User not found"

    if username in blocked_users:
        return False, "User is blocked"

    user_info = users[username]
    if not user_info.get("active", False):
        return False, "Account inactive"

    if user_info.get("clearance", 0) >= resource_level:
        return True, ""

    return False, "Insufficient clearance"


def run_task2():
    """Основна функція виконання Завдання 2 (Варіант 11)."""
    # 1. Вхідні дані варіанта 11
    users = {
        "risk_manager": {
            "role": "risk_analyst",
            "clearance": 4,
            "department": "Risk Management",
            "active": True,
        },
        "business_analyst": {
            "role": "business_analyst",
            "clearance": 2,
            "department": "Business",
            "active": True,
        },
        "legal_counsel": {
            "role": "legal",
            "clearance": 3,
            "department": "Legal",
            "active": True,
        },
        "contractor_dev": {
            "role": "contractor",
            "clearance": 2,
            "department": "Contract",
            "active": True,
        },
        "obsolete_system": {
            "role": "legacy_system",
            "clearance": 1,
            "department": "Legacy",
            "active": False,
        },
    }

    resources = [
        ("risk_registers", 4),
        ("business_requirements", 2),
        ("legal_documents", 3),
        ("contract_code", 2),
        ("governance_framework", 4),
        ("meeting_minutes", 1),
        ("regulatory_reports", 3),
        ("executive_dashboards", 4),
        ("project_specs", 2),
        ("public_statements", 1),
    ]

    security_levels = (
        "Public",
        "Internal Use",
        "Restricted",
        "Highly Restricted",
    )

    blocked_users = {"obsolete_system", "contract_expired", "legal_hold"}

    # 2. Виведення списку ресурсів із текстовими мітками рівня безпеки
    print("Список усіх ресурсів системи:")
    for res_name, res_lvl in resources:
        level_label = security_levels[res_lvl - 1]
        print(f"  Ресурс: {res_name:<24} | Рівень: {level_label}")

    # 3-4. Перевірка доступу та виведення в заданому форматі
    print("\nРезультати перевірки доступу:")
    for username in users:
        for res_name, res_lvl in resources:
            is_allowed, reason = check_user_access(
                username, res_lvl, users, blocked_users
            )

            if is_allowed:
                decision = "ALLOW"
            else:
                decision = f"DENY ({reason})"

            print(f"user={username} resource={res_name} -> {decision}")


if __name__ == "__main__":
    run_task2()
