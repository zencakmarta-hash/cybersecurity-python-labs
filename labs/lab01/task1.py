import random

# Вхідні дані 11 варіанту[cite: 1]
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
]  # [cite: 1]
criteria = {
    "min_length": 7,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}  # [cite: 1]
forbidden_passwords = {
    "simple",
    "participant",
    "common123",
    "regular123",
    "normal123",
    "test",
}  # [cite: 1]

# Додавання дублікатів[cite: 1]
for _ in range(3):
    idx = random.randint(0, len(passwords) - 1)  # [cite: 1]
    passwords.append(passwords[idx])  # [cite: 1]


def analyze_password(pwd, all_pwds):
    length_ok = len(pwd) >= criteria["min_length"]  # [cite: 1]
    has_digit = (
        any(c.isdigit() for c in pwd) if criteria["require_digits"] else True
    )  # [cite: 1]
    has_upper = (
        any(c.isupper() for c in pwd) if criteria["require_upper"] else True
    )  # [cite: 1]
    has_special = (
        any(not c.isalnum() for c in pwd) if criteria["require_special"] else True
    )  # [cite: 1]

    all_criteria = has_digit and has_upper and has_special  # [cite: 1]
    is_unique = all_pwds.count(pwd) == 1  # [cite: 1]

    if pwd in forbidden_passwords or not length_ok:  # [cite: 1]
        return "Заборонений"  # [cite: 1]
    if (
        all_criteria and len(pwd) >= criteria["min_length"] + 4 and is_unique
    ):  # [cite: 1]
        return "Дуже сильний"  # [cite: 1]
    if all_criteria:  # [cite: 1]
        return "Сильний"  # [cite: 1]
    if has_digit or has_upper or has_special:  # [cite: 1]
        return "Середній"  # [cite: 1]
    return "Слабкий"  # [cite: 1]


print(f"{'Пароль':<20} | {'Надійність'}")
for p in passwords:
    print(f"{p:<20} | {analyze_password(p, passwords)}")
