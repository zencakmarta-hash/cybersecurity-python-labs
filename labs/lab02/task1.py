import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone

PBKDF2_ITERATIONS = 100_000
SESSION_TIMEOUT_SEC = 900


class User:
    def __init__(
        self, username: str, email: str, role: str = "User", active: bool = True
    ):
        self.username = username
        self.role = role
        self.active = active
        self._email = ""
        self.email = email  # Виклик сеттера для валідації
        self.__password_salt = os.urandom(16)
        self.__password_hash = b""

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value):
        # Оновлений регулярний вираз, який дозволяє крапки, підкреслення та плюси
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.match(pattern, value):
            raise ValueError(f"Некоректний формат email: {value}")
        self._email = value

    def set_password(self, password: str) -> None:
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        if not self.__password_hash:
            return False
        computed_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS
        )
        return hmac.compare_digest(self.__password_hash, computed_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        status = "Active" if self.active else "Inactive"
        return f"User({self.username}, Email: {self.email}, Role: {self.role}, Status: {status})"


class Admin(User):
    def __init__(self, username: str, email: str, permissions: set[str] | None = None):
        super().__init__(username, email, role="Admin")
        self.permissions = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        base_str = super().__str__()
        perms = ", ".join(sorted(self.permissions)) if self.permissions else "None"
        return f"{base_str} | Permissions: [{perms}]"


class Session:
    def __init__(self, ip: str):
        self.ip = ip
        now = datetime.now(timezone.utc)
        self.login_time = now
        self.last_activity = now

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("Timeout повинен бути позитивним числом")
        now = datetime.now(timezone.utc)
        return (now - self.last_activity).total_seconds() < timeout_sec


@dataclass
class AuditRecord:
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    def __init__(self):
        self.records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc), username=username, action=action
        )
        self.records.append(record)

    def show_all(self) -> list[str]:
        return [
            f"[{r.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}] User: {r.username} | Action: {r.action}"
            for r in self.records
        ]


class UserAccount:
    def __init__(self, user: User):
        self.user = user
        self.session: Session | None = None
        self.audit_log = AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if self.user.username != username or not self.user.active:
            self.audit_log.add_log(username, "login_failure")
            return False

        if self.user.check_password(password):
            self.session = Session(ip)
            self.session.touch()
            self.audit_log.add_log(username, "login_success")
            return True
        else:
            self.audit_log.add_log(username, "login_failure")
            return False

    def is_authenticated(self) -> bool:
        if self.session and self.session.is_active(SESSION_TIMEOUT_SEC):
            return True
        return False

    def logout(self) -> None:
        if self.user:
            self.audit_log.add_log(self.user.username, "logout")
        self.session = None

    def __getitem__(self, key: str):
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "audit_log":
            return self.audit_log
        else:
            raise KeyError(f"Ключ '{key}' не підтримується або є приватним.")

    def __setitem__(self, key: str, value):
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення повинно бути екземпляром User")
            self.user = value
        else:
            raise KeyError(f"Зміна атрибута '{key}' через [] заборонена.")
