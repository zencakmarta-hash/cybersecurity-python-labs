# Вхідні дані 11 варіанту[cite: 1]
users = {
    "risk_manager": {
        "role": "risk_analyst",
        "clearance": 4,
        "department": "Risk Management",
        "active": True,
    },
    # [cite: 1]
    "business_analyst": {
        "role": "business_analyst",
        "clearance": 2,
        "department": "Business",
        "active": True,
    },
    # [cite: 1]
    "legal_counsel": {
        "role": "legal",
        "clearance": 3,
        "department": "Legal",
        "active": True,
    },  # [cite: 1]
    "contractor_dev": {
        "role": "contractor",
        "clearance": 2,
        "department": "Contract",
        "active": True,
    },  # [cite: 1]
    "obsolete_system": {
        "role": "legacy_system",
        "clearance": 1,
        "department": "Legacy",
        "active": False,
    },  # [cite: 1]
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
]  # [cite: 1]
security_levels = (
    "Public",
    "Internal Use",
    "Restricted",
    "Highly Restricted",
)  # [cite: 1]
blocked_users = {"obsolete_system", "contract_expired", "legal_hold"}  # [cite: 1]

for res_name, res_lvl in resources:
    print(f"Ресурс: {res_name} (Рівень: {security_levels[res_lvl - 1]})")  # [cite: 1]

for username in ["risk_manager", "contractor_dev", "obsolete_system", "unknown_user"]:
    for res_name, res_lvl in resources:
        if username not in users:  # [cite: 1]
            status = "DENY (User not found)"  # [cite: 1]
        elif username in blocked_users:  # [cite: 1]
            status = "DENY (User is blocked)"  # [cite: 1]
        elif not users[username]["active"]:  # [cite: 1]
            status = "DENY (Account inactive)"  # [cite: 1]
        elif users[username]["clearance"] >= res_lvl:  # [cite: 1]
            status = "ALLOW"  # [cite: 1]
        else:
            status = "DENY (Insufficient clearance)"  # [cite: 1]

        print(f"user={username} resource={res_name} -> {status}")  # [cite: 1]
