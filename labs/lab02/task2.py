import argparse
import csv
import json
import logging
import re
from dataclasses import asdict, dataclass
from pathlib import Path

# Регулярні вирази для перевірки IP та MAC
IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


@dataclass
class ArpEntry:
    ip: str
    mac: str
    interface: str
    entry_type: str


@dataclass
class ArpConflict:
    mac_address: str
    associated_ips: list[str]
    alert_message: str


def validate_ip(ip: str) -> bool:
    return bool(IP_REGEX.match(ip.strip()))


def validate_mac(mac: str) -> bool:
    return bool(MAC_REGEX.match(mac.strip()))


def parse_arp_table(file_path: Path) -> tuple[list[ArpEntry], int]:
    valid_entries = []
    invalid_count = 0

    if not file_path.exists():
        raise FileNotFoundError(f"Файл ARP-таблиці не знайдено: {file_path}")

    with file_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Очищення ключів і значень від пробілів
            clean_row = {k.strip(): v.strip() for k, v in row.items() if k and v}
            ip = clean_row.get("IP Address") or clean_row.get("IP")
            mac = clean_row.get("MAC Address") or clean_row.get("MAC")
            interface = clean_row.get("Interface", "N/A")
            entry_type = clean_row.get("Type", "N/A")

            if ip and mac and validate_ip(ip) and validate_mac(mac):
                valid_entries.append(ArpEntry(ip, mac, interface, entry_type))
            else:
                invalid_count += 1

    return valid_entries, invalid_count


def detect_arp_spoofing(entries: list[ArpEntry]) -> list[ArpConflict]:
    from collections import defaultdict

    mac_to_ips = defaultdict(set)
    for entry in entries:
        mac_to_ips[entry.mac.lower()].add(entry.ip)

    conflicts = []
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            ip_list = sorted(list(ips))
            conflict = ArpConflict(
                mac_address=mac,
                associated_ips=ip_list,
                alert_message=(
                    f"MAC Address Duplicate Conflict! MAC {mac} associated with "
                    f"MULTIPLE IP addresses: {', '.join(ip_list)}"
                ),
            )
            conflicts.append(conflict)

    return conflicts


def run_arp_audit(
    arp_file: Path, output_json: Path, detect_spoof: bool, log_file: Path | None = None
) -> None:
    # Налаштування логування
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s",
        handlers=handlers,
        force=True,
    )

    logging.info(f"Parsing ARP table snapshot from {arp_file}...")
    entries, invalid_count = parse_arp_table(arp_file)
    logging.info(f"Validated {len(entries) + invalid_count} IP/MAC entries.")

    print("\n=== Validated Entries Summary ===")
    print(f"Valid IP/MAC Pairs : {len(entries)}")
    print(f"Invalid Syntax     : {invalid_count}")

    conflicts = []
    if detect_spoof:
        conflicts = detect_arp_spoofing(entries)
        if conflicts:
            print("\n=== CRITICAL SECURITY ALERTS: ARP-SPOOFING DETECTED ===")
            for c in conflicts:
                logging.error(f"[ALERT] {c.alert_message}")
                print("[ALERT] MAC Address Duplicate Conflict!")
                print(
                    f"MAC Address: {c.mac_address} associated with MULTIPLE IP addresses:"
                )
                for ip in c.associated_ips:
                    print(f"  - {ip}")
                print(
                    "-> POSSIBLE MAN-IN-THE-MIDDLE / ARP-SPOOFING ATTACK IN PROGRESS!\n"
                )
        else:
            print("\n[INFO] No ARP spoofing conflicts detected.")

    # Збереження результатів у JSON
    report_data = {
        "summary": {
            "valid_entries": len(entries),
            "invalid_syntax": invalid_count,
            "conflicts_count": len(conflicts),
        },
        "conflicts": [asdict(c) for c in conflicts],
        "entries": [asdict(e) for e in entries],
    }

    output_json.parent.mkdir(parents=True, exist_ok=True)
    with output_json.open("w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)

    logging.info(f"Critical conflict logged to {output_json}")


def main():
    parser = argparse.ArgumentParser(
        description="Аудитор ARP-таблиць та виявлення ARP-Spoofing"
    )
    parser.add_argument(
        "--arp-file",
        type=Path,
        default=Path("labs/lab02/data/data_v11/arp_table.csv"),
        help="Шлях до файлу ARP-таблиці (CSV)",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=Path("labs/lab02/data/arp_security_alerts.json"),
        help="Шлях для збереження JSON-звіту",
    )
    parser.add_argument(
        "--detect-spoofing",
        action="store_true",
        default=True,
        help="Увімкнути детектор ARP-Spoofing",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="Шлях до лог-файлу",
    )

    args = parser.parse_args()
    run_arp_audit(args.arp_file, args.output_json, args.detect_spoofing, args.log_file)


if __name__ == "__main__":
    main()
