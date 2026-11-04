"""Input validation helpers used by the web API."""
import ipaddress
from datetime import datetime


def valid_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(str(text).strip())
        return True
    except ValueError:
        return False


def valid_date(text: str) -> bool:
    try:
        datetime.strptime(str(text).strip(), "%Y-%m-%d")
        return True
    except ValueError:
        return False


def valid_int(value, low: int, high: int) -> bool:
    try:
        return low <= int(value) <= high
    except (TypeError, ValueError):
        return False
