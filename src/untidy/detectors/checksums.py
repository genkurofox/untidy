from __future__ import annotations


def luhn_valid(digits: str) -> bool:
    d = [int(c) for c in digits if c.isdigit()]
    if len(d) < 13 or len(d) > 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def ssn_valid(ssn: str) -> bool:
    digits = "".join(c for c in ssn if c.isdigit())
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in {"000", "666"} or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    return True


def routing_valid(digits: str) -> bool:
    d = [int(c) for c in digits if c.isdigit()]
    if len(d) != 9:
        return False
    checksum = (
        3 * (d[0] + d[3] + d[6])
        + 7 * (d[1] + d[4] + d[7])
        + 1 * (d[2] + d[5] + d[8])
    )
    return checksum % 10 == 0
