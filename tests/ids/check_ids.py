#!/usr/bin/env python3
"""
YARA Rule ID Check

Verifies that every YARA rule has exactly one "id" meta field containing a
UUID in canonical lowercase form (e.g. "0f5d3a4c-1b2e-4c3d-9e8f-123456789abc")
and that no id is used by more than one rule.

Usage: check_ids.py [rules_dir]   (default: ./yara)
"""

import re
import sys
import uuid
from collections import defaultdict
from pathlib import Path

import plyara

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def is_valid_uuid(value):
    if not isinstance(value, str) or not UUID_RE.match(value):
        return False
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def main():
    rules_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "./yara")
    files = sorted(p for p in rules_dir.rglob("*") if p.suffix.lower() in (".yar", ".yara") and p.is_file())
    if not files:
        print(f"ERROR: No YARA rules found in {rules_dir}")
        return 1

    errors = []
    ids = defaultdict(list)
    rule_count = 0

    for path in files:
        try:
            rules = plyara.Plyara().parse_string(path.read_text(encoding="utf-8", errors="surrogateescape"))
        except Exception as e:
            errors.append(f"{path}: cannot parse file: {e}")
            continue

        for rule in rules:
            rule_count += 1
            where = f"{path}:{rule['start_line']}: rule {rule['rule_name']}"
            values = [m["id"] for m in rule.get("metadata", []) if "id" in m]
            if not values:
                errors.append(f"{where}: missing 'id' meta field")
                continue
            if len(values) > 1:
                errors.append(f"{where}: multiple 'id' meta fields")
            for value in values:
                if is_valid_uuid(value):
                    ids[value].append(where)
                else:
                    errors.append(f"{where}: invalid 'id' {value!r} (expected lowercase UUID)")

    for value, locations in ids.items():
        if len(locations) > 1:
            errors.append(f"duplicate id {value} used by:\n    " + "\n    ".join(locations))

    print("=== YARA Rule ID Check ===")
    print(f"Files: {len(files)}, rules: {rule_count}")
    if errors:
        print(f"\n{len(errors)} error(s):")
        for e in errors:
            print(f"ERROR: {e}")
        return 1
    print("All rules have a valid and unique 'id'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
