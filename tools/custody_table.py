#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Enumerate theft and loss outcomes for the NC0 2-of-3 share custody layout. Apache-2.0.

Each share is usable only when its ciphertext and its passphrase paper are
both present. For every non-empty set of places, the table reports how many
shares a thief who takes exactly those places can use, and how many shares
the owner can still recover if exactly those places are lost.

The script prints a Markdown table for the owner runbook. It exits non-zero
if the layout breaks either rule: every single theft yields fewer shares than
the threshold, and every single loss leaves at least the threshold.
"""

from itertools import combinations
import sys

THRESHOLD = 2

PLACES: dict[str, frozenset[str]] = {
    "Site 1": frozenset({"stick A", "paper A"}),
    "Site 2": frozenset({"stick B", "paper B"}),
    "P": frozenset({"paper C"}),
    "Cloud": frozenset({"cloud C"}),
}

SHARES: dict[str, tuple[str, str]] = {
    "A": ("stick A", "paper A"),
    "B": ("stick B", "paper B"),
    "C": ("cloud C", "paper C"),
}


def usable(items: frozenset[str]) -> list[str]:
    return sorted(name for name, (blob, paper) in SHARES.items() if blob in items and paper in items)


def rows(places: dict[str, frozenset[str]]) -> list[tuple[tuple[str, ...], list[str], list[str]]]:
    names = list(places)
    result = []
    for size in range(1, len(names) + 1):
        for chosen in combinations(names, size):
            taken = frozenset().union(*(places[name] for name in chosen))
            kept = frozenset().union(*(places[name] for name in names if name not in chosen))
            result.append((chosen, usable(taken), usable(kept)))
    return result


def violations(places: dict[str, frozenset[str]]) -> list[str]:
    problems = []
    for chosen, stolen, kept in rows(places):
        if len(chosen) != 1:
            continue
        if len(stolen) >= THRESHOLD:
            problems.append(f"theft of {chosen[0]} yields {len(stolen)} shares")
        if len(kept) < THRESHOLD:
            problems.append(f"loss of {chosen[0]} leaves {len(kept)} shares")
    return problems


def table(places: dict[str, frozenset[str]]) -> str:
    def cell(shares: list[str]) -> str:
        return f"{len(shares)} ({', '.join(shares)})" if shares else "0"

    lines = ["| Places | Theft: usable shares | Loss: shares left |", "|---|---|---|"]
    for chosen, stolen, kept in rows(places):
        lines.append(f"| {' + '.join(chosen)} | {cell(stolen)} | {cell(kept)} |")
    return "\n".join(lines)


def main() -> int:
    print(table(PLACES))
    problems = violations(PLACES)
    for problem in problems:
        print(f"custody rule violated: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
