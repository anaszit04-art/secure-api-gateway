from __future__ import annotations

import argparse
import re

from pathlib import Path


METRIC_PATTERN = re.compile(
    r"^"
    r"(?P<series>"
    r"(?P<name>[A-Za-z_:][A-Za-z0-9_:]*)"
    r"(?:\{[^}]*\})?"
    r")"
    r"\s+"
    r"(?P<value>"
    r"[-+]?"
    r"(?:"
    r"\d+(?:\.\d*)?"
    r"|"
    r"\.\d+"
    r")"
    r"(?:[eE][-+]?\d+)?"
    r")"
    r"(?:\s+\d+)?"
    r"$"
)


SELECTED_METRICS = frozenset(
    {
        "gateway_http_requests_total",
        "gateway_rate_limit_decisions_total",
        "gateway_upstream_requests_total",
        "gateway_upstream_resilience_events_total",
    }
)


def parse_metrics(
    path: Path,
) -> dict[str, float]:
    values: dict[str, float] = {}

    for raw_line in path.read_text(
        encoding="utf-8"
    ).splitlines():
        line = raw_line.strip()

        if (
            not line
            or line.startswith("#")
        ):
            continue

        match = METRIC_PATTERN.match(
            line
        )

        if match is None:
            continue

        metric_name = match.group(
            "name"
        )

        if (
            metric_name
            not in SELECTED_METRICS
        ):
            continue

        values[
            match.group("series")
        ] = float(
            match.group("value")
        )

    return values


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "before"
    )

    parser.add_argument(
        "after"
    )

    args = parser.parse_args()

    before = parse_metrics(
        Path(args.before)
    )

    after = parse_metrics(
        Path(args.after)
    )

    changed = False

    for series in sorted(
        set(before)
        | set(after)
    ):
        delta = (
            after.get(
                series,
                0.0,
            )
            - before.get(
                series,
                0.0,
            )
        )

        if delta <= 0:
            continue

        changed = True

        print(
            f"{series} +{delta:g}"
        )

    if not changed:
        print(
            "No positive selected metric deltas."
        )


if __name__ == "__main__":
    main()
