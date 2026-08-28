from __future__ import annotations

import argparse
import asyncio
import json
import math
import secrets

from collections import Counter
from pathlib import Path
from time import perf_counter
from typing import Any

import httpx


DEFAULT_BASE_URL = (
    "http://127.0.0.1:8000"
)

DEFAULT_TIMEOUT_SECONDS = 12.0

SESSION_FILE_MODE = 0o600

BENCHMARK_USERNAME_PREFIX = (
    "phase7load"
)


def parse_status_set(
    raw_value: str,
) -> set[int]:
    values: set[int] = set()

    for item in raw_value.split(","):
        item = item.strip()

        if not item:
            continue

        values.add(
            int(item)
        )

    return values


def percentile(
    values: list[float],
    percentile_value: float,
) -> float:
    if not values:
        return 0.0

    ordered = sorted(
        values
    )

    index = (
        math.ceil(
            percentile_value
            * len(ordered)
        )
        - 1
    )

    index = max(
        0,
        min(
            index,
            len(ordered) - 1,
        ),
    )

    return ordered[
        index
    ]


def load_session_token(
    path: Path,
) -> str:
    payload = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    token = payload.get(
        "access_token"
    )

    if (
        not isinstance(token, str)
        or not token
    ):
        raise RuntimeError(
            "Session file does not contain "
            "a valid access token."
        )

    return token


async def create_session(
    *,
    base_url: str,
    session_file: Path,
) -> None:
    username = (
        BENCHMARK_USERNAME_PREFIX
        + secrets.token_hex(6)
    )

    password = secrets.token_urlsafe(
        24
    )

    timeout = httpx.Timeout(
        DEFAULT_TIMEOUT_SECONDS
    )

    async with httpx.AsyncClient(
        base_url=base_url,
        timeout=timeout,
        follow_redirects=False,
    ) as client:
        registration = await client.post(
            "/auth/register",
            json={
                "username": username,
                "password": password,
            },
        )

        if registration.status_code not in {
            200,
            201,
        }:
            raise RuntimeError(
                "Benchmark registration failed "
                f"with HTTP "
                f"{registration.status_code}."
            )

        registration_payload = (
            registration.json()
        )

        token_response = await client.post(
            "/auth/token",
            data={
                "grant_type": "password",
                "username": username,
                "password": password,
            },
        )

        if token_response.status_code != 200:
            raise RuntimeError(
                "Benchmark authentication failed "
                f"with HTTP "
                f"{token_response.status_code}."
            )

        token_payload = (
            token_response.json()
        )

        access_token = token_payload.get(
            "access_token"
        )

        if (
            not isinstance(
                access_token,
                str,
            )
            or not access_token
        ):
            raise RuntimeError(
                "Authentication response does not "
                "contain an access token."
            )

    session_payload = {
        "username": username,
        "user_id": (
            registration_payload.get(
                "id"
            )
        ),
        "access_token": access_token,
    }

    session_file.write_text(
        json.dumps(
            session_payload,
            indent=2,
        ),
        encoding="utf-8",
    )

    session_file.chmod(
        SESSION_FILE_MODE
    )

    print(
        "Benchmark session created"
    )

    print(
        "Username:",
        username,
    )

    print(
        "Session file:",
        session_file,
    )

    print(
        "Token: NOT DISPLAYED"
    )


async def execute_load(
    *,
    base_url: str,
    path: str,
    total_requests: int,
    concurrency: int,
    warmup_requests: int,
    session_file: Path | None,
) -> dict[str, Any]:
    headers: dict[str, str] = {}

    if session_file is not None:
        token = load_session_token(
            session_file
        )

        headers[
            "Authorization"
        ] = (
            f"Bearer {token}"
        )

    limits = httpx.Limits(
        max_connections=concurrency,
        max_keepalive_connections=(
            concurrency
        ),
    )

    timeout = httpx.Timeout(
        DEFAULT_TIMEOUT_SECONDS
    )

    status_counts: Counter[int] = (
        Counter()
    )

    transport_errors: Counter[str] = (
        Counter()
    )

    latencies: list[float] = []

    response_headers: dict[
        str,
        dict[str, str],
    ] = {}

    async with httpx.AsyncClient(
        base_url=base_url,
        headers=headers,
        limits=limits,
        timeout=timeout,
        follow_redirects=False,
    ) as client:

        for _ in range(
            warmup_requests
        ):
            try:
                await client.get(
                    path
                )
            except httpx.RequestError:
                pass

        queue: asyncio.Queue[int] = (
            asyncio.Queue()
        )

        for request_number in range(
            total_requests
        ):
            queue.put_nowait(
                request_number
            )

        async def worker() -> None:
            while True:
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    return

                started_at = (
                    perf_counter()
                )

                try:
                    response = await client.get(
                        path
                    )

                except httpx.RequestError as exc:
                    transport_errors[
                        type(exc).__name__
                    ] += 1

                else:
                    elapsed = (
                        perf_counter()
                        - started_at
                    )

                    latencies.append(
                        elapsed
                    )

                    status_counts[
                        response.status_code
                    ] += 1

                    status_key = str(
                        response.status_code
                    )

                    if (
                        status_key
                        not in response_headers
                    ):
                        interesting_headers = {}

                        for header_name in (
                            "x-ratelimit-limit",
                            "x-ratelimit-remaining",
                            "x-ratelimit-reset",
                            "retry-after",
                            "x-request-id",
                        ):
                            header_value = (
                                response.headers.get(
                                    header_name
                                )
                            )

                            if (
                                header_value
                                is not None
                            ):
                                interesting_headers[
                                    header_name
                                ] = header_value

                        response_headers[
                            status_key
                        ] = (
                            interesting_headers
                        )

                finally:
                    queue.task_done()

        started_at = perf_counter()

        workers = [
            asyncio.create_task(
                worker()
            )
            for _ in range(
                concurrency
            )
        ]

        await asyncio.gather(
            *workers
        )

        total_duration = (
            perf_counter()
            - started_at
        )

    successful_transport_requests = (
        sum(
            status_counts.values()
        )
    )

    summary: dict[str, Any] = {
        "target": path,
        "requests": total_requests,
        "concurrency": concurrency,
        "warmup_requests": (
            warmup_requests
        ),
        "duration_seconds": (
            total_duration
        ),
        "requests_per_second": (
            total_requests
            / total_duration
            if total_duration > 0
            else 0.0
        ),
        "http_responses": (
            successful_transport_requests
        ),
        "status_codes": {
            str(status): count
            for status, count
            in sorted(
                status_counts.items()
            )
        },
        "transport_errors": dict(
            transport_errors
        ),
        "latency_ms": {
            "min": (
                min(latencies) * 1000
                if latencies
                else 0.0
            ),
            "mean": (
                (
                    sum(latencies)
                    / len(latencies)
                )
                * 1000
                if latencies
                else 0.0
            ),
            "p50": (
                percentile(
                    latencies,
                    0.50,
                )
                * 1000
            ),
            "p95": (
                percentile(
                    latencies,
                    0.95,
                )
                * 1000
            ),
            "p99": (
                percentile(
                    latencies,
                    0.99,
                )
                * 1000
            ),
            "max": (
                max(latencies) * 1000
                if latencies
                else 0.0
            ),
        },
        "sample_headers": (
            response_headers
        ),
    }

    return summary


def print_summary(
    summary: dict[str, Any],
) -> None:
    latency = summary[
        "latency_ms"
    ]

    print(
        "\n=== LOAD RESULT ==="
    )

    print(
        "Target:",
        summary["target"],
    )

    print(
        "Requests:",
        summary["requests"],
    )

    print(
        "Concurrency:",
        summary["concurrency"],
    )

    print(
        "Duration:",
        (
            f"{summary['duration_seconds']:.3f}s"
        ),
    )

    print(
        "Throughput:",
        (
            f"{summary['requests_per_second']:.2f}"
            " req/s"
        ),
    )

    print(
        "Status codes:",
        summary["status_codes"],
    )

    print(
        "Transport errors:",
        summary["transport_errors"],
    )

    print(
        "Latency ms:"
    )

    for name in (
        "min",
        "mean",
        "p50",
        "p95",
        "p99",
        "max",
    ):
        print(
            f"  {name:>4}: "
            f"{latency[name]:.2f}"
        )

    print(
        "Sample headers:"
    )

    for (
        status_code,
        headers,
    ) in (
        summary[
            "sample_headers"
        ].items()
    ):
        print(
            f"  HTTP {status_code}:",
            headers,
        )


async def run_load_command(
    args: argparse.Namespace,
) -> None:
    session_file = (
        Path(
            args.session_file
        )
        if args.session_file
        else None
    )

    summary = await execute_load(
        base_url=args.base_url,
        path=args.path,
        total_requests=args.total,
        concurrency=args.concurrency,
        warmup_requests=args.warmup,
        session_file=session_file,
    )

    print_summary(
        summary
    )

    output_path = (
        Path(args.output)
        if args.output
        else None
    )

    if output_path is not None:
        output_path.write_text(
            json.dumps(
                summary,
                indent=2,
            ),
            encoding="utf-8",
        )

        print(
            "Result file:",
            output_path,
        )

    allowed = parse_status_set(
        args.allow_status
    )

    required = parse_status_set(
        args.require_status
    )

    observed = {
        int(status_code)
        for status_code
        in summary[
            "status_codes"
        ]
    }

    unexpected = (
        observed - allowed
    )

    missing = (
        required - observed
    )

    transport_errors = summary[
        "transport_errors"
    ]

    if unexpected:
        raise RuntimeError(
            "Unexpected HTTP status codes: "
            + ", ".join(
                str(value)
                for value
                in sorted(unexpected)
            )
        )

    if missing:
        raise RuntimeError(
            "Required HTTP status codes "
            "were not observed: "
            + ", ".join(
                str(value)
                for value
                in sorted(missing)
            )
        )

    if transport_errors:
        raise RuntimeError(
            "Transport errors occurred during "
            "the benchmark."
        )

    print(
        "Acceptance: PASS"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Bounded Phase 7 load and resilience "
            "probe for the Secure API Gateway."
        )
    )

    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
    )

    subparsers = (
        parser.add_subparsers(
            dest="command",
            required=True,
        )
    )

    session_parser = (
        subparsers.add_parser(
            "session"
        )
    )

    session_parser.add_argument(
        "--session-file",
        required=True,
    )

    load_parser = (
        subparsers.add_parser(
            "run"
        )
    )

    load_parser.add_argument(
        "--path",
        required=True,
    )

    load_parser.add_argument(
        "--total",
        type=int,
        required=True,
    )

    load_parser.add_argument(
        "--concurrency",
        type=int,
        required=True,
    )

    load_parser.add_argument(
        "--warmup",
        type=int,
        default=0,
    )

    load_parser.add_argument(
        "--session-file",
    )

    load_parser.add_argument(
        "--allow-status",
        default="200",
    )

    load_parser.add_argument(
        "--require-status",
        default="",
    )

    load_parser.add_argument(
        "--output",
    )

    return parser


def validate_load_arguments(
    args: argparse.Namespace,
) -> None:
    if args.command != "run":
        return

    if args.total < 1:
        raise ValueError(
            "--total must be positive."
        )

    if args.concurrency < 1:
        raise ValueError(
            "--concurrency must be positive."
        )

    if (
        args.concurrency
        > args.total
    ):
        raise ValueError(
            "--concurrency cannot exceed "
            "--total."
        )

    if args.warmup < 0:
        raise ValueError(
            "--warmup cannot be negative."
        )


def main() -> None:
    parser = build_parser()

    args = parser.parse_args()

    validate_load_arguments(
        args
    )

    if args.command == "session":
        asyncio.run(
            create_session(
                base_url=args.base_url,
                session_file=Path(
                    args.session_file
                ),
            )
        )

        return

    asyncio.run(
        run_load_command(
            args
        )
    )


if __name__ == "__main__":
    main()
