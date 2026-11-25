"""Sentinela: analisador offline de logs de autenticação para estudos de Blue Team."""
import argparse
import csv
from collections.abc import Callable
from datetime import datetime, timedelta
import json
from pathlib import Path
import sys
from typing import Literal, TypeGuard, TypedDict


CsvField = Literal[
    "rule", "severity", "title", "description", "source_ip",
    "username", "accounts", "first_seen", "last_seen", "observed_count",
]


class Event(TypedDict):
    timestamp: str
    source_ip: str
    username: str
    event: Literal["login_failed", "login_success"]
    _time: datetime


class Alert(TypedDict):
    rule: Literal["AUTH-001", "AUTH-002", "AUTH-003"]
    severity: Literal["medium", "high"]
    title: str
    description: str
    source_ip: str
    username: str | None
    accounts: list[str]
    first_seen: str
    last_seen: str
    observed_count: int


class ReportSummary(TypedDict):
    total_events: int
    failed_logins: int
    successful_logins: int
    alerts: int


class Report(TypedDict):
    summary: ReportSummary
    alerts: list[Alert]


def is_json_object(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict)


def read_events(path: Path) -> list[Event]:
    events: list[Event] = []
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        raise ValueError(f"Não foi possível abrir o arquivo: {exc}") from exc
    required = {"timestamp", "source_ip", "username", "event"}
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            item: object = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Linha {number}: JSON inválido ({exc.msg}).") from exc
        if not is_json_object(item) or not required <= item.keys():
            raise ValueError(f"Linha {number}: são necessários timestamp, source_ip, username e event.")
        raw_timestamp = item["timestamp"]
        raw_source_ip = item["source_ip"]
        raw_username = item["username"]
        raw_event = item["event"]
        if raw_event == "login_failed":
            event: Literal["login_failed", "login_success"] = "login_failed"
        elif raw_event == "login_success":
            event = "login_success"
        else:
            raise ValueError(f"Linha {number}: event deve ser login_failed ou login_success.")
        if not isinstance(raw_timestamp, str) or not raw_timestamp.strip():
            raise ValueError(f"Linha {number}: todos os campos devem ser textos não vazios.")
        if not isinstance(raw_source_ip, str) or not raw_source_ip.strip():
            raise ValueError(f"Linha {number}: todos os campos devem ser textos não vazios.")
        if not isinstance(raw_username, str) or not raw_username.strip():
            raise ValueError(f"Linha {number}: todos os campos devem ser textos não vazios.")
        timestamp = raw_timestamp
        source_ip = raw_source_ip
        username = raw_username
        try:
            event_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Linha {number}: timestamp ISO 8601 inválido.") from exc
        if event_time.tzinfo is None:
            raise ValueError(f"Linha {number}: inclua o fuso horário, por exemplo Z ou -03:00.")
        events.append({
            "timestamp": timestamp,
            "source_ip": source_ip,
            "username": username,
            "event": event,
            "_time": event_time,
        })
    return sorted(events, key=lambda event: event["_time"])


def threshold_windows(
    items: list[Event],
    minutes: int,
    limit: int,
    measure: Callable[[list[Event]], int],
) -> list[list[Event]]:
    result: list[list[Event]] = []
    start = 0
    active = False
    period = timedelta(minutes=minutes)
    for end in range(len(items)):
        while items[end]["_time"] - items[start]["_time"] > period:
            start += 1
        current: list[Event] = items[start:end + 1]
        if measure(current) >= limit:
            if not active:
                result.append(current)
            active = True
        else:
            active = False
    return result


def alert(
    rule: Literal["AUTH-001", "AUTH-002", "AUTH-003"],
    severity: Literal["medium", "high"],
    title: str,
    items: list[Event],
    description: str,
) -> Alert:
    last = items[-1]
    return {"rule": rule, "severity": severity, "title": title,
            "description": description, "source_ip": last["source_ip"],
            "username": None if rule == "AUTH-002" else last["username"],
            "accounts": sorted({e["username"] for e in items}) if rule == "AUTH-002" else [],
            "first_seen": items[0]["timestamp"], "last_seen": last["timestamp"],
            "observed_count": len(items)}


def count_distinct_accounts(group: list[Event]) -> int:
    return len({event["username"] for event in group})


def analyze(
    events: list[Event],
    minutes: int,
    failure_limit: int,
    spray_limit: int,
) -> Report:
    failed = [e for e in events if e["event"] == "login_failed"]
    successes = [e for e in events if e["event"] == "login_success"]
    by_user: dict[tuple[str, str], list[Event]] = {}
    by_ip: dict[str, list[Event]] = {}
    all_by_user: dict[tuple[str, str], list[Event]] = {}
    for e in events:
        key = (e["source_ip"], e["username"])
        all_by_user.setdefault(key, []).append(e)
        if e["event"] == "login_failed":
            by_user.setdefault(key, []).append(e)
            by_ip.setdefault(e["source_ip"], []).append(e)
    alerts: list[Alert] = []
    for (_, username), group in by_user.items():
        for window in threshold_windows(group, minutes, failure_limit, len):
            alerts.append(alert("AUTH-001", "medium", "Muitas falhas de autenticação", window,
                                f"{len(window)} falhas para a conta {username} em até {minutes} minutos."))
    for _, group in by_ip.items():
        for window in threshold_windows(group, minutes, spray_limit, count_distinct_accounts):
            a = alert("AUTH-002", "high", "Possível password spraying", window,
                      f"Tentativas contra {count_distinct_accounts(window)} contas diferentes em até {minutes} minutos.")
            a["observed_count"] = count_distinct_accounts(window)
            alerts.append(a)
    for success in successes:
        recent = [e for e in all_by_user[(success["source_ip"], success["username"])]
                  if e["event"] == "login_failed" and
                  timedelta(0) <= success["_time"] - e["_time"] <= timedelta(minutes=minutes)]
        if len(recent) >= 3:
            alerts.append(alert("AUTH-003", "high", "Login após várias falhas", recent + [success],
                                f"Login bem-sucedido após {len(recent)} falhas recentes."))
    alerts.sort(key=lambda a: datetime.fromisoformat(a["last_seen"].replace("Z", "+00:00")))
    return {"summary": {"total_events": len(events), "failed_logins": len(failed),
                         "successful_logins": len(successes), "alerts": len(alerts)}, "alerts": alerts}


def safe_csv_value(value: str) -> str:
    if value.lstrip(" \t\r\n")[:1] in {"=", "+", "-", "@"}:
        return "'" + value
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Analisador defensivo de logs de autenticação.")
    parser.add_argument("--input", required=True, type=Path, help="Arquivo JSON Lines de eventos.")
    parser.add_argument("--output", type=Path, help="Arquivo de relatório (padrão: tela).")
    parser.add_argument("--format", choices=("json", "csv"), default="json")
    parser.add_argument("--window-minutes", type=int, default=10)
    parser.add_argument("--failure-threshold", type=int, default=5)
    parser.add_argument("--spray-threshold", type=int, default=5)
    args = parser.parse_args()
    if min(args.window_minutes, args.failure_threshold, args.spray_threshold) < 1:
        parser.error("minutos e limiares devem ser pelo menos 1")
    try:
        report = analyze(read_events(args.input), args.window_minutes, args.failure_threshold, args.spray_threshold)
        if args.format == "json":
            output = json.dumps(report, ensure_ascii=False, indent=2)
        else:
            from io import StringIO
            stream = StringIO()
            columns: tuple[CsvField, ...] = (
                "rule", "severity", "title", "description", "source_ip",
                "username", "accounts", "first_seen", "last_seen",
                "observed_count",
            )
            writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for item in report["alerts"]:
                row: dict[CsvField, object] = {
                    "rule": safe_csv_value(item["rule"]),
                    "severity": safe_csv_value(item["severity"]),
                    "title": safe_csv_value(item["title"]),
                    "description": safe_csv_value(item["description"]),
                    "source_ip": safe_csv_value(item["source_ip"]),
                    "username": (
                        safe_csv_value(item["username"])
                        if item["username"] is not None else ""
                    ),
                    "accounts": safe_csv_value(
                        json.dumps(item["accounts"], ensure_ascii=False)
                    ),
                    "first_seen": safe_csv_value(item["first_seen"]),
                    "last_seen": safe_csv_value(item["last_seen"]),
                    "observed_count": item["observed_count"],
                }
                writer.writerow(row)
            output = stream.getvalue()
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
    except (ValueError, OSError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
