"""Sentinela: analisador offline de logs de autenticação para estudos de Blue Team."""
import argparse
import csv
from bisect import bisect_left, bisect_right
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import sys
from typing import Literal, TypeGuard, TypedDict


EventName = Literal[
    "login_failed", "login_success", "mfa_failed", "mfa_success",
]
RuleName = Literal[
    "AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-005",
]
Severity = Literal["medium", "high"]
CsvField = Literal[
    "record_type", "rule", "severity", "title", "description", "source_ip",
    "username", "accounts", "first_seen", "last_seen", "first_seen_utc",
    "last_seen_utc", "observed_count", "evidence_count", "evidence_json",
    "input_sha256", "ruleset_version", "report_metadata_json",
]


class Event(TypedDict):
    timestamp: str
    source_ip: str
    source_ip_normalized: str
    username: str
    event: EventName
    event_id: str
    source_line: int
    system: str | None
    auth_method: str | None
    mfa: bool | None
    device: str | None
    account_status: Literal["active", "disabled", "unknown"] | None
    privileged: bool | None
    _time: datetime


class EvidenceEvent(TypedDict):
    event_id: str
    source_line: int
    timestamp: str
    timestamp_utc: str
    source_ip: str
    source_ip_normalized: str
    username: str
    event: EventName
    system: str | None
    auth_method: str | None
    mfa: bool | None
    device: str | None
    account_status: str | None
    privileged: bool | None


class Alert(TypedDict):
    rule: RuleName
    severity: Severity
    title: str
    description: str
    source_ip: str
    username: str | None
    accounts: list[str]
    first_seen: str
    last_seen: str
    first_seen_utc: str
    last_seen_utc: str
    observed_count: int
    evidence: list[EvidenceEvent]


class ReportSummary(TypedDict):
    total_events: int
    failed_logins: int
    successful_logins: int
    mfa_failures: int
    disabled_account_attempts: int
    alerts: int


class RuleInfo(TypedDict):
    severity: Severity
    description: str
    detection: str


class ReportMetadata(TypedDict):
    schema_version: str
    tool_version: str
    ruleset_version: str
    source_file_name: str
    input_sha256: str
    analysis_time_utc: str
    thresholds: dict[str, int]
    rules: dict[str, RuleInfo]
    limitations: list[str]


class Report(TypedDict):
    metadata: ReportMetadata
    summary: ReportSummary
    alerts: list[Alert]


class DuplicateJsonKeyError(ValueError):
    pass


RULESET_VERSION = "1.0"
TOOL_VERSION = "0.2.0"
RULES: dict[str, RuleInfo] = {
    "AUTH-001": {
        "severity": "medium",
        "description": "Várias falhas de login para a mesma conta e origem.",
        "detection": "Falhas iguais ou acima de failure_threshold na janela configurada.",
    },
    "AUTH-002": {
        "severity": "high",
        "description": "Uma origem tentou autenticar-se em várias contas.",
        "detection": "Contas distintas iguais ou acima de spray_threshold na janela.",
    },
    "AUTH-003": {
        "severity": "high",
        "description": "Login bem-sucedido após falhas recentes para a mesma conta e origem.",
        "detection": "Falhas iguais ou acima de success_after_failures_threshold.",
    },
    "AUTH-004": {
        "severity": "medium",
        "description": "Tentativa de autenticação contra uma conta marcada como desativada.",
        "detection": "Evento de login com account_status igual a disabled.",
    },
    "AUTH-005": {
        "severity": "medium",
        "description": "Várias falhas de MFA para a mesma conta e origem.",
        "detection": "Falhas de MFA iguais ou acima de mfa_failure_threshold na janela.",
    },
}


def is_json_object(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict)


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(key)
        result[key] = value
    return result


def _optional_text(item: dict[str, object], key: str, line: int) -> str | None:
    value = item.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Linha {line}: {key} deve ser um texto não vazio.")
    return value


def _read_input_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ValueError(f"Não foi possível abrir o arquivo: {exc}") from exc


def _parse_events(content: bytes) -> list[Event]:
    try:
        lines = content.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("O arquivo de entrada não está codificado em UTF-8.") from exc

    events: list[Event] = []
    required = {"timestamp", "source_ip", "username", "event"}
    valid_statuses = {"active", "disabled", "unknown"}

    for number, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            item: object = json.loads(
                line, object_pairs_hook=_reject_duplicate_json_keys,
            )
        except DuplicateJsonKeyError as exc:
            raise ValueError(
                f"Linha {number}: chave JSON duplicada ({exc})."
            ) from exc
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Linha {number}: JSON inválido ({exc.msg})."
            ) from exc
        if not is_json_object(item) or not required <= item.keys():
            raise ValueError(
                f"Linha {number}: são necessários timestamp, source_ip, "
                "username e event."
            )

        for key in item:
            normalized_key = "".join(
                character for character in key.casefold() if character.isalnum()
            )
            if any(indicator in normalized_key for indicator in (
                "password", "passwd", "secret", "token", "cookie",
                "credential", "authorization", "bearer", "apikey",
                "privatekey", "signingkey", "encryptionkey",
            )):
                raise ValueError(
                    f"Linha {number}: remova o campo sensível {key!r} dos logs."
                )

        raw_event = item["event"]
        if raw_event == "login_failed":
            event_name: EventName = "login_failed"
        elif raw_event == "login_success":
            event_name = "login_success"
        elif raw_event == "mfa_failed":
            event_name = "mfa_failed"
        elif raw_event == "mfa_success":
            event_name = "mfa_success"
        else:
            raise ValueError(
                f"Linha {number}: event deve ser login_failed, login_success, "
                "mfa_failed ou mfa_success."
            )

        timestamp = item["timestamp"]
        source_ip = item["source_ip"]
        username = item["username"]
        if not isinstance(timestamp, str) or not timestamp.strip():
            raise ValueError(
                f"Linha {number}: timestamp deve ser um texto não vazio."
            )
        if not isinstance(source_ip, str) or not source_ip.strip():
            raise ValueError(
                f"Linha {number}: source_ip deve ser um texto não vazio."
            )
        if not isinstance(username, str) or not username.strip():
            raise ValueError(
                f"Linha {number}: username deve ser um texto não vazio."
            )
        try:
            normalized_ip = str(ipaddress.ip_address(source_ip.strip()))
        except ValueError as exc:
            raise ValueError(
                f"Linha {number}: source_ip não é um endereço IP válido."
            ) from exc

        timestamp_value = (
            timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp
        )
        try:
            event_time = datetime.fromisoformat(timestamp_value)
        except ValueError as exc:
            raise ValueError(
                f"Linha {number}: timestamp ISO 8601 inválido."
            ) from exc
        if event_time.tzinfo is None or event_time.utcoffset() is None:
            raise ValueError(
                f"Linha {number}: inclua o fuso horário, por exemplo Z ou -03:00."
            )

        event_id = _optional_text(item, "event_id", number) or f"line:{number}"
        system = _optional_text(item, "system", number)
        auth_method = _optional_text(item, "auth_method", number)
        device = _optional_text(item, "device", number)
        account_status_value = _optional_text(item, "account_status", number)
        account_status: Literal["active", "disabled", "unknown"] | None = None
        if account_status_value is not None:
            if account_status_value not in valid_statuses:
                raise ValueError(
                    f"Linha {number}: account_status deve ser active, disabled "
                    "ou unknown."
                )
            if account_status_value == "active":
                account_status = "active"
            elif account_status_value == "disabled":
                account_status = "disabled"
            else:
                account_status = "unknown"

        mfa = item.get("mfa")
        if mfa is not None and not isinstance(mfa, bool):
            raise ValueError(f"Linha {number}: mfa deve ser booleano.")
        privileged = item.get("privileged")
        if privileged is not None and not isinstance(privileged, bool):
            raise ValueError(f"Linha {number}: privileged deve ser booleano.")

        events.append({
            "timestamp": timestamp,
            "source_ip": source_ip,
            "source_ip_normalized": normalized_ip,
            "username": username,
            "event": event_name,
            "event_id": event_id,
            "source_line": number,
            "system": system,
            "auth_method": auth_method,
            "mfa": mfa,
            "device": device,
            "account_status": account_status,
            "privileged": privileged,
            "_time": event_time.astimezone(timezone.utc),
        })
    return sorted(events, key=lambda event: event["_time"])


def read_events(path: Path) -> list[Event]:
    return _parse_events(_read_input_bytes(path))


def read_events_with_hash(path: Path) -> tuple[list[Event], str]:
    content = _read_input_bytes(path)
    return _parse_events(content), hashlib.sha256(content).hexdigest()


def _utc_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _evidence(item: Event) -> EvidenceEvent:
    return {
        "event_id": item["event_id"],
        "source_line": item["source_line"],
        "timestamp": item["timestamp"],
        "timestamp_utc": _utc_iso(item["_time"]),
        "source_ip": item["source_ip"],
        "source_ip_normalized": item["source_ip_normalized"],
        "username": item["username"],
        "event": item["event"],
        "system": item["system"],
        "auth_method": item["auth_method"],
        "mfa": item["mfa"],
        "device": item["device"],
        "account_status": item["account_status"],
        "privileged": item["privileged"],
    }


def count_distinct_accounts(items: list[Event]) -> int:
    return len({item["username"] for item in items})


def threshold_windows(
    items: list[Event],
    minutes: int,
    limit: int,
    measure: Callable[[list[Event]], int],
) -> list[list[Event]]:
    episodes: list[list[Event]] = []
    episode: list[Event] = []
    start = 0
    period = timedelta(minutes=minutes)
    distinct_accounts: dict[str, int] = {}
    uses_distinct_accounts = measure is count_distinct_accounts

    for end, item in enumerate(items):
        if uses_distinct_accounts:
            username = item["username"]
            distinct_accounts[username] = distinct_accounts.get(username, 0) + 1
        while items[end]["_time"] - items[start]["_time"] > period:
            if uses_distinct_accounts:
                username = items[start]["username"]
                remaining = distinct_accounts[username] - 1
                if remaining:
                    distinct_accounts[username] = remaining
                else:
                    del distinct_accounts[username]
            start += 1
        if measure is len:
            measured = end - start + 1
        elif uses_distinct_accounts:
            measured = len(distinct_accounts)
        else:
            measured = measure(items[start:end + 1])
        if measured >= limit:
            if not episode:
                episode = list(items[start:end + 1])
            else:
                episode.append(item)
        elif episode:
            episodes.append(episode)
            episode = []

    if episode:
        episodes.append(episode)
    return episodes


def alert(
    rule: RuleName,
    severity: Severity,
    title: str,
    items: list[Event],
    description: str,
) -> Alert:
    first = items[0]
    last = items[-1]
    return {
        "rule": rule,
        "severity": severity,
        "title": title,
        "description": description,
        "source_ip": last["source_ip_normalized"],
        "username": None if rule == "AUTH-002" else last["username"],
        "accounts": (
            sorted({item["username"] for item in items})
            if rule == "AUTH-002" else []
        ),
        "first_seen": first["timestamp"],
        "last_seen": last["timestamp"],
        "first_seen_utc": _utc_iso(first["_time"]),
        "last_seen_utc": _utc_iso(last["_time"]),
        "observed_count": len(items),
        "evidence": [_evidence(item) for item in items],
    }


def analyze(
    events: list[Event],
    minutes: int,
    failure_limit: int,
    spray_limit: int,
    *,
    success_after_failures_threshold: int = 3,
    mfa_failure_threshold: int = 5,
) -> Report:
    if min(
        minutes,
        failure_limit,
        spray_limit,
        success_after_failures_threshold,
        mfa_failure_threshold,
    ) < 1:
        raise ValueError("minutos e limiares devem ser pelo menos 1")
    events = sorted(events, key=lambda item: item["_time"])

    failed_logins = [item for item in events if item["event"] == "login_failed"]
    successful_logins = [item for item in events if item["event"] == "login_success"]
    mfa_failures = [item for item in events if item["event"] == "mfa_failed"]
    disabled_attempts = [
        item for item in events
        if item["event"] in {"login_failed", "login_success"}
        and item["account_status"] == "disabled"
    ]

    by_principal: dict[tuple[str, str], list[Event]] = {}
    failed_by_ip: dict[str, list[Event]] = {}
    mfa_failed_by_principal: dict[tuple[str, str], list[Event]] = {}
    disabled_by_principal: dict[tuple[str, str], list[Event]] = {}
    for item in events:
        principal = (item["source_ip_normalized"], item["username"])
        by_principal.setdefault(principal, []).append(item)
        if item["event"] == "login_failed":
            failed_by_ip.setdefault(item["source_ip_normalized"], []).append(item)
        elif item["event"] == "mfa_failed":
            mfa_failed_by_principal.setdefault(principal, []).append(item)
        elif (
            item["event"] in {"login_failed", "login_success"}
            and item["account_status"] == "disabled"
        ):
            disabled_by_principal.setdefault(principal, []).append(item)

    alerts: list[Alert] = []
    for (_, username), group in by_principal.items():
        login_failures = [item for item in group if item["event"] == "login_failed"]
        for window in threshold_windows(login_failures, minutes, failure_limit, len):
            alerts.append(alert(
                "AUTH-001", "medium", "Muitas falhas de autenticação", window,
                f"{len(window)} falhas para a conta {username} em até "
                f"{minutes} minutos.",
            ))

    for _, group in failed_by_ip.items():
        for window in threshold_windows(
            group, minutes, spray_limit, count_distinct_accounts,
        ):
            account_count = count_distinct_accounts(window)
            spray_alert = alert(
                "AUTH-002", "high", "Possível password spraying", window,
                f"Tentativas contra {account_count} contas diferentes em até "
                f"{minutes} minutos.",
            )
            spray_alert["observed_count"] = account_count
            alerts.append(spray_alert)

    for principal, group in by_principal.items():
        failure_events = [item for item in group if item["event"] == "login_failed"]
        failure_times = [item["_time"] for item in failure_events]
        for success in group:
            if success["event"] != "login_success":
                continue
            first_time = success["_time"] - timedelta(minutes=minutes)
            first_index = bisect_left(failure_times, first_time)
            last_index = bisect_right(failure_times, success["_time"])
            recent_failures = [
                failure
                for failure in failure_events[first_index:last_index]
                if (
                    failure["_time"] < success["_time"]
                    or (
                        failure["_time"] == success["_time"]
                        and failure["source_line"] < success["source_line"]
                    )
                )
            ]
            if len(recent_failures) >= success_after_failures_threshold:
                evidence = recent_failures + [success]
                alerts.append(alert(
                    "AUTH-003", "high", "Login após várias falhas", evidence,
                    f"Login bem-sucedido após {len(recent_failures)} falhas "
                    f"recentes em até {minutes} minutos.",
                ))

    for _, group in disabled_by_principal.items():
        for item in group:
            is_success = item["event"] == "login_success"
            alerts.append(alert(
                "AUTH-004",
                "high" if is_success else "medium",
                "Autenticação em conta desativada",
                [item],
                "Foi observado um login bem-sucedido em conta marcada como "
                "desativada." if is_success else
                "Foi observada uma tentativa de login em conta marcada como "
                "desativada.",
            ))

    for (_, username), group in mfa_failed_by_principal.items():
        for window in threshold_windows(group, minutes, mfa_failure_threshold, len):
            alerts.append(alert(
                "AUTH-005", "medium", "Várias falhas de MFA", window,
                f"{len(window)} falhas de MFA para a conta {username} em até "
                f"{minutes} minutos.",
            ))

    alerts.sort(key=lambda item: (
        datetime.fromisoformat(item["last_seen_utc"].replace("Z", "+00:00")),
        item["rule"],
        item["source_ip"],
        item["username"] or "",
    ))
    return {
        "metadata": {
            "schema_version": "1.0",
            "tool_version": TOOL_VERSION,
            "ruleset_version": RULESET_VERSION,
            "source_file_name": "",
            "input_sha256": "",
            "analysis_time_utc": "",
            "thresholds": {
                "window_minutes": minutes,
                "failure_threshold": failure_limit,
                "spray_threshold": spray_limit,
                "success_after_failures_threshold": success_after_failures_threshold,
                "mfa_failure_threshold": mfa_failure_threshold,
            },
            "rules": RULES,
            "limitations": [
                "Alertas são heurísticas e não confirmam comprometimento.",
                "Não há baseline para inferir atividade incomum de contas ou dispositivos.",
                "A precisão depende da qualidade e completude dos eventos fornecidos.",
            ],
        },
        "summary": {
            "total_events": len(events),
            "failed_logins": len(failed_logins),
            "successful_logins": len(successful_logins),
            "mfa_failures": len(mfa_failures),
            "disabled_account_attempts": len(disabled_attempts),
            "alerts": len(alerts),
        },
        "alerts": alerts,
    }


def safe_csv_value(value: str) -> str:
    if value.lstrip(" \t\r\n")[:1] in {"=", "+", "-", "@"}:
        return "'" + value
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analisador defensivo de logs de autenticação.",
    )
    parser.add_argument(
        "--input", required=True, type=Path,
        help="Arquivo JSON Lines de eventos.",
    )
    parser.add_argument("--output", type=Path, help="Arquivo de relatório.")
    parser.add_argument("--format", choices=("json", "csv"), default="json")
    parser.add_argument("--window-minutes", type=int, default=10)
    parser.add_argument("--failure-threshold", type=int, default=5)
    parser.add_argument("--spray-threshold", type=int, default=5)
    parser.add_argument("--success-after-failures-threshold", type=int, default=3)
    parser.add_argument("--mfa-failure-threshold", type=int, default=5)
    args = parser.parse_args()

    thresholds = (
        args.window_minutes,
        args.failure_threshold,
        args.spray_threshold,
        args.success_after_failures_threshold,
        args.mfa_failure_threshold,
    )
    if min(thresholds) < 1:
        parser.error("minutos e limiares devem ser pelo menos 1")
    if args.output is not None and args.output.resolve() == args.input.resolve():
        parser.error("o arquivo de saída não pode sobrescrever o arquivo de entrada")

    try:
        events, input_sha256 = read_events_with_hash(args.input)
        report = analyze(
            events,
            args.window_minutes,
            args.failure_threshold,
            args.spray_threshold,
            success_after_failures_threshold=args.success_after_failures_threshold,
            mfa_failure_threshold=args.mfa_failure_threshold,
        )
        report["metadata"]["source_file_name"] = args.input.name
        report["metadata"]["input_sha256"] = input_sha256
        report["metadata"]["analysis_time_utc"] = _utc_iso(
            datetime.now(timezone.utc)
        )

        if args.format == "json":
            output = json.dumps(report, ensure_ascii=False, indent=2)
        else:
            from io import StringIO

            stream = StringIO()
            columns: tuple[CsvField, ...] = (
                "record_type", "rule", "severity", "title", "description",
                "source_ip", "username", "accounts", "first_seen", "last_seen",
                "first_seen_utc", "last_seen_utc", "observed_count",
                "evidence_count", "evidence_json", "input_sha256",
                "ruleset_version", "report_metadata_json",
            )
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            metadata_json = json.dumps(
                report["metadata"], ensure_ascii=False, sort_keys=True,
            )
            writer.writerow({
                "record_type": "metadata",
                "input_sha256": report["metadata"]["input_sha256"],
                "ruleset_version": report["metadata"]["ruleset_version"],
                "report_metadata_json": safe_csv_value(metadata_json),
            })
            for item in report["alerts"]:
                writer.writerow({
                    "record_type": "alert",
                    "rule": safe_csv_value(item["rule"]),
                    "severity": safe_csv_value(item["severity"]),
                    "title": safe_csv_value(item["title"]),
                    "description": safe_csv_value(item["description"]),
                    "source_ip": safe_csv_value(item["source_ip"]),
                    "username": (
                        safe_csv_value(item["username"])
                        if item["username"] is not None else ""
                    ),
                    "accounts": safe_csv_value(json.dumps(
                        item["accounts"], ensure_ascii=False,
                    )),
                    "first_seen": safe_csv_value(item["first_seen"]),
                    "last_seen": safe_csv_value(item["last_seen"]),
                    "first_seen_utc": safe_csv_value(item["first_seen_utc"]),
                    "last_seen_utc": safe_csv_value(item["last_seen_utc"]),
                    "observed_count": item["observed_count"],
                    "evidence_count": len(item["evidence"]),
                    "evidence_json": safe_csv_value(json.dumps(
                        item["evidence"], ensure_ascii=False,
                    )),
                })
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
