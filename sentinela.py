"""Sentinela: analisador offline de logs de autenticação para estudos de Blue Team."""
import argparse
import csv
from datetime import datetime, timedelta
import json
from pathlib import Path
import sys


def read_events(path):
    events = []
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        raise ValueError(f"Não foi possível abrir o arquivo: {exc}") from exc
    required = {"timestamp", "source_ip", "username", "event"}
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Linha {number}: JSON inválido ({exc.msg}).") from exc
        if not isinstance(item, dict) or not required <= item.keys():
            raise ValueError(f"Linha {number}: são necessários timestamp, source_ip, username e event.")
        if item["event"] not in {"login_failed", "login_success"}:
            raise ValueError(f"Linha {number}: event deve ser login_failed ou login_success.")
        if not all(isinstance(item[k], str) and item[k].strip() for k in required):
            raise ValueError(f"Linha {number}: todos os campos devem ser textos não vazios.")
        try:
            item["_time"] = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Linha {number}: timestamp ISO 8601 inválido.") from exc
        if item["_time"].tzinfo is None:
            raise ValueError(f"Linha {number}: inclua o fuso horário, por exemplo Z ou -03:00.")
        events.append(item)
    return sorted(events, key=lambda e: e["_time"])


def threshold_windows(items, minutes, limit, measure):
    result, start, active = [], 0, False
    period = timedelta(minutes=minutes)
    for end in range(len(items)):
        while items[end]["_time"] - items[start]["_time"] > period:
            start += 1
        current = items[start:end + 1]
        if measure(current) >= limit:
            if not active:
                result.append(current)
            active = True
        else:
            active = False
    return result


def alert(rule, severity, title, items, description):
    last = items[-1]
    return {"rule": rule, "severity": severity, "title": title,
            "description": description, "source_ip": last["source_ip"],
            "username": None if rule == "AUTH-002" else last["username"],
            "accounts": sorted({e["username"] for e in items}) if rule == "AUTH-002" else [],
            "first_seen": items[0]["timestamp"], "last_seen": last["timestamp"],
            "observed_count": len(items)}


def analyze(events, minutes, failure_limit, spray_limit):
    failed = [e for e in events if e["event"] == "login_failed"]
    successes = [e for e in events if e["event"] == "login_success"]
    by_user, by_ip, all_by_user = {}, {}, {}
    for e in events:
        key = (e["source_ip"], e["username"])
        all_by_user.setdefault(key, []).append(e)
        if e["event"] == "login_failed":
            by_user.setdefault(key, []).append(e)
            by_ip.setdefault(e["source_ip"], []).append(e)
    alerts = []
    for (_, username), group in by_user.items():
        for window in threshold_windows(group, minutes, failure_limit, len):
            alerts.append(alert("AUTH-001", "medium", "Muitas falhas de autenticação", window,
                                f"{len(window)} falhas para a conta {username} em até {minutes} minutos."))
    for _, group in by_ip.items():
        distinct = lambda group: len({e["username"] for e in group})
        for window in threshold_windows(group, minutes, spray_limit, distinct):
            a = alert("AUTH-002", "high", "Possível password spraying", window,
                      f"Tentativas contra {distinct(window)} contas diferentes em até {minutes} minutos.")
            a["observed_count"] = distinct(window)
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


def main():
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
            columns = ("rule", "severity", "title", "description", "source_ip", "username", "first_seen", "last_seen", "observed_count")
            writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(report["alerts"])
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
