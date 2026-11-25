import csv
from collections.abc import Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sentinela import Event, analyze, main, read_events


ROOT = Path(__file__).parent
SAMPLE_EVENTS = ROOT / "sample_auth_events.jsonl"


class ReadEventsTests(unittest.TestCase):
    def test_rejects_non_string_event_values(self):
        invalid_events: tuple[list[object] | dict[str, object], ...] = ([], {})
        for event in invalid_events:
            with self.subTest(event=event), tempfile.TemporaryDirectory() as directory:
                input_path = Path(directory) / "events.jsonl"
                input_path.write_text(json.dumps({
                    "timestamp": "2026-10-27T09:00:00-03:00",
                    "source_ip": "203.0.113.1",
                    "username": "ana",
                    "event": event,
                }), encoding="utf-8")

                with self.assertRaisesRegex(ValueError, "event deve ser"):
                    read_events(input_path)

    def test_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "events.jsonl"
            input_path.write_text(
                '{"timestamp":"2026-10-27T09:00:00Z",'
                '"source_ip":"203.0.113.1","username":"ana",'
                '"event":"login_failed","event":"login_success"}',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "chave JSON duplicada"):
                read_events(input_path)

    def test_normalizes_source_ip_and_timestamp_while_preserving_originals(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "events.jsonl"
            input_path.write_text(json.dumps({
                "timestamp": "2026-10-27T12:00:00+03:00",
                "source_ip": "2001:0db8::1",
                "username": "ana",
                "event": "login_failed",
                "event_id": "auth-123",
                "system": "vpn",
                "auth_method": "password",
                "mfa": True,
                "device": "laptop-01",
                "account_status": "active",
                "privileged": False,
            }), encoding="utf-8")

            event = read_events(input_path)[0]

        self.assertEqual(event["timestamp"], "2026-10-27T12:00:00+03:00")
        self.assertEqual(event["source_ip_normalized"], "2001:db8::1")
        self.assertEqual(event["_time"].isoformat(), "2026-10-27T09:00:00+00:00")
        self.assertEqual(event["event_id"], "auth-123")
        self.assertEqual(event["system"], "vpn")

    def test_rejects_invalid_ip_and_sensitive_fields(self):
        base_event = {
            "timestamp": "2026-10-27T09:00:00-03:00",
            "source_ip": "not-an-ip",
            "username": "ana",
            "event": "login_failed",
        }
        cases = (
            (base_event, "source_ip não é"),
            ({**base_event, "source_ip": "203.0.113.1", "accessToken": "do-not-log"},
             "campo sensível"),
        )
        for event, message in cases:
            with self.subTest(event=event), tempfile.TemporaryDirectory() as directory:
                input_path = Path(directory) / "events.jsonl"
                input_path.write_text(json.dumps(event), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, message):
                    read_events(input_path)

    def test_sorts_out_of_order_events_by_utc_and_keeps_source_lines(self):
        source_events = [
            {
                "timestamp": "2026-10-27T10:00:00+03:00",
                "source_ip": "203.0.113.1",
                "username": "later",
                "event": "login_failed",
            },
            {
                "timestamp": "2026-10-27T05:00:00Z",
                "source_ip": "203.0.113.2",
                "username": "earlier",
                "event": "login_failed",
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "events.jsonl"
            input_path.write_text(
                "\n".join(json.dumps(event) for event in source_events),
                encoding="utf-8",
            )

            events = read_events(input_path)

        self.assertEqual([event["username"] for event in events], ["earlier", "later"])
        self.assertEqual([event["source_line"] for event in events], [2, 1])

    def test_rejects_non_boolean_context_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "events.jsonl"
            input_path.write_text(json.dumps({
                "timestamp": "2026-10-27T09:00:00-03:00",
                "source_ip": "203.0.113.1",
                "username": "ana",
                "event": "login_failed",
                "privileged": "false",
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "privileged deve ser booleano"):
                read_events(input_path)


class CliTests(unittest.TestCase):
    def test_csv_includes_password_spray_accounts(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "alerts.csv"
            with patch("sys.argv", [
                "sentinela", "--input", str(SAMPLE_EVENTS),
                "--format", "csv", "--output", str(output_path),
            ]):
                self.assertEqual(main(), 0)

            with output_path.open(encoding="utf-8", newline="") as output_file:
                rows = list(csv.DictReader(output_file))

            spray_alert = next(row for row in rows if row["rule"] == "AUTH-002")
            self.assertEqual(
                json.loads(spray_alert["accounts"]),
                ["bruno", "carla", "diego", "eva", "felipe"],
            )

    def test_csv_neutralizes_formula_like_log_values(self):
        malicious_values = (
            "=1+1",
            "+1+1",
            "-1+1",
            "@SUM(A1:A2)",
            " \t=1+1",
            "\t=1+1",
            "\r=1+1",
            "\n=1+1",
        )
        events: list[dict[str, object]] = []
        expected: dict[str, str] = {}
        for index, value in enumerate(malicious_values):
            source_ip = f"198.51.100.{index + 1}"
            expected[source_ip] = "'" + value.replace("\n", "\r\n")
            for minute in range(5):
                events.append({
                    "timestamp": f"2026-10-27T09:0{minute}:00-03:00",
                    "source_ip": source_ip,
                    "username": value,
                    "event": "login_failed",
                })

        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "events.jsonl"
            output_path = Path(directory) / "alerts.csv"
            input_path.write_text(
                "\n".join(json.dumps(event) for event in events),
                encoding="utf-8",
            )
            with patch("sys.argv", [
                "sentinela", "--input", str(input_path),
                "--format", "csv", "--output", str(output_path),
            ]):
                self.assertEqual(main(), 0)

            with output_path.open(encoding="utf-8", newline="") as output_file:
                rows = list(csv.DictReader(output_file))

        alert_rows = [row for row in rows if row["record_type"] == "alert"]
        self.assertEqual(len(alert_rows), len(expected))
        for row in alert_rows:
            self.assertEqual(expected[row["source_ip"]], row["username"])
            self.assertNotIn(row["username"][0], "=+-@\t\r\n")
            self.assertNotIn(row["source_ip"][0], "=+-@\t\r\n")

    def test_malformed_event_returns_cli_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "events.jsonl"
            input_path.write_text(json.dumps({
                "timestamp": "2026-10-27T09:00:00-03:00",
                "source_ip": "203.0.113.1",
                "username": "ana",
                "event": [],
            }), encoding="utf-8")

            with patch("sys.argv", ["sentinela", "--input", str(input_path)]):
                with patch("sys.stderr") as stderr:
                    self.assertEqual(main(), 2)

            error_output = "".join(
                call.args[0] for call in stderr.write.call_args_list
            )
            self.assertIn("Erro:", error_output)
            self.assertNotIn("Traceback", error_output)

    def test_cli_prevents_overwriting_the_input_file(self):
        original_content = SAMPLE_EVENTS.read_text(encoding="utf-8")
        with patch("sys.argv", [
            "sentinela", "--input", str(SAMPLE_EVENTS),
            "--output", str(SAMPLE_EVENTS),
        ]):
            with patch("sys.stderr"):
                with self.assertRaises(SystemExit) as error:
                    main()

        self.assertEqual(error.exception.code, 2)
        self.assertEqual(SAMPLE_EVENTS.read_text(encoding="utf-8"), original_content)

    def test_cli_prevents_overwriting_input_through_hard_link(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "events.jsonl"
            output_path = Path(directory) / "report.json"
            original_content = (
                '{"timestamp":"2026-10-27T09:00:00Z",'
                '"source_ip":"203.0.113.1","username":"ana",'
                '"event":"login_success"}\n'
            )
            input_path.write_text(original_content, encoding="utf-8")
            try:
                os.link(input_path, output_path)
            except OSError as exc:
                self.skipTest(f"hard links are unavailable: {exc}")

            with patch("sys.argv", [
                "sentinela", "--input", str(input_path),
                "--output", str(output_path),
            ]):
                with patch("sys.stderr"):
                    with self.assertRaises(SystemExit) as error:
                        main()

            self.assertEqual(error.exception.code, 2)
            self.assertEqual(input_path.read_text(encoding="utf-8"), original_content)

    def test_json_report_contains_hash_and_rule_thresholds(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "report.json"
            with patch("sys.argv", [
                "sentinela", "--input", str(SAMPLE_EVENTS),
                "--output", str(output_path),
            ]):
                self.assertEqual(main(), 0)

            report = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(
            report["metadata"]["input_sha256"],
            hashlib.sha256(SAMPLE_EVENTS.read_bytes()).hexdigest(),
        )
        self.assertEqual(report["metadata"]["ruleset_version"], "1.0")
        self.assertEqual(report["metadata"]["thresholds"]["mfa_failure_threshold"], 5)
        self.assertEqual(report["metadata"]["rules"]["AUTH-004"]["severity"], "variable")
        self.assertIn("analysis_time_utc", report["metadata"])
        self.assertTrue(report["alerts"][0]["evidence"])

    def test_csv_contains_audit_metadata_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "alerts.csv"
            with patch("sys.argv", [
                "sentinela", "--input", str(SAMPLE_EVENTS),
                "--format", "csv", "--output", str(output_path),
            ]):
                self.assertEqual(main(), 0)

            with output_path.open(encoding="utf-8", newline="") as output_file:
                rows = list(csv.DictReader(output_file))

        spray_alert = next(row for row in rows if row["rule"] == "AUTH-002")
        metadata_row = next(row for row in rows if row["record_type"] == "metadata")
        evidence = json.loads(spray_alert["evidence_json"])
        metadata = json.loads(metadata_row["report_metadata_json"])
        self.assertEqual(len(evidence), int(spray_alert["evidence_count"]))
        self.assertEqual(metadata_row["input_sha256"], metadata["input_sha256"])
        self.assertEqual(metadata["ruleset_version"], "1.0")

    def test_csv_keeps_metadata_when_there_are_no_alerts(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "events.jsonl"
            output_path = Path(directory) / "alerts.csv"
            input_path.write_text("", encoding="utf-8")

            with patch("sys.argv", [
                "sentinela", "--input", str(input_path),
                "--format", "csv", "--output", str(output_path),
            ]):
                self.assertEqual(main(), 0)

            with output_path.open(encoding="utf-8", newline="") as output_file:
                rows = list(csv.DictReader(output_file))

        self.assertEqual([row["record_type"] for row in rows], ["metadata"])
        metadata = json.loads(rows[0]["report_metadata_json"])
        self.assertEqual(metadata["input_sha256"], rows[0]["input_sha256"])


class AnalysisTests(unittest.TestCase):
    def _events(
        self, events: Sequence[Mapping[str, object]],
    ) -> list[Event]:
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "events.jsonl"
            input_path.write_text(
                "\n".join(json.dumps(dict(event)) for event in events),
                encoding="utf-8",
            )
            return read_events(input_path)

    def test_spray_evidence_covers_the_whole_active_episode(self):
        events = [{
            "timestamp": f"2026-10-27T09:0{minute}:00-03:00",
            "source_ip": "203.0.113.10",
            "username": f"user-{minute}",
            "event": "login_failed",
        } for minute in range(6)]

        report = analyze(self._events(events), 10, 5, 5)
        spray_alert = next(
            item for item in report["alerts"] if item["rule"] == "AUTH-002"
        )

        self.assertEqual(spray_alert["accounts"], [f"user-{i}" for i in range(6)])
        self.assertEqual(spray_alert["observed_count"], 6)
        self.assertEqual(len(spray_alert["evidence"]), 6)

    def test_auth001_repeated_failures_include_supporting_events(self):
        events = [{
            "timestamp": f"2026-10-27T09:0{minute}:00-03:00",
            "source_ip": "203.0.113.14",
            "username": "ana",
            "event": "login_failed",
        } for minute in range(5)]

        report = analyze(self._events(events), 10, 5, 5)
        failure_alert = next(
            item for item in report["alerts"] if item["rule"] == "AUTH-001"
        )

        self.assertEqual(failure_alert["observed_count"], 5)
        self.assertEqual(len(failure_alert["evidence"]), 5)

    def test_mfa_failure_rule_has_all_supporting_events(self):
        events = [{
            "timestamp": f"2026-10-27T09:0{minute}:00-03:00",
            "source_ip": "203.0.113.11",
            "username": "ana",
            "event": "mfa_failed",
        } for minute in range(5)]

        report = analyze(self._events(events), 10, 5, 5)
        mfa_alert = next(
            item for item in report["alerts"] if item["rule"] == "AUTH-005"
        )

        self.assertEqual(mfa_alert["observed_count"], 5)
        self.assertEqual(len(mfa_alert["evidence"]), 5)
        self.assertEqual(report["summary"]["mfa_failures"], 5)

    def test_successful_login_to_disabled_account_is_high_severity(self):
        events = [{
            "timestamp": "2026-10-27T09:00:00-03:00",
            "source_ip": "203.0.113.12",
            "username": "former-user",
            "event": "login_success",
            "account_status": "disabled",
        }]

        report = analyze(self._events(events), 10, 5, 5)
        disabled_alert = next(
            item for item in report["alerts"] if item["rule"] == "AUTH-004"
        )

        self.assertEqual(disabled_alert["severity"], "high")
        self.assertEqual(disabled_alert["evidence"][0]["account_status"], "disabled")

    def test_success_after_failures_includes_boundary_event(self):
        events = [
            {
                "timestamp": f"2026-10-27T09:{minute:02d}:00-03:00",
                "source_ip": "203.0.113.13",
                "username": "ana",
                "event": "login_failed",
            }
            for minute in (0, 3, 5)
        ]
        events.append({
            "timestamp": "2026-10-27T09:10:00-03:00",
            "source_ip": "203.0.113.13",
            "username": "ana",
            "event": "login_success",
        })

        report = analyze(self._events(events), 10, 5, 5)
        success_alert = next(
            item for item in report["alerts"] if item["rule"] == "AUTH-003"
        )

        self.assertEqual(len(success_alert["evidence"]), 4)
        self.assertEqual(success_alert["last_seen_utc"], "2026-10-27T12:10:00Z")

    def test_auth003_respects_source_order_for_identical_timestamps(self):
        timestamp = "2026-10-27T09:00:00Z"
        failures = [{
            "timestamp": timestamp,
            "source_ip": "203.0.113.15",
            "username": "ana",
            "event": "login_failed",
        } for _ in range(3)]
        success = {
            "timestamp": timestamp,
            "source_ip": "203.0.113.15",
            "username": "ana",
            "event": "login_success",
        }

        with_success_first = self._events([success, *failures])
        report = analyze(with_success_first, 10, 5, 5)
        self.assertNotIn("AUTH-003", {item["rule"] for item in report["alerts"]})

        with_success_last = self._events([*failures, success])
        report = analyze(with_success_last, 10, 5, 5)
        success_alert = next(
            item for item in report["alerts"] if item["rule"] == "AUTH-003"
        )
        self.assertEqual(
            [item["source_line"] for item in success_alert["evidence"]],
            [1, 2, 3, 4],
        )

    def test_rejects_non_positive_thresholds_when_called_as_library(self):
        with self.assertRaisesRegex(ValueError, "limiares devem ser pelo menos 1"):
            analyze([], 0, 5, 5)


if __name__ == "__main__":
    unittest.main()
