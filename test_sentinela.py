import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sentinela import main, read_events


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

        source_ip = " +1+1"
        expected["' +1+1"] = "ana"
        for minute in range(5):
            events.append({
                "timestamp": f"2026-10-27T09:0{minute}:00-03:00",
                "source_ip": source_ip,
                "username": "ana",
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

        self.assertEqual(len(rows), len(expected))
        for row in rows:
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


if __name__ == "__main__":
    unittest.main()
