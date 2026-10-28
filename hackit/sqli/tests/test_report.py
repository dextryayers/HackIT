"""Tests for report rendering and summary calculation."""

import csv
import json
import os
import tempfile
import unittest

from hackit.sqli import report


def sample_results():
    return [
        {
            "parameter": "id",
            "type": "boolean",
            "payload": "1 AND 1=1",
            "dbms": "SQLite",
            "dbms_version": "3.46.1",
            "details": "query parameter, boolean technique",
            "confidence": 0.9,
            "location": "query",
            "technique": "boolean",
            "prefix": "'",
            "suffix": "-- -",
            "columns": 4,
        },
        {
            "parameter": "enumeration",
            "type": "list-dbs",
            "payload": "main\x1eanalytics",
            "dbms": "SQLite",
            "details": "available databases",
            "confidence": 1.0,
        },
        {
            "parameter": "enumeration",
            "type": "list-tables",
            "payload": "users\x1esecrets",
            "dbms": "SQLite",
            "details": "main",
            "confidence": 1.0,
        },
        {
            "parameter": "enumeration",
            "type": "sql-query",
            "payload": "HACKIT{sqlite_union_works}",
            "dbms": "SQLite",
            "details": "SELECT flag FROM secrets WHERE id=1",
            "confidence": 1.0,
        },
        {
            "parameter": "enumeration",
            "type": "dump-table",
            "payload": "2 rows",
            "dbms": "SQLite",
            "details": "main.secrets",
            "confidence": 1.0,
            "column_names": ["id", "name", "flag"],
            "rows": [
                ["1", "launch-code", "HACKIT{sqlite_union_works}"],
                ["2", "backup-key", "HACKIT{blind_extraction_works}"],
            ],
        },
    ]


class SplitValuesTests(unittest.TestCase):
    def test_list_input(self):
        self.assertEqual(report.split_values(["a", "b", ""]), ["a", "b"])

    def test_control_separators(self):
        self.assertEqual(report.split_values("a\x1eb\x1fc"), ["a", "b", "c"])

    def test_comma_separator(self):
        self.assertEqual(report.split_values("a, b ,c"), ["a", "b", "c"])

    def test_empty_input(self):
        self.assertEqual(report.split_values(None), [])
        self.assertEqual(report.split_values(""), [])


class ResultTableTests(unittest.TestCase):
    def test_uses_explicit_columns_and_rows(self):
        columns, rows = report.result_table(sample_results()[4])
        self.assertEqual(columns, ["id", "name", "flag"])
        self.assertEqual(rows[0][2], "HACKIT{sqlite_union_works}")

    def test_parses_json_payload(self):
        item = {
            "type": "dump-table",
            "payload": json.dumps([{"id": 1, "name": "alice"}]),
        }
        columns, rows = report.result_table(item)
        self.assertEqual(columns, ["id", "name"])
        self.assertEqual(rows, [["1", "alice"]])

    def test_parses_json_scalar_list(self):
        item = {"type": "dump-table", "payload": json.dumps([1, 2, 3])}
        columns, rows = report.result_table(item)
        self.assertEqual(columns, ["Value"])
        self.assertEqual(rows, [["1"], ["2"], ["3"]])

    def test_falls_back_to_generated_columns(self):
        item = {"type": "dump-table", "rows": [["a", "b"]]}
        columns, rows = report.result_table(item)
        self.assertEqual(columns, ["Column 1", "Column 2"])
        self.assertEqual(rows, [["a", "b"]])


class SummaryTests(unittest.TestCase):
    def test_counts_findings_and_data(self):
        summary = report.summarize(sample_results(), target="http://example.test")
        self.assertTrue(summary["vulnerable"])
        self.assertEqual(summary["findings"], 1)
        self.assertEqual(summary["dbms"], "SQLite")
        self.assertEqual(summary["dbms_version"], "3.46.1")
        self.assertEqual(summary["parameters"], ["enumeration", "id"])
        self.assertEqual(summary["techniques"], ["boolean"])
        self.assertEqual(summary["locations"], ["query"])
        self.assertIn("main", summary["databases"])
        self.assertEqual(summary["table_count"], 2)
        self.assertEqual(summary["dump_tables"], 1)
        self.assertEqual(summary["dumped_rows"], 2)

    def test_no_findings_is_not_vulnerable(self):
        summary = report.summarize([{"type": "list-dbs", "payload": "main"}])
        self.assertFalse(summary["vulnerable"])
        self.assertEqual(summary["dbms"], "Unknown")

    def test_severity_thresholds(self):
        self.assertEqual(report.severity(0.95), "Critical")
        self.assertEqual(report.severity(0.75), "High")
        self.assertEqual(report.severity(0.5), "Medium")
        self.assertEqual(report.severity(0.1), "Low")


class ReportFileTests(unittest.TestCase):
    def test_generate_all_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "report")
            paths = report.generate_report(
                sample_results(),
                base,
                formats=("html", "json", "csv", "txt"),
                target="http://example.test/vuln?id=1",
            )
            for name in ("html", "json", "csv", "txt"):
                self.assertTrue(os.path.exists(paths[name]))
                self.assertGreater(os.path.getsize(paths[name]), 0)

            with open(paths["html"], encoding="utf-8") as handle:
                html_text = handle.read()
            self.assertIn("SQL injection report", html_text)
            self.assertIn("http://example.test/vuln?id=1", html_text)
            self.assertIn("HACKIT{sqlite_union_works}", html_text)

            with open(paths["json"], encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload["summary"]["dbms"], "SQLite")
            self.assertEqual(len(payload["results"]), 5)

            with open(paths["csv"], newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            data_rows = [row for row in rows if row["section"] == "data"]
            self.assertEqual(len(data_rows), 2)
            self.assertIn("HACKIT{blind_extraction_works}", data_rows[1]["value"])

            with open(paths["txt"], encoding="utf-8") as handle:
                text = handle.read()
            self.assertIn("DBMS      : SQLite 3.46.1", text)
            self.assertIn("Data: main.secrets", text)

    def test_html_escapes_untrusted_values(self):
        item = {
            "parameter": "<script>alert(1)</script>",
            "type": "boolean",
            "dbms": "<b>SQLite</b>",
            "details": "<img src=x onerror=alert(1)>",
            "confidence": 0.9,
            "payload": "<script>",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "safe.html")
            report.generate_html([item], path)
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
        self.assertNotIn("<script>alert(1)</script>", text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", text)

    def test_unsupported_format_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                report.generate_report([], os.path.join(tmp, "x"), formats=("pdf",))


if __name__ == "__main__":
    unittest.main()
