"""Tests for CLI option handling and shell helpers."""

import unittest

from hackit.sqli import (
    _apply_crawl,
    _default_scan,
    _engine_kwargs,
    _has_action,
    _split_list,
    _title_for,
)


class SplitListTests(unittest.TestCase):
    def test_tuple_input(self):
        self.assertEqual(_split_list(("a", "b", "")), ["a", "b"])

    def test_comma_input(self):
        self.assertEqual(_split_list("a, b ,c"), ["a", "b", "c"])

    def test_empty_input(self):
        self.assertEqual(_split_list(None), [])
        self.assertEqual(_split_list(""), [])


class ActionTests(unittest.TestCase):
    def test_boolean_action(self):
        self.assertTrue(_has_action({"list_dbs": True}))

    def test_string_action(self):
        self.assertTrue(_has_action({"sql_query": "SELECT 1"}))

    def test_no_action(self):
        self.assertFalse(_has_action({"list_dbs": False, "sql_query": ""}))

    def test_default_scan_adds_enumeration(self):
        options = _default_scan({"url": "http://example.test"})
        self.assertTrue(options["fingerprint"])
        self.assertTrue(options["current_db"])
        self.assertTrue(options["current_user"])
        self.assertTrue(options["list_dbs"])
        self.assertTrue(options["list_tables"])

    def test_default_scan_keeps_explicit_action(self):
        options = _default_scan({"url": "http://example.test", "dump_table": "users"})
        self.assertNotIn("fingerprint", options)
        self.assertEqual(options["dump_table"], "users")


class CrawlTests(unittest.TestCase):
    def test_full_crawl_composes_actions(self):
        options = _apply_crawl(
            {
                "crawl": "full",
                "crawl_depth": 9,
                "crawl_threads": 20,
                "crawl_output": "old",
            }
        )
        self.assertTrue(options["schema"])
        self.assertTrue(options["list_columns"])
        self.assertTrue(options["count_rows"])
        self.assertTrue(options["dump_all"])
        self.assertNotIn("crawl", options)
        self.assertNotIn("crawl_depth", options)
        self.assertNotIn("crawl_threads", options)
        self.assertNotIn("crawl_output", options)

    def test_schema_crawl_skips_dump(self):
        options = _apply_crawl({"crawl": "schema"})
        self.assertTrue(options["schema"])
        self.assertNotIn("dump_all", options)

    def test_no_crawl_is_unchanged(self):
        options = {"list_dbs": True}
        self.assertEqual(_apply_crawl(options), options)


class TitleTests(unittest.TestCase):
    def test_titles(self):
        self.assertEqual(_title_for({"dump_table": "users"}), "Data extraction")
        self.assertEqual(_title_for({"sql_query": "SELECT 1"}), "SQL query result")
        self.assertEqual(_title_for({"list_dbs": True}), "Database enumeration")
        self.assertEqual(_title_for({"schema": True}), "Schema enumeration")
        self.assertEqual(_title_for({"count_rows": True}), "Row counts")
        self.assertEqual(_title_for({"users": True}), "Account enumeration")
        self.assertEqual(_title_for({"fingerprint": True}), "DBMS fingerprint")
        self.assertEqual(_title_for({}), "SQL injection assessment")


class EngineKwargsTests(unittest.TestCase):
    def test_skips_false_and_empty_values(self):
        kwargs = _engine_kwargs(
            {
                "list_dbs": True,
                "dump_all": False,
                "database": "",
                "sql_query": None,
                "rows": 5,
            }
        )
        self.assertEqual(kwargs, {"list_dbs": True, "rows": 5})

    def test_joins_headers_and_tamper(self):
        kwargs = _engine_kwargs(
            {
                "headers": ("X-One: 1", "X-Two: 2"),
                "tamper": ("space2comment", "randomcase"),
            }
        )
        self.assertEqual(kwargs["header"], "X-One: 1,X-Two: 2")
        self.assertEqual(kwargs["tamper"], "space2comment,randomcase")

    def test_passthrough_values(self):
        kwargs = _engine_kwargs(
            {
                "technique": "time",
                "time_secs": 2,
                "prefix": "'",
                "suffix": "-- -",
                "extract_technique": "blind",
            }
        )
        self.assertEqual(kwargs["technique"], "time")
        self.assertEqual(kwargs["time_secs"], 2)
        self.assertEqual(kwargs["prefix"], "'")
        self.assertEqual(kwargs["suffix"], "-- -")
        self.assertEqual(kwargs["extract_technique"], "blind")


if __name__ == "__main__":
    unittest.main()
