"""Synthetic-only contract, SQLite and concurrency tests. No Windows log or AI access."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stderr, redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("assistant_publisher", Path(__file__).with_name("publish-assistant-audit.py"))
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


def fixture():
    evidence = {
        "SchemaVersion": 1, "RunId": "00000000-0000-4000-8000-000000000001",
        "ScanStart": "2026-01-01T00:00:00Z", "ScanEnd": "2026-01-02T00:00:00Z",
        "CollectedAt": "2026-01-02T00:00:03Z", "DurationMs": 3000,
        "Channels": [{"LogName": log, "Status": "complete", "EventCount": 2 if log == "Security" else 0, "Reason": "none"}
                     for log in ("Security", "System", "Application", "Setup")],
        "Events": [{"EventRef": f"Security:{index}", "EventId": "4625", "EventTimestamp": f"2026-01-01T12:00:0{index}Z",
                    "Source": "SyntheticProvider", "LogName": "Security", "EventRecordId": str(index),
                    "EventDescription": f"Synthetic event {index}", "EventAdditionalData": '{"LogonType":"3"}',
                    "UserName": "synthetic-user", "IpAddress": "192.0.2.1"} for index in (1, 2)]}
    finding = {"Key": "failed_logon_burst", "EventRef": "Security:2", "RelatedEventRefs": ["Security:1", "Security:2"],
               "Title": "Synthetic finding", "Description": "Synthetic evidence summary", "RootCause": "Cause not established",
               "Recommendation": "Review the original records", "TitleZh": "合成问题", "DescriptionZh": "合成证据摘要",
               "RootCauseZh": "原因尚未确定", "RecommendationZh": "核对原始记录", "Severity": "Medium", "Confidence": "High",
               "Category": "Login", "Affected": "synthetic-user"}
    result = {"Timestamp": "2026-01-02T00:01:00Z", "Findings": [finding],
              "Metadata": {"SchemaVersion": 1, "Mode": "assistant", "RunId": evidence["RunId"], "Producer": "codex",
                           "AnalysisModel": "synthetic-model", "ScanType": "Full Scan",
                           "AnalyzedEventRefs": ["Security:1", "Security:2"], "FilterSummary": ""}}
    return result, evidence


def prepared():
    result, evidence = fixture()
    return publisher.prepare_result(result, evidence, "0" * 64)


class AssistantWorkflowTests(unittest.TestCase):
    def test_evidence_and_model_are_bound_without_model_owned_source_fields(self):
        normalized = prepared()
        issue = normalized["Findings"][0]
        self.assertEqual(normalized["HealthScore"], 94)
        self.assertEqual(issue["EventDescription"], "Synthetic event 2")
        self.assertEqual(issue["EventRecordId"], "2")
        self.assertEqual(issue["AnalysisModel"], "synthetic-model")
        self.assertEqual(issue["Occurrences"], 2)
        self.assertEqual(issue["SupportingEventCount"], 2)
        self.assertEqual(issue["FirstSeenUtc"], "2026-01-01T12:00:01Z")
        self.assertEqual(issue["LastSeenUtc"], "2026-01-01T12:00:02Z")
        self.assertEqual(normalized["Metadata"]["AnalyzedEventCount"], 2)
        self.assertEqual(normalized["Metadata"]["CoverageStatus"], "complete")

    def test_both_producers_and_unknown_model_are_supported(self):
        for producer in ("codex", "claude"):
            result, evidence = fixture()
            result["Metadata"].update(Producer=producer, AnalysisModel="unknown")
            self.assertEqual(publisher.prepare_result(result, evidence, "0" * 64)["Findings"][0]["AnalysisModel"], "unknown")

    def test_invalid_contracts_are_rejected(self):
        mutations = [
            lambda r, e: r["Metadata"].update(Mode="extended"),
            lambda r, e: r["Metadata"].update(SchemaVersion=2),
            lambda r, e: r["Metadata"].update(SchemaVersion=True),
            lambda r, e: r["Metadata"].update(RunId="00000000-0000-4000-8000-000000000002"),
            lambda r, e: r["Metadata"].update(AnalyzedEventRefs=["Security:3"]),
            lambda r, e: r["Metadata"].update(AnalyzedEventRefs=["Security:1", "Security:1"]),
            lambda r, e: r["Findings"][0].update(EventRef="Security:3"),
            lambda r, e: r["Findings"][0].update(RelatedEventRefs=["Security:1"]),
            lambda r, e: r["Findings"][0].update(RelatedEventRefs=["Security:1", "Security:2", "Security:2"]),
            lambda r, e: r["Findings"][0].update(Severity="Critical"),
            lambda r, e: r["Findings"][0].update(Category="Unknown"),
            lambda r, e: r["Findings"][0].update(Confidence=""),
            lambda r, e: r["Findings"][0].update(TitleZh=""),
            lambda r, e: r["Findings"][0].update(Recommendation="line one\nline two"),
            lambda r, e: r["Findings"][0].update(EventDescription="invented evidence"),
            lambda r, e: r["Findings"][0].update(Key="Invalid Key"),
            lambda r, e: r["Findings"].append(deepcopy(r["Findings"][0])),
            lambda r, e: r.update(HealthScore=100),
            lambda r, e: r.update(Timestamp="2026-01-02 00:01:00"),
            lambda r, e: r.update(Timestamp="2026-01-01T00:01:00Z"),
            lambda r, e: e["Events"][0].update(EventTimestamp=e["ScanEnd"]),
            lambda r, e: e["Events"].append(deepcopy(e["Events"][0])),
            lambda r, e: e["Channels"][0].update(EventCount=True),
            lambda r, e: e["Channels"][0].update(EventCount=3),
            lambda r, e: e["Channels"].pop(),
            lambda r, e: e["Channels"][1].update(Status="unavailable"),
            lambda r, e: e.update(ScanStart="2025-12-01T00:00:00Z"),
            lambda r, e: e["Events"][0].update(Source="DifferentProvider"),
            lambda r, e: e["Events"][0].update(EventId="65536"),
            lambda r, e: e["Events"][0].update(EventRecordId="0", EventRef="Security:0"),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(case=index):
                result, evidence = fixture()
                mutation(result, evidence)
                with self.assertRaises(publisher.ValidationError):
                    publisher.prepare_result(result, evidence, "0" * 64)

    def test_filtering_requires_an_explicit_reason_and_no_unanalyzed_findings(self):
        result, evidence = fixture()
        result["Metadata"]["AnalyzedEventRefs"] = ["Security:2"]
        with self.assertRaises(publisher.ValidationError):
            publisher.prepare_result(result, evidence, "0" * 64)
        result["Metadata"]["FilterSummary"] = "Synthetic filtering"
        with self.assertRaises(publisher.ValidationError):
            publisher.prepare_result(result, evidence, "0" * 64)
        result["Findings"][0]["RelatedEventRefs"] = ["Security:2"]
        normalized = publisher.prepare_result(result, evidence, "0" * 64)
        self.assertEqual(normalized["Metadata"]["FilteredEventCount"], 1)
        self.assertEqual(normalized["Findings"][0]["Occurrences"], 1)

    def test_zero_analysis_remains_explicitly_unassessed(self):
        result, evidence = fixture()
        result["Findings"] = []
        result["Metadata"].update(AnalyzedEventRefs=[], FilterSummary="No events were assessed")
        normalized = publisher.prepare_result(result, evidence, "0" * 64)
        self.assertEqual(normalized["Metadata"]["AnalyzedEventCount"], 0)
        self.assertEqual(normalized["Metadata"]["FilteredEventCount"], 2)

    def test_partial_coverage_is_derived_from_unavailable_or_truncated_channels(self):
        for status, reason in (("unavailable", "access_denied"), ("truncated", "limit")):
            with self.subTest(status=status):
                result, evidence = fixture()
                evidence["Channels"][1 if status == "unavailable" else 0].update(Status=status, Reason=reason)
                normalized = publisher.prepare_result(result, evidence, "0" * 64)
                self.assertEqual(normalized["Metadata"]["CoverageStatus"], "partial")
                self.assertIn(reason, normalized["Metadata"]["CoverageNotes"])
                self.assertEqual(len(normalized["Findings"]), 1)

    def test_score_rounding_caps_and_no_occurrence_multiplier(self):
        result, evidence = fixture()
        result["Findings"][0]["Severity"] = "Low"
        self.assertEqual(publisher.prepare_result(result, evidence, "0" * 64)["HealthScore"], 98)
        source = result["Findings"][0]
        result["Findings"] = [{**source, "Key": f"pattern_{index}", "Severity": severity}
                              for index, severity in enumerate(["High"] * 8 + ["Medium"] * 6 + ["Low"] * 20)]
        self.assertEqual(publisher.prepare_result(result, evidence, "0" * 64)["HealthScore"], 0)

    def test_publish_is_idempotent_preserves_legacy_and_rejects_conflicts(self):
        with tempfile.TemporaryDirectory(prefix="lsa-assistant-test-") as directory:
            root = Path(directory)
            legacy = root / "audit_data.db"
            legacy.write_bytes(b"Synthetic legacy marker; never touch this file")
            original = legacy.read_bytes()
            path = publisher.database_path(root)
            result = prepared()
            first, second = publisher.publish(result, path), publisher.publish(result, path)
            self.assertTrue(first["Added"])
            self.assertFalse(second["Added"])
            self.assertEqual(first["RowId"], second["RowId"])
            changed = deepcopy(result)
            changed["Findings"][0]["Title"] = "Conflicting retry"
            with self.assertRaises(publisher.ValidationError):
                publisher.publish(changed, path)
            self.assertEqual(publisher.status(path)["RecordCount"], 1)
            self.assertEqual(legacy.read_bytes(), original)

    def test_concurrent_publishers_append_one_row_per_run(self):
        with tempfile.TemporaryDirectory(prefix="lsa-assistant-test-") as directory:
            path = publisher.database_path(directory)
            result = prepared()
            publisher.publish(result, path)
            result["Metadata"]["RunId"] = "00000000-0000-4000-8000-000000000002"
            with ThreadPoolExecutor(max_workers=4) as executor:
                results = list(executor.map(lambda _: publisher.publish(result, path), range(8)))
            self.assertEqual(sum(item["Added"] for item in results), 1)
            self.assertEqual(publisher.status(path)["RecordCount"], 2)

    def test_storage_timestamp_uses_sqlite_utc_ordering_and_pascal_case(self):
        with tempfile.TemporaryDirectory(prefix="lsa-assistant-test-") as directory:
            path = publisher.database_path(directory)
            publisher.publish(prepared(), path)
            with closing(sqlite3.connect(path)) as connection:
                row = connection.execute("SELECT Timestamp, FindingsJson, MetadataJson FROM AuditResults WHERE Timestamp >= ? AND Timestamp < ?",
                                         ("2026-01-02 00:00:00", "2026-01-03 00:00:00")).fetchone()
                self.assertTrue(row[0].startswith("2026-01-02 00:01:00."))
                self.assertEqual(json.loads(row[1])[0]["TitleZh"], "合成问题")
                self.assertEqual(json.loads(row[2])["Mode"], "assistant")
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)

    def test_transaction_failure_leaves_previous_results_intact(self):
        with tempfile.TemporaryDirectory(prefix="lsa-assistant-test-") as directory:
            path = publisher.database_path(directory)
            result = prepared()
            publisher.publish(result, path)
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("CREATE TRIGGER reject_insert BEFORE INSERT ON AuditResults BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END")
                connection.commit()
            result["Metadata"]["RunId"] = "00000000-0000-4000-8000-000000000002"
            with self.assertRaises(sqlite3.Error):
                publisher.publish(result, path)
            self.assertEqual(publisher.status(path)["RecordCount"], 1)

    def test_foreign_database_is_refused_without_changing_its_journal_or_contents(self):
        with tempfile.TemporaryDirectory(prefix="lsa-assistant-test-") as directory:
            path = publisher.database_path(directory)
            path.parent.mkdir()
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("CREATE TABLE AuditResults (Id INTEGER PRIMARY KEY, Timestamp DATETIME, HealthScore INTEGER, FindingsJson TEXT, MetadataJson TEXT)")
                connection.execute("INSERT INTO AuditResults VALUES (1, '2026-01-01 00:00:00', 80, '[]', '{\"Mode\":\"extended\"}')")
                connection.commit()
            before = path.read_bytes()
            with self.assertRaises(publisher.ValidationError):
                publisher.publish(prepared(), path)
            self.assertEqual(path.read_bytes(), before)

    def test_status_does_not_create_a_database_and_partial_does_not_advance_cursor(self):
        with tempfile.TemporaryDirectory(prefix="lsa-assistant-test-") as directory:
            path = publisher.database_path(directory)
            self.assertEqual(publisher.status(path)["RecordCount"], 0)
            self.assertFalse(path.parent.exists())
            result = prepared()
            publisher.publish(result, path)
            partial = deepcopy(result)
            partial["Timestamp"] = "2026-01-03T00:00:00Z"
            partial["Metadata"].update(RunId="00000000-0000-4000-8000-000000000002", CoverageStatus="partial", ScanEnd="2026-01-03T00:00:00Z")
            publisher.publish(partial, path)
            self.assertEqual(publisher.status(path)["LastCompleteScanEnd"], "2026-01-02T00:00:00Z")
            backfill = deepcopy(result)
            backfill["Timestamp"] = "2026-01-04T00:00:00Z"
            backfill["Metadata"].update(RunId="00000000-0000-4000-8000-000000000003", ScanEnd="2026-01-01T00:00:00Z")
            publisher.publish(backfill, path)
            self.assertEqual(publisher.status(path)["LastCompleteScanEnd"], "2026-01-02T00:00:00Z")

    def test_common_credential_forms_are_rejected_but_redacted_text_is_accepted(self):
        for secret in ('password=synthetic-value', '"api_key":"synthetic-value"', 'bearer ' + 'A' * 24):
            result, evidence = fixture()
            evidence["Events"][0]["EventDescription"] = secret
            with self.assertRaises(publisher.ValidationError):
                publisher.prepare_result(result, evidence, "0" * 64)
        result, evidence = fixture()
        evidence["Events"][0]["EventDescription"] = 'password=[REDACTED]; "api_key":"[REDACTED]"'
        publisher.prepare_result(result, evidence, "0" * 64)

    def test_strict_json_rejects_duplicate_keys_nonfinite_numbers_and_oversize_files(self):
        with tempfile.TemporaryDirectory(prefix="lsa-assistant-test-") as directory:
            path = Path(directory) / "input.json"
            for payload in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', '{"a":'):
                with self.subTest(payload=payload):
                    path.write_text(payload, encoding="utf-8")
                    with self.assertRaises(publisher.ValidationError):
                        publisher.load_json(path, 100)
            path.write_text('{"a": 1}', encoding="utf-8-sig")
            self.assertEqual(publisher.load_json(path, 100)[0], {"a": 1})
            with self.assertRaises(publisher.ValidationError):
                publisher.load_json(path, 2)

    def test_validation_cli_never_creates_a_database_or_echoes_secret_text(self):
        with tempfile.TemporaryDirectory(prefix="lsa-assistant-test-") as directory:
            root = Path(directory)
            result, evidence = fixture()
            result_path, evidence_path = root / "result.json", root / "evidence.json"
            result_path.write_text(json.dumps(result), encoding="utf-8")
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(publisher.main(["validate", str(result_path), "--evidence", str(evidence_path), "--data-root", str(root)]), 0)
            self.assertFalse((root / "assistant").exists())
            secret = "sk-" + "syntheticsecret" * 3
            evidence["Events"][0]["EventDescription"] = secret
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            errors = io.StringIO()
            with redirect_stderr(errors), redirect_stdout(io.StringIO()):
                self.assertEqual(publisher.main(["publish", str(result_path), "--evidence", str(evidence_path), "--data-root", str(root)]), 1)
            self.assertNotIn(secret, errors.getvalue())
            self.assertFalse((root / "assistant").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
