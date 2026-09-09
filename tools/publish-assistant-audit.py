"""Validate external audits and append them to the assistant database. Standard library only.

Never collects logs, starts an agent, calls an AI endpoint, or writes the extended database.
See the bundled AGENTS.md for the input contract (v2; v1 remains readable).
"""

import argparse
from collections import Counter
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import sys
from uuid import UUID


LEGACY_LOGS = {"Security", "System", "Application", "Setup"}
LOGS = LEGACY_LOGS | {"ForwardedEvents"}
SEVERITIES = {"High", "Medium", "Low"}
CATEGORIES = {"Login", "Privilege", "Firewall", "Network", "System", "Application",
              "Encryption", "Policy", "Audit", "Other"}
TEXT_LIMITS = {"Title": 80, "Description": 320, "RootCause": 320, "Recommendation": 320,
               "TitleZh": 80, "DescriptionZh": 320, "RootCauseZh": 320, "RecommendationZh": 320}
EVIDENCE_LIMITS = {"EventRef": 128, "EventId": 10, "EventTimestamp": 40, "Source": 512,
                   "LogName": 32, "EventRecordId": 32, "EventDescription": 4096,
                   "EventAdditionalData": 8192, "UserName": 256, "IpAddress": 128}
ASSISTANT_APPLICATION_ID = 0x4C534141
MODELS = ("gpt-5.6-luna", "gpt-5.6-terra", "gpt-5.6-sol", "gpt-6-astra")
SECRET_PATTERN = re.compile(
    r"-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----|\bsk-[A-Za-z0-9_-]{20,}"
    r"|\b(?:Bearer|Basic)\s+[A-Za-z0-9_+/=-]{16,}"
    r"|\b(?:api[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|password|passwd|pwd|secret|cookie)[\"']?\s*[:=]\s*[\"']?(?!\[REDACTED\])[^\"'\s,;<>]+",
    re.IGNORECASE)


class ValidationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "JSON contains duplicate property names.")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValidationError("JSON contains a non-finite number.")


def load_json(path, max_bytes):
    with Path(path).open("rb") as source:
        raw = source.read(max_bytes + 1)
    require(len(raw) <= max_bytes, "Input exceeds the documented size limit.")
    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object,
                           parse_constant=reject_constant)
    except (json.JSONDecodeError, UnicodeError):
        raise ValidationError("Input must be one UTF-8 JSON document.") from None
    return value, hashlib.sha256(raw).hexdigest()


def fields(value, required, optional=(), label="Object"):
    require(type(value) is dict, f"{label} must be an object.")
    require(set(required) <= value.keys(), f"{label} is missing required fields.")
    require(value.keys() <= set(required) | set(optional), f"{label} contains unsupported fields.")


def text(value, limit, label, empty=False, multiline=False):
    require(isinstance(value, str) and len(value) <= limit, f"{label} has an invalid string length.")
    require(empty or bool(value.strip()), f"{label} must not be empty.")
    require(multiline or ("\n" not in value and "\r" not in value), f"{label} must be single-line.")
    require("\x00" not in value and not SECRET_PATTERN.search(value), f"{label} requires secret redaction.")
    return value


def integer(value, minimum, maximum, label):
    require(type(value) is int and minimum <= value <= maximum, f"{label} is outside its integer range.")
    return value


def utc(value, label):
    require(isinstance(value, str) and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z", value) is not None,
        f"{label} must be an ISO-8601 UTC timestamp ending in Z.")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValidationError(f"{label} is not a valid timestamp.") from None


def refs(value, available, label, allow_empty=False):
    require(type(value) is list and (allow_empty or bool(value)), f"{label} must be an array of references.")
    require(all(isinstance(item, str) for item in value), f"{label} contains an invalid reference.")
    require(len(value) == len(set(value)) and set(value) <= available, f"{label} contains duplicate or unknown references.")
    return set(value)


def prepare_result(result, evidence, evidence_hash):
    fields(evidence, {"SchemaVersion", "RunId", "ScanStart", "ScanEnd", "CollectedAt",
                      "DurationMs", "Channels", "Events"}, label="Evidence")
    require(type(evidence["SchemaVersion"]) is int and evidence["SchemaVersion"] in (1, 2), "Unsupported evidence schema.")
    schema = evidence["SchemaVersion"]
    expected_logs = LOGS if schema == 2 else LEGACY_LOGS
    try:
        require(str(UUID(evidence["RunId"])) == evidence["RunId"], "RunId must be a canonical UUID.")
    except (ValueError, TypeError, AttributeError):
        raise ValidationError("RunId must be a canonical UUID.") from None
    start, end = utc(evidence["ScanStart"], "ScanStart"), utc(evidence["ScanEnd"], "ScanEnd")
    collected = utc(evidence["CollectedAt"], "CollectedAt")
    require(timedelta(0) < end - start <= timedelta(hours=24), "Collection windows must be positive and at most 24 hours.")
    require(end <= collected <= datetime.now(timezone.utc) + timedelta(minutes=5), "Collection times are inconsistent or in the future.")
    collection_ms = integer(evidence["DurationMs"], 0, 86_400_000, "DurationMs")
    require(type(evidence["Channels"]) is list and len(evidence["Channels"]) == len(expected_logs), "Evidence must describe every channel for its schema.")
    channels = {}
    for channel in evidence["Channels"]:
        fields(channel, {"LogName", "Status", "EventCount", "Reason"}, label="Channel")
        name = text(channel["LogName"], 32, "Channel.LogName")
        require(name in expected_logs and name not in channels, "Channel names must be known and unique.")
        require(channel["Status"] in ("complete", "unavailable", "truncated", "skipped"), "Unknown channel status.")
        require(channel["Reason"] in ("none", "access_denied", "not_found", "query_failed", "limit", "not_requested"), "Unknown channel reason.")
        integer(channel["EventCount"], 0, 5000, "Channel.EventCount")
        require((channel["Status"] == "complete" and channel["Reason"] == "none")
                or (channel["Status"] == "truncated" and channel["Reason"] == "limit" and channel["EventCount"] > 0)
                or (schema == 2 and name == "Security" and channel["Status"] == "skipped"
                    and channel["Reason"] == "not_requested" and channel["EventCount"] == 0)
                or (channel["Status"] == "unavailable" and channel["Reason"] in ("access_denied", "not_found", "query_failed")
                    and channel["EventCount"] == 0), "Channel status, reason and count disagree.")
        channels[name] = channel

    require(type(evidence["Events"]) is list and len(evidence["Events"]) <= len(expected_logs) * 5000, "Events must be a bounded array.")
    events = {}
    counts = Counter()
    for event in evidence["Events"]:
        fields(event, EVIDENCE_LIMITS, label="Event")
        for field, limit in EVIDENCE_LIMITS.items():
            text(event[field], limit, f"Event.{field}", empty=field in ("EventDescription", "EventAdditionalData", "UserName", "IpAddress"),
                 multiline=field in ("EventDescription", "EventAdditionalData"))
        require(event["LogName"] in LOGS and re.fullmatch(r"[0-9]+", event["EventRecordId"]) is not None
                and re.fullmatch(r"[0-9]+", event["EventId"]) is not None, "Invalid event identity.")
        require(0 < int(event["EventRecordId"]) <= 2**63 - 1 and 0 <= int(event["EventId"]) <= 65535, "Event IDs are outside the Windows event ranges.")
        require(event["EventRef"] == f"{event['LogName']}:{event['EventRecordId']}" and event["EventRef"] not in events,
                "Event references must be unique channel:record-id identities.")
        require(start <= utc(event["EventTimestamp"], "EventTimestamp") < end, "An event is outside the collection window.")
        events[event["EventRef"]] = event
        counts[event["LogName"]] += 1
    require(all(counts[name] == channel["EventCount"] for name, channel in channels.items()), "Channel counts do not match evidence.")

    fields(result, {"Timestamp", "Findings", "Metadata"}, {"HealthScore"}, "Result")
    finished = utc(result["Timestamp"], "Timestamp")
    require(collected <= finished <= datetime.now(timezone.utc) + timedelta(minutes=5), "Result completion time is inconsistent or in the future.")
    metadata = result["Metadata"]
    fields(metadata, {"SchemaVersion", "Mode", "RunId", "Producer", "AnalysisModel", "ScanType", "AnalyzedEventRefs", "FilterSummary"},
           {"BaselineStart", "BaselineEnd"}, label="Metadata")
    require(type(metadata["SchemaVersion"]) is int and metadata["SchemaVersion"] == schema and metadata["Mode"] == "assistant", "Assistant metadata must match the evidence schema version.")
    require(metadata["RunId"] == evidence["RunId"], "The result and evidence RunId do not match.")
    require(metadata["Producer"] in ("claude", "codex"), "Producer must be claude or codex.")
    text(metadata["AnalysisModel"], 128, "AnalysisModel")
    require(metadata["ScanType"] in ("Fast Scan", "Full Scan"), "Unknown ScanType.")
    if "BaselineStart" in metadata or "BaselineEnd" in metadata:
        require("BaselineStart" in metadata and "BaselineEnd" in metadata, "Both baseline boundaries are required.")
        baseline_start, baseline_end = utc(metadata["BaselineStart"], "BaselineStart"), utc(metadata["BaselineEnd"], "BaselineEnd")
        require(baseline_start <= start < end <= baseline_end and timedelta(0) < baseline_end - baseline_start <= timedelta(days=7),
                "The batch must be inside a baseline of at most seven days.")
    analyzed = refs(metadata["AnalyzedEventRefs"], events.keys(), "AnalyzedEventRefs", allow_empty=True)
    text(metadata["FilterSummary"], 640, "FilterSummary", empty=len(analyzed) == len(events))
    require(type(result["Findings"]) is list and len(result["Findings"]) <= 500, "Findings must be an array of at most 500 items.")
    findings, patterns = [], set()
    for finding in result["Findings"]:
        fields(finding, set(TEXT_LIMITS) | {"Key", "EventRef", "RelatedEventRefs", "Severity", "Confidence", "Category", "Affected"}, label="Finding")
        for field, limit in TEXT_LIMITS.items():
            text(finding[field], limit, field)
        text(finding["Affected"], 256, "Affected", empty=True)
        require(isinstance(finding["Key"], str) and re.fullmatch(r"[a-z][a-z0-9_]{0,47}", finding["Key"]) is not None, "Key must be a snake_case pattern identifier of at most 48 characters.")
        require(isinstance(finding["Severity"], str) and finding["Severity"] in SEVERITIES
                and isinstance(finding["Confidence"], str) and finding["Confidence"] in SEVERITIES, "Unknown severity or confidence.")
        require(isinstance(finding["Category"], str) and finding["Category"] in CATEGORIES, "Unknown category.")
        related = refs(finding["RelatedEventRefs"], analyzed, "RelatedEventRefs")
        require(isinstance(finding["EventRef"], str) and finding["EventRef"] in related, "Primary evidence is missing from related references.")
        primary = events[finding["EventRef"]]
        require(all((events[ref]["LogName"], events[ref]["Source"]) == (primary["LogName"], primary["Source"]) for ref in related),
                "Keep findings from different channels or providers separate.")
        pattern = (finding["Key"], primary["LogName"], primary["Source"], finding["Affected"])
        require(pattern not in patterns, "Merge duplicate finding patterns before publishing.")
        patterns.add(pattern)
        times = sorted((events[ref]["EventTimestamp"] for ref in related), key=lambda value: utc(value, "EventTimestamp"))
        findings.append({**finding, **primary, "RelatedEventRefs": sorted(related),
                         "FirstSeenUtc": times[0], "LastSeenUtc": times[-1], "SupportingEventCount": len(related),
                         "EventTimes": {ref: events[ref]["EventTimestamp"] for ref in sorted(related)},
                         "Occurrences": len(related), "DetectedAt": result["Timestamp"],
                         "AnalysisModel": metadata["AnalysisModel"], "OriginalAnalysisModel": "", "OptimizedAtUtc": None})

    findings.sort(key=lambda item: ({"High": 0, "Medium": 1, "Low": 2}[item["Severity"]], -utc(item["EventTimestamp"], "EventTimestamp").timestamp()))
    severity_counts = Counter(item["Severity"] for item in findings)
    score = max(0, 100 - min(60, 15 * severity_counts["High"]) - min(25, 6 * severity_counts["Medium"])
                - min(15, math.floor(1.5 * severity_counts["Low"] + 0.5)))
    if "HealthScore" in result:
        require(type(result["HealthScore"]) is int and result["HealthScore"] == score, "HealthScore does not match the application's scoring rule.")
    incomplete = [channel for channel in evidence["Channels"] if channel["Status"] != "complete"]
    coverage = "partial" if any(channel["Status"] != "skipped" for channel in incomplete) else "limited" if incomplete else "complete"
    normalized_metadata = {**metadata, "AnalyzedEventRefs": sorted(analyzed), "EvidenceSha256": evidence_hash,
                           "AnalysisModels": [metadata["AnalysisModel"]] if analyzed else [], "AnalysisCompleted": True, "MergeVersion": 1,
                           "ScanStart": evidence["ScanStart"], "ScanEnd": evidence["ScanEnd"],
                           "EventCount": len(events), "AnalyzedEventCount": len(analyzed), "FilteredEventCount": len(events) - len(analyzed),
                           "DurationMs": collection_ms + int((finished - collected).total_seconds() * 1000),
                           "TimeRange": f"{start:%Y-%m-%d %H:%M} - {end:%Y-%m-%d %H:%M}",
                           "Channels": evidence["Channels"], "CoverageStatus": coverage,
                           "CoverageNotes": "; ".join(f"{item['LogName']}: {item['Status']} ({item['Reason']})" for item in incomplete)}
    return {"Timestamp": result["Timestamp"], "HealthScore": score, "Findings": findings, "Metadata": normalized_metadata}


def database_path(data_root=None):
    if data_root is None:
        require(bool(os.environ.get("LOCALAPPDATA")), "LOCALAPPDATA is unavailable; pass the viewer's data directory with --data-root.")
        data_root = Path(os.environ["LOCALAPPDATA"]) / "LocalSecurityAudit"
    root = Path(data_root).resolve()
    path = root / "assistant" / "audit_data.db"
    require(path.resolve() == path, "The assistant database path must not redirect through a link or junction.")
    return path


def publish(result, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path, timeout=5, isolation_level=None)) as connection:
        app_id = connection.execute("PRAGMA application_id").fetchone()[0]
        require(app_id in (0, ASSISTANT_APPLICATION_ID), "This database belongs to a different application.")
        require(connection.execute("PRAGMA user_version").fetchone()[0] in (0, 1), "Unsupported database version.")
        exists = connection.execute("SELECT 1 FROM sqlite_master WHERE name='AuditResults'").fetchone()
        if exists:
            columns = [row[1] for row in connection.execute("PRAGMA table_info(AuditResults)")]
            require(columns == ["Id", "Timestamp", "HealthScore", "FindingsJson", "MetadataJson"], "The database schema is not supported.")
            foreign_row = connection.execute("SELECT 1 FROM AuditResults WHERE CASE WHEN json_valid(MetadataJson) THEN coalesce(json_extract(MetadataJson, '$.Mode'), '') ELSE '' END != 'assistant' LIMIT 1").fetchone()
            require(foreign_row is None, "Refusing a database containing non-assistant or malformed records.")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute("CREATE TABLE IF NOT EXISTS AuditResults (Id INTEGER PRIMARY KEY AUTOINCREMENT, Timestamp DATETIME NOT NULL, HealthScore INTEGER NOT NULL, FindingsJson TEXT NOT NULL, MetadataJson TEXT)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON AuditResults(Timestamp DESC)")
            # BEGIN IMMEDIATE serializes all publishers, so retrying a RunId cannot append a second row.
            existing = connection.execute("SELECT Id, Timestamp, HealthScore, FindingsJson, MetadataJson FROM AuditResults WHERE json_extract(MetadataJson, '$.RunId') = ?", (result["Metadata"]["RunId"],)).fetchone()
            timestamp = utc(result["Timestamp"], "Timestamp").strftime("%Y-%m-%d %H:%M:%S.%f")
            if existing:
                previous_findings, previous_meta = json.loads(existing[3]), json.loads(existing[4])
                comparison_findings = [dict(finding) for finding in result["Findings"]]
                for old, new in zip(previous_findings, comparison_findings):
                    if "EventTimes" not in old:
                        new.pop("EventTimes", None)
                comparison_meta = dict(result["Metadata"])
                for name in ("AnalysisModels", "AnalysisCompleted", "MergeVersion"):
                    if name not in previous_meta:
                        comparison_meta.pop(name, None)
                require(existing[1] == timestamp and existing[2] == result["HealthScore"]
                        and previous_findings == comparison_findings and previous_meta == comparison_meta,
                        "RunId already exists with different content. Stored results were not overwritten.")
                row_id, added = existing[0], False
            else:
                cursor = connection.execute("INSERT INTO AuditResults (Timestamp, HealthScore, FindingsJson, MetadataJson) VALUES (?, ?, ?, ?)",
                                            (timestamp, result["HealthScore"], json.dumps(result["Findings"], ensure_ascii=False),
                                             json.dumps(result["Metadata"], ensure_ascii=False)))
                row_id, added = cursor.lastrowid, True
            connection.execute(f"PRAGMA application_id={ASSISTANT_APPLICATION_ID}")
            connection.execute("PRAGMA user_version=1")
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
    return {"Database": str(path), "RowId": row_id, "Added": added}


def model_rank(meta):
    models = meta.get("AnalysisModels", [meta.get("AnalysisModel")])
    return min((MODELS.index(model) if model in MODELS else -1 for model in models), default=-1)


def eligible(meta, full):
    if meta.get("CoverageStatus") not in ("complete", "limited"):
        return False
    expected = LOGS if full else LOGS - {"Security"}
    channels = meta.get("Channels", [])
    return all(sum(channel.get("LogName") == log and channel.get("Status") == "complete"
                   and channel.get("Reason") == "none" for channel in channels) == 1 for log in expected)


def checkpoint(records, full):
    usable = [meta for meta in records if eligible(meta, full)]
    cursor, rank = None, -1
    for meta in usable:
        end = utc(meta["ScanEnd"], "ScanEnd")
        baseline_start, baseline_end = meta.get("BaselineStart"), meta.get("BaselineEnd")
        if baseline_start:
            covered = utc(baseline_start, "BaselineStart")
            ranked = covered
            target = utc(baseline_end, "BaselineEnd")
            parts = sorted((part for part in usable if part.get("BaselineStart") == baseline_start
                            and part.get("BaselineEnd") == baseline_end), key=lambda part: utc(part["ScanStart"], "ScanStart"))
            for part in parts:
                start, stop = utc(part["ScanStart"], "ScanStart"), utc(part["ScanEnd"], "ScanEnd")
                if start <= covered < stop:
                    covered = stop
                if (model_rank(part) >= model_rank(meta) or part.get("EventCount") == 0) and start <= ranked < stop:
                    ranked = stop
            if covered > utc(baseline_start, "BaselineStart"):
                cursor = max(cursor, covered) if cursor else covered
            if ranked < target:
                continue
        else:
            cursor = max(cursor, end) if cursor else end
        rank = max(rank, model_rank(meta))
    return cursor, rank


def status(path, model=None, include_security=False, now=None):
    now = now or datetime.now(timezone.utc)
    summary = {"Database": str(path), "RecordCount": 0, "LatestPublishedAt": None, "LastCompleteScanEnd": None, "LastStandardScanEnd": None}
    records, retained = [], []
    for database in (path, path.parent.parent / "audit_data.db"):
        if not database.exists():
            continue
        require(database.resolve() == database, "A history database path must not redirect through a link or junction.")
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=5)) as connection:
            for timestamp, raw in connection.execute("SELECT Timestamp, MetadataJson FROM AuditResults ORDER BY Timestamp DESC, Id DESC"):
                try:
                    meta = json.loads(raw)
                    if not isinstance(meta, dict) or meta.get("Mode") not in ("assistant", "extended", "full"):
                        continue
                    start, end = utc(meta["ScanStart"], "ScanStart"), utc(meta["ScanEnd"], "ScanEnd")
                    if start >= end or end > now:
                        continue
                    records.append(meta)
                    summary["RecordCount"] += 1
                    if summary["LatestPublishedAt"] is None or timestamp > summary["LatestPublishedAt"]:
                        summary["LatestPublishedAt"] = timestamp
                except (TypeError, ValueError, KeyError):
                    continue
            if connection.execute("SELECT 1 FROM sqlite_master WHERE name='ScanCheckpoints'").fetchone():
                retained.extend(connection.execute("SELECT Scope, ModelRank, ScanEnd FROM ScanCheckpoints"))
    checkpoints = {}
    for full, key in ((False, "LastStandardScanEnd"), (True, "LastCompleteScanEnd")):
        cursor, rank = checkpoint(records, full)
        for scope, stored_rank, raw_end in retained:
            if scope != ("full" if full else "standard"):
                continue
            end = datetime.fromisoformat(raw_end).replace(tzinfo=timezone.utc)
            if end <= now:
                cursor = max(cursor, end) if cursor else end
                rank = max(rank, stored_rank)
        summary[key] = cursor.isoformat().replace("+00:00", "Z") if cursor else None
        checkpoints[full] = (cursor, rank)
    cursor, rank = checkpoints[include_security]
    summary["BestAnalysisModel"] = MODELS[rank] if 0 <= rank < len(MODELS) else None
    if model is not None:
        requested_rank = MODELS.index(model) if model in MODELS else -1
        upgrade = rank >= 0 and requested_rank > rank
        start = min(cursor, now - timedelta(days=7)) if cursor and upgrade else cursor or now - timedelta(days=7)
        summary.update(ScanReason="model_upgrade" if upgrade else "incremental" if cursor else "initial",
                       SuggestedScanStart=start.isoformat().replace("+00:00", "Z"), SuggestedScanEnd=now.isoformat().replace("+00:00", "Z"))
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "publish", "status"))
    parser.add_argument("result", nargs="?")
    parser.add_argument("--evidence")
    parser.add_argument("--data-root", help="Directory containing assistant/audit_data.db, as shown in the viewer. Never the database filename.")
    parser.add_argument("--model", help="Actual analysis model; status returns a shared incremental or seven-day upgrade window.")
    parser.add_argument("--include-security", action="store_true", help="Use full-scope progress for status. Does not collect or grant access.")
    args = parser.parse_args(argv)
    try:
        if args.command == "status":
            require(args.result is None and args.evidence is None, "status does not accept input files.")
            output = status(database_path(args.data_root), args.model, args.include_security)
        else:
            require(bool(args.result and args.evidence), "validate and publish require a result file and --evidence.")
            result, _ = load_json(args.result, 8 * 1024 * 1024)
            evidence, digest = load_json(args.evidence, 64 * 1024 * 1024)
            normalized = prepare_result(result, evidence, digest)
            output = {"Valid": True, "FindingCount": len(normalized["Findings"]), "CoverageStatus": normalized["Metadata"]["CoverageStatus"]}
            if args.command == "publish":
                output.update(publish(normalized, database_path(args.data_root)))
        print(json.dumps(output, ensure_ascii=False))
        return 0
    except ValidationError as error:
        print(f"Validation failed: {error}", file=sys.stderr)
    except (OSError, sqlite3.Error, ValueError, TypeError, KeyError):
        # Never echo source JSON, raw event text or database contents in errors/tracebacks.
        print("Input or database operation failed. Check the paths, schema and file permissions; no result was published.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
