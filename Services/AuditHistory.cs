using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

public static class AuditHistory
{
    private static readonly string[] StandardLogs = { "System", "Application", "Setup", "ForwardedEvents" };
    public static string Text(AuditResult result, string name) =>
        result.Metadata?.TryGetValue(name, out var value) == true && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty : string.Empty;

    public static int Count(AuditResult result, string name) =>
        result.Metadata?.TryGetValue(name, out var value) == true && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int count) ? count : -1;

    public static bool Window(AuditResult result, out DateTime start, out DateTime end)
    {
        start = end = default;
        return DateTime.TryParse(Text(result, "ScanStart"), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out start)
            && DateTime.TryParse(Text(result, "ScanEnd"), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out end)
            && start < end && end <= result.Timestamp && end <= DateTime.UtcNow;
    }

    public static bool ChannelComplete(AuditResult result, string log)
    {
        if (Text(result, "CoverageStatus") is not ("complete" or "limited")) return false;
        if (result.Metadata?.TryGetValue("Channels", out var channels) != true || channels.ValueKind != JsonValueKind.Array)
            return Text(result, "Mode") != AppMode.Assistant && Text(result, "CoverageStatus") == "complete"
                && (log != "Security" || Text(result, "Mode") == AppMode.Full);
        var matches = channels.EnumerateArray().Where(channel => channel.ValueKind == JsonValueKind.Object
            && channel.TryGetProperty("LogName", out var name) && name.ValueKind == JsonValueKind.String && name.GetString() == log).ToList();
        return matches.Count == 1 && matches[0].TryGetProperty("Status", out var state)
            && state.ValueKind == JsonValueKind.String && state.GetString() == "complete"
            && matches[0].TryGetProperty("Reason", out var reason) && reason.ValueKind == JsonValueKind.String && reason.GetString() == "none";
    }

    public static bool Eligible(AuditResult result, string mode) => Window(result, out _, out _)
        && StandardLogs.All(log => ChannelComplete(result, log))
        && (mode != AppMode.Full || ChannelComplete(result, "Security"));

    public static int ModelRank(AuditResult result)
    {
        if (result.Metadata?.TryGetValue("AnalysisModels", out var models) == true && models.ValueKind == JsonValueKind.Array)
        {
            var ranks = models.EnumerateArray().Select(model => model.ValueKind == JsonValueKind.String ? AiModelCatalog.Rank(model.GetString()) : -1).ToList();
            return ranks.Count == 0 ? -1 : ranks.Min();
        }
        string model = Text(result, "AnalysisModel");
        if (model.Length > 0) return AiModelCatalog.Rank(model);
        return result.Findings.Count == 0 ? -1 : result.Findings.Min(issue => AiModelCatalog.Rank(
            issue.OptimizedAtUtc != null ? issue.OriginalAnalysisModel : issue.AnalysisModel));
    }

    public static (DateTime Cursor, int BestModelRank) Checkpoint(IEnumerable<AuditResult> records, string mode)
    {
        DateTime cursor = default;
        int rank = -1;
        var eligible = records.Where(result => Eligible(result, mode)).ToList();
        foreach (var result in eligible)
        {
            Window(result, out _, out var end);
            string baselineStart = Text(result, "BaselineStart"), baselineEnd = Text(result, "BaselineEnd");
            if (baselineStart.Length > 0)
            {
                if (!DateTime.TryParse(baselineStart, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var covered)
                    || !DateTime.TryParse(baselineEnd, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var target)) continue;
                DateTime progress = covered;
                foreach (var part in eligible.Where(part => Text(part, "BaselineStart") == baselineStart
                    && Text(part, "BaselineEnd") == baselineEnd)
                    .OrderBy(part => Text(part, "ScanStart"), StringComparer.Ordinal))
                {
                    Window(part, out var start, out var stop);
                    if (start <= progress && stop > progress) progress = stop;
                    if ((ModelRank(part) >= ModelRank(result) || Count(part, "EventCount") == 0) && start <= covered && stop > covered) covered = stop;
                }
                if (progress > cursor && progress > DateTime.Parse(baselineStart, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind)) cursor = progress;
                if (covered < target) continue;
            }
            else if (end > cursor) cursor = end;
            rank = Math.Max(rank, ModelRank(result));
        }
        return (cursor, rank);
    }

    public static bool ValidateAssistant(AuditResult result)
    {
        try
        {
            if (Text(result, "Mode") != AppMode.Assistant || Count(result, "SchemaVersion") is not (1 or 2)
                || !Window(result, out var start, out var end) || end - start > TimeSpan.FromDays(1)
                || !Guid.TryParseExact(Text(result, "RunId"), "D", out _)
                || Text(result, "Producer") is not ("codex" or "claude")
                || string.IsNullOrWhiteSpace(Text(result, "AnalysisModel"))
                || !Regex.IsMatch(Text(result, "EvidenceSha256"), "^[a-fA-F0-9]{64}$") || result.Findings.Count > 500) return false;
            int total = Count(result, "EventCount"), analyzed = Count(result, "AnalyzedEventCount"), filtered = Count(result, "FilteredEventCount");
            if (total < 0 || analyzed < 0 || filtered < 0 || analyzed + filtered != total) return false;
            if (result.Metadata!.TryGetValue("AnalysisModels", out var models))
            {
                if (models.ValueKind != JsonValueKind.Array || models.GetArrayLength() != (analyzed > 0 ? 1 : 0)
                    || analyzed > 0 && (models[0].ValueKind != JsonValueKind.String || models[0].GetString() != Text(result, "AnalysisModel"))) return false;
            }
            if (result.Metadata.ContainsKey("BaselineStart") || result.Metadata.ContainsKey("BaselineEnd"))
            {
                if (!DateTime.TryParse(Text(result, "BaselineStart"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var baselineStart)
                    || !DateTime.TryParse(Text(result, "BaselineEnd"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var baselineEnd)
                    || baselineStart > start || baselineEnd < end || baselineEnd - baselineStart > TimeSpan.FromDays(7)) return false;
            }
            var logs = new HashSet<string>(StandardLogs.Append("Security"), StringComparer.Ordinal);
            if (Count(result, "SchemaVersion") == 1) logs.Remove("ForwardedEvents");
            if (result.Metadata?.TryGetValue("Channels", out var channels) != true || channels.ValueKind != JsonValueKind.Array) return false;
            int sum = 0;
            bool partial = false, limited = false;
            foreach (var channel in channels.EnumerateArray())
            {
                string? log = channel.GetProperty("LogName").GetString(), state = channel.GetProperty("Status").GetString(), reason = channel.GetProperty("Reason").GetString();
                int count = channel.GetProperty("EventCount").GetInt32();
                if (log == null || !logs.Remove(log) || count is < 0 or > 5000) return false;
                if (state == "complete" && reason == "none") { }
                else if (state == "truncated" && reason == "limit" && count > 0) partial = true;
                else if (state == "unavailable" && reason is "access_denied" or "not_found" or "query_failed" && count == 0) partial = true;
                else if (state == "skipped" && log == "Security" && reason == "not_requested" && count == 0 && Count(result, "SchemaVersion") == 2) limited = true;
                else return false;
                sum += count;
            }
            if (logs.Count != 0 || sum != total || Text(result, "CoverageStatus") != (partial ? "partial" : limited ? "limited" : "complete")) return false;
            var refs = result.Metadata!["AnalyzedEventRefs"].EnumerateArray().Select(value => value.GetString() ?? "").ToList();
            if (refs.Count != analyzed || refs.Distinct(StringComparer.Ordinal).Count() != analyzed) return false;
            if (filtered > 0 && string.IsNullOrWhiteSpace(Text(result, "FilterSummary"))) return false;
            foreach (var issue in result.Findings)
            {
                if (!issue.HasBilingualText || issue.Key == null || issue.Key.Length is < 1 or > 48 || issue.Affected == null || issue.Affected.Length > 256
                    || issue.AnalysisModel != Text(result, "AnalysisModel") || issue.Severity is not ("High" or "Medium" or "Low")
                    || issue.Confidence is not ("High" or "Medium" or "Low") || issue.EventRef != $"{issue.LogName}:{issue.EventRecordId}"
                    || issue.Category is not ("Login" or "Privilege" or "Firewall" or "Network" or "System" or "Application" or "Encryption" or "Policy" or "Audit" or "Other")
                    || !Regex.IsMatch(issue.Key, "^[a-z][a-z0-9_]{0,47}$")
                    || !long.TryParse(issue.EventRecordId, out var recordId) || recordId <= 0
                    || !int.TryParse(issue.EventId, out var eventId) || eventId is < 0 or > 65535
                    || !DateTime.TryParse(issue.EventTimestamp, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var eventTime)
                    || eventTime < start || eventTime >= end
                    || issue.RelatedEventRefs.Count == 0 || !issue.RelatedEventRefs.Contains(issue.EventRef)
                    || issue.RelatedEventRefs.Any(reference => !refs.Contains(reference, StringComparer.Ordinal))
                    || issue.RelatedEventRefs.Distinct(StringComparer.Ordinal).Count() != issue.RelatedEventRefs.Count
                    || issue.SupportingEventCount != issue.RelatedEventRefs.Count
                    || issue.FirstSeenUtc < start || issue.LastSeenUtc >= end || issue.FirstSeenUtc > issue.LastSeenUtc
                    || issue.EventTimes == null || issue.EventTimes.Any(pair => !issue.RelatedEventRefs.Contains(pair.Key) || pair.Value < start || pair.Value >= end)) return false;
                if (new[] { issue.Title, issue.TitleZh }.Any(text => text.Length > 80 || text.Contains('\n') || text.Contains('\r'))
                    || new[] { issue.Description, issue.DescriptionZh, issue.RootCause, issue.RootCauseZh, issue.Recommendation, issue.RecommendationZh }
                        .Any(text => text.Length > 320 || text.Contains('\n') || text.Contains('\r'))) return false;
                if (issue.EventTimes.Count > 0 && (issue.EventTimes.Count != issue.SupportingEventCount
                    || issue.EventTimes.Values.Min() != issue.FirstSeenUtc || issue.EventTimes.Values.Max() != issue.LastSeenUtc
                    || !issue.EventTimes.TryGetValue(issue.EventRef, out var primaryTime) || primaryTime != eventTime)) return false;
            }
            return result.HealthScore == HealthScoreCalculator.Calculate(result.Findings).Score;
        }
        catch (Exception ex) when (ex is InvalidOperationException or KeyNotFoundException or FormatException or OverflowException or ArgumentException)
        { return false; }
    }

    public static List<AuditIssue> EffectiveFindings(IReadOnlyList<AuditResult> records)
    {
        var candidates = new List<(AuditIssue Issue, DateTime Published)>();
        foreach (var record in records)
        foreach (var original in record.Findings)
        {
            var issue = JsonSerializer.Deserialize<AuditIssue>(JsonSerializer.Serialize(original))!;
            int rank = AiModelCatalog.Rank(issue.AnalysisModel);
            var replacements = records.Where(other => rank >= 0 && ModelRank(other) > rank && Count(other, "AnalyzedEventCount") > 0
                && ChannelComplete(other, issue.LogName) && Window(other, out _, out _)).ToList();
            bool Covered(DateTime time) => replacements.Any(other => Window(other, out var start, out var end) && time >= start && time < end);
            if (issue.EventTimes.Count == issue.SupportingEventCount && issue.EventTimes.Count > 0)
            {
                issue.EventTimes = issue.EventTimes.Where(pair => !Covered(pair.Value)).ToDictionary(pair => pair.Key, pair => pair.Value);
                if (issue.EventTimes.Count == 0) continue;
                issue.RelatedEventRefs = issue.EventTimes.Keys.ToList();
                issue.SupportingEventCount = issue.Occurrences = issue.EventTimes.Count;
                issue.FirstSeenUtc = issue.EventTimes.Values.Min();
                issue.LastSeenUtc = issue.EventTimes.Values.Max();
            }
            else if (issue.FirstSeenUtc != default && replacements.Any(other => Window(other, out var start, out var end)
                && issue.FirstSeenUtc >= start && issue.LastSeenUtc < end)) continue;
            candidates.Add((issue, record.Timestamp));
        }
        var findings = new List<AuditIssue>();
        foreach (var group in candidates.GroupBy(pair => (pair.Issue.LogName, pair.Issue.Source, pair.Issue.Category,
            Pattern: string.IsNullOrEmpty(pair.Issue.Key) ? pair.Issue.EventId + ":" + pair.Issue.Title : pair.Issue.Key, pair.Issue.Affected,
            UnknownModel: AiModelCatalog.Rank(pair.Issue.AnalysisModel) < 0 ? pair.Issue.AnalysisModel : null)))
        {
            var ordered = group.OrderByDescending(pair => AiModelCatalog.Rank(pair.Issue.AnalysisModel)).ThenByDescending(pair => pair.Published).ToList();
            var issue = ordered[0].Issue;
            bool completeTimeline = ordered.All(pair => pair.Issue.EventTimes.Count > 0 && pair.Issue.EventTimes.Count == pair.Issue.SupportingEventCount);
            var times = ordered.SelectMany(pair => pair.Issue.EventTimes).GroupBy(pair => (pair.Key, pair.Value))
                .Select(group => group.First()).ToList();
            issue.EventTimes = times.GroupBy(pair => pair.Key).ToDictionary(group => group.Key, group => group.Max(pair => pair.Value));
            issue.RelatedEventRefs = ordered.SelectMany(pair => pair.Issue.RelatedEventRefs).Distinct(StringComparer.Ordinal).ToList();
            issue.SupportingEventCount = completeTimeline ? times.Count : Math.Max(issue.EventTimes.Count, ordered.Max(pair => pair.Issue.SupportingEventCount));
            issue.Occurrences = completeTimeline ? times.Count : Math.Max(issue.SupportingEventCount, ordered.Max(pair => pair.Issue.Occurrences));
            issue.FirstSeenUtc = ordered.Where(pair => pair.Issue.FirstSeenUtc != default).Select(pair => pair.Issue.FirstSeenUtc).DefaultIfEmpty().Min();
            issue.LastSeenUtc = ordered.Max(pair => pair.Issue.LastSeenUtc);
            findings.Add(issue);
        }
        return findings.OrderBy(issue => issue.Severity == "High" ? 0 : issue.Severity == "Medium" ? 1 : 2).ThenByDescending(issue => issue.LastSeenUtc).ToList();
    }
}
