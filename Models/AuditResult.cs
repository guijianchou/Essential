using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LocalSecurityAudit.Models;

public class AuditResult
{
    public DateTime Timestamp { get; set; }
    public int HealthScore { get; set; }
    public List<AuditIssue> Findings { get; set; } = new();
    public Dictionary<string, JsonElement>? Metadata { get; set; }

    [JsonIgnore]
    public bool HasLimitedCoverage => Metadata?.TryGetValue("CoverageStatus", out var status) == true
        && status.ValueKind == JsonValueKind.String && status.GetString() == "limited";

    [JsonIgnore]
    public bool HasIncompleteCoverage => Metadata?.TryGetValue("CoverageStatus", out var status) == true
        && (status.ValueKind != JsonValueKind.String || status.GetString() != "complete");

    [JsonIgnore]
    public bool HasAssessment => !HasIncompleteCoverage && HasAnalyzedEvidence;

    // A daily-scope score is not an overall assessment. Fail closed unless the only
    // omitted channel is the explicitly skipped Security log.
    [JsonIgnore]
    public bool HasScopedAssessment
    {
        get
        {
            if (!HasLimitedCoverage
                || Metadata?.TryGetValue("AnalyzedEventCount", out var analyzed) != true
                || analyzed.ValueKind != JsonValueKind.Number || !analyzed.TryGetInt32(out int analyzedCount) || analyzedCount <= 0
                || Metadata?.TryGetValue("Channels", out var channels) != true
                || channels.ValueKind != JsonValueKind.Array) return false;
            var remaining = new HashSet<string>(StringComparer.Ordinal)
                { "Security", "System", "Application", "Setup", "ForwardedEvents" };
            foreach (var channel in channels.EnumerateArray())
            {
                if (channel.ValueKind != JsonValueKind.Object
                    || !channel.TryGetProperty("LogName", out var log) || log.ValueKind != JsonValueKind.String
                    || !remaining.Remove(log.GetString()!)
                    || !channel.TryGetProperty("Status", out var status) || status.ValueKind != JsonValueKind.String
                    || !channel.TryGetProperty("Reason", out var reason) || reason.ValueKind != JsonValueKind.String
                    || !channel.TryGetProperty("EventCount", out var count) || count.ValueKind != JsonValueKind.Number
                    || !count.TryGetInt32(out int value)
                    || value < 0) return false;
                bool security = log.GetString() == "Security";
                if (status.GetString() != (security ? "skipped" : "complete")
                    || reason.GetString() != (security ? "not_requested" : "none")
                    || (security && value != 0)) return false;
            }
            return remaining.Count == 0;
        }
    }

    private bool HasAnalyzedEvidence => Findings.Count > 0
        || (Metadata != null
            && Metadata.TryGetValue(Metadata.ContainsKey("AnalyzedEventCount") ? "AnalyzedEventCount" : "EventCount", out var count)
            && count.ValueKind == JsonValueKind.Number && count.TryGetInt32(out int value) && value > 0);
}
